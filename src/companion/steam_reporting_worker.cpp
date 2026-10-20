#include "companion/steam_reporting_worker.h"
#include <algorithm>
#include <cstring>

namespace rs2fix::reporting {
namespace {
bool Qpc(void*,std::uint64_t* out) noexcept {
    LARGE_INTEGER now{};
    if (!out || !QueryPerformanceCounter(&now) || now.QuadPart<=0) return false;
    *out=static_cast<std::uint64_t>(now.QuadPart); return true;
}
constexpr NativeWorkerClock kClock{nullptr,Qpc};
bool Clock(NativeReceiptWorker& w,std::uint64_t& out) noexcept {
    out=0;
    if (w.clockFailed || !w.clock.sample(w.clock.context,&out) || !out || out<w.lastClock) {
        w.clockFailed=true; RevokeStatus(*w.status,Reason::ClockFailed); return false;
    }
    w.lastClock=out; return true;
}
bool Add(NativeReceiptWorker& w,std::uint64_t& value,std::uint64_t amount=1) noexcept {
    if (amount>UINT64_MAX-value) { LoseStatus(*w.status,Reason::CounterOverflow); return false; }
    value+=amount; return true;
}
void Publish(NativeReceiptWorker& w) noexcept {
    if (ReadStatusWord(w.pipeline.initialized)) {
        w.counters.startupObserved=w.pipeline.startupObserved;
        w.counters.preparedSequence=w.pipeline.preparedSequence;
        w.counters.observedSequence=w.pipeline.observedSequence;
        w.counters.readerOffset=w.scanner.offset; w.counters.partialBytes=w.scanner.carry;
        w.counters.ledgerDepth=w.pipeline.ledgerWrite-w.pipeline.ledgerRead;
        w.counters.readyDepth=ReadStatusWord(w.pipeline.readyWrite)-ReadStatusWord(w.pipeline.readyRead);
        w.counters.ringReadSequence=ReadStatusWord(w.ring->reportReadSequence);
        w.counters.matchedAwaitingSubmitSequence=w.pipeline.heldMatch ?
            w.pipeline.ledger[w.pipeline.ledgerRead%kNativeLedgerCapacity].sequence : 0;
    }
    PublishWorkerV3(*w.status,w.counters); // Coherent owner race is retried next cycle.
}
void Pause(NativeReceiptWorker& w,TransportReason reason,std::uint64_t qpc) noexcept {
    if (reason>=TransportReason::ReceiptGap) {
        LatchTransportFault(*w.status,reason); Publish(w); return;
    }
    const auto value=static_cast<std::uint64_t>(reason);
    if (w.counters.pauseReason!=value) {
        if (value) StoreStatusWord(w.status->workerPauseReason,value); // Close first.
        if (!Add(w,w.counters.pauseConditionSequence)) return;
        w.counters.pauseConditionQpc=qpc;
        w.counters.pauseReason=value;
    }
    Publish(w); // Clear only after the coherent condition-free state is published.
}
bool Ack(NativeReceiptWorker& w,std::uint64_t qpc) noexcept {
    if (!w.pipeline.heldMatch) return true;
    OwnerSnapshotV3 owner{};
    if (!ReadOwnerV3(*w.status,&owner) || !AcknowledgeNativeReceipt(w.pipeline,owner)) return false;
    if (!ResumeReceiptScanner(w.scanner)) {
        LoseStatus(*w.status,Reason::RecordLoss); return false;
    }
    w.counters.lastReceiptQpc=qpc;
    return true;
}
TransportReason ReceiptAge(NativeReceiptWorker& w,std::uint64_t now) noexcept {
    if (w.pipeline.ledgerRead==w.pipeline.ledgerWrite) { w.receiptWaitActive=false; return TransportReason::None; }
    OwnerSnapshotV3 owner{};
    if (!ReadOwnerV3(*w.status,&owner)) return static_cast<TransportReason>(w.counters.pauseReason);
    const auto& front=w.pipeline.ledger[w.pipeline.ledgerRead%kNativeLedgerCapacity];
    const bool submitted=front.sequence ? front.sequence<=owner.transport.submittedSequence :
        owner.transport.startupSubmitted!=0;
    const auto frequency=w.status->header.qpcFrequency;
    if (!submitted) { w.receiptWaitActive=false; return TransportReason::None; }
    // Start only once a coherent normally-returned submission is visible. A
    // long stay in the ready queue is not overdue FILE receipt time. This is a
    // conservative worker-observed lower bound, never a proof of missing data.
    if (!w.receiptWaitActive || w.receiptWaitSequence!=front.sequence) {
        w.receiptWaitActive=true; w.receiptWaitSequence=front.sequence; w.receiptWaitStartedQpc=now;
    }
    // Division avoids frequency*30 overflow. Age alone is never evidence loss.
    if (now>=w.receiptWaitStartedQpc && (now-w.receiptWaitStartedQpc)/frequency>=30)
        return TransportReason::ReceiptOverdue;
    return TransportReason::None;
}
TransportReason FinishInitialLine(NativeReceiptWorker& w,std::uint64_t now) noexcept {
    if (!w.scanner.skipInitialSuffix) return TransportReason::None;
    const auto frequency=w.status->header.qpcFrequency;
    const auto interval=frequency/4+(frequency%4!=0);
    if (w.haveCycle && now-w.lastCycle<interval) return TransportReason::AwaitingLogger;
    w.haveCycle=true; w.lastCycle=now;
    if (!Add(w,w.counters.readCycles)) return TransportReason::AwaitingLogger;
    DWORD budget=kNativeReadCycleBytes;
    TransportReason reason=TransportReason::AwaitingLogger;
    while (budget && w.scanner.skipInitialSuffix) {
        DWORD got{};
        reason=ReadNativeLogFile(w.file,w.scanner.offset,w.readBuffer,
            (std::min)(budget,static_cast<DWORD>(sizeof(w.readBuffer))),&got);
        w.counters.lastReadError=w.file.lastError;
        if (reason!=TransportReason::None) break;
        if (!got) { reason=TransportReason::AwaitingLogger; break; }
        budget-=got;
        if (!Add(w,w.counters.readBytes,got)) return TransportReason::AwaitingLogger;
        for (DWORD i=0;i<got;++i) {
            if (w.scanner.offset==UINT64_MAX) { LoseStatus(*w.status,Reason::CounterOverflow); return TransportReason::AwaitingLogger; }
            ++w.scanner.offset;
            if (w.readBuffer[i]=='\n') { w.scanner.skipInitialSuffix=false; break; }
        }
        reason=w.scanner.skipInitialSuffix ? TransportReason::AwaitingLogger : TransportReason::None;
    }
    w.counters.readerOffset=w.scanner.offset;
    std::uint64_t end{};
    if (!Clock(w,end)) return TransportReason::AwaitingLogger;
    if (!Add(w,w.counters.receiptTicks,end-now)) return TransportReason::AwaitingLogger;
    // Do not spend a second normal-read budget immediately after qualification.
    // Keep this same processed cursor; never replay/skip the future bootstrap.
    w.lastCycle=end;
    return reason;
}
TransportReason RejectUnpublishedFile(NativeReceiptWorker& w,TransportReason reason,
    std::uint64_t now) noexcept {
    // No bootstrap, ready frame or immutable log identity exists yet. A changed
    // candidate is retryable; it cannot be evidence of losing admitted output.
    // Once qualified, the separate branch below retains the original identity
    // and treats truncation/replacement as the existing sticky transport fault.
    CloseNativeLogFile(w.file); w.file={}; w.scanner={};
    w.counters.readerOffset=0; w.counters.partialBytes=0;
    if (reason==TransportReason::FileTruncated || reason==TransportReason::FileIdentityChanged)
        reason=TransportReason::ReceiptUnavailable;
    Pause(w,reason,now);
    return reason;
}
}
const NativeWorkerClock& ProductionNativeWorkerClock() noexcept { return kClock; }
bool InitializeNativeReceiptWorker(NativeReceiptWorker& w,StatusWireV3& status,ReportRingV3& ring,
    const NativeFormatContext& format,const NativeHashOps& hash,const NativeWorkerClock& clock) noexcept {
    if (w.initialized || !hash.digest || !clock.sample || !status.header.qpcFrequency ||
        ReadStatusWord(status.headerReady)!=1 || ring.status!=&status || ReadStatusWord(ring.ready)!=1)
        return false;
    w.status=&status; w.ring=&ring; w.format=format; w.hash=hash; w.clock=clock;
    w.initialized=true;
    return true;
}
TransportReason QualifyNativeReceiptFile(NativeReceiptWorker& w,const std::uint16_t* path,
    std::size_t chars,std::uint64_t prefixMode,std::uint64_t epoch) noexcept {
    if (!w.initialized || !epoch || epoch<w.qualifiedEpoch) return TransportReason::ProfileUnsafe;
    std::uint64_t now{};
    if (!Clock(w,now)) return TransportReason::ReceiptUnavailable;
    if (prefixMode>1 || (w.qualifiedEpoch && prefixMode!=w.format.log.prefixMode)) {
        Pause(w,TransportReason::FramingUnsupported,now); return TransportReason::FramingUnsupported;
    }
    Pause(w,w.qualifiedEpoch ? TransportReason::SameFileRequalification : TransportReason::AwaitingLogger,now);
    if (w.qualifiedEpoch) {
        const auto reason=RequalifyNativeLogFile(w.file,path,chars);
        w.counters.lastReadError=w.file.lastError;
        if (reason!=TransportReason::None) { Pause(w,reason,now); return reason; }
        w.qualifiedEpoch=epoch;
        // Resume remains an owner decision after boundary/credits/source checks.
        Pause(w,ReceiptAge(w,now),now); return TransportReason::None;
    }
    const bool first=!w.file.handle;
    auto reason=first ? OpenNativeLogFile(w.file,path,chars) : RequalifyNativeLogFile(w.file,path,chars);
    w.counters.lastReadError=w.file.lastError;
    if (reason!=TransportReason::None) return RejectUnpublishedFile(w,reason,now);
    if (first && !InitializeReceiptScanner(w.scanner,w.file.initialEOF,w.file.initialAtLineBoundary,
        static_cast<native_log::PrefixMode>(prefixMode),w.format.header.runId)) {
        LatchTransportFault(*w.status,TransportReason::ProfileUnsafe); return TransportReason::ProfileUnsafe;
    }
    w.scanner.prefixMode=static_cast<native_log::PrefixMode>(prefixMode);
    reason=FinishInitialLine(w,now);
    if (StatusRevoked(*w.status)) return reason==TransportReason::None ? TransportReason::AwaitingLogger : reason;
    if (reason!=TransportReason::None) {
        if (reason!=TransportReason::AwaitingLogger) return RejectUnpublishedFile(w,reason,now);
        Pause(w,reason,now); return reason;
    }
    auto& log=w.format.log;
    log.volumeSerial=w.file.identity.volumeSerial;
    std::memcpy(log.fileId,w.file.identity.fileId,sizeof(log.fileId));
    log.initialEOF=w.file.initialEOF;
    log.pathChars=chars; log.prefixMode=prefixMode; log.transportKind=1; log.durability=0;
    log.initialAtLineBoundary=w.file.initialAtLineBoundary ? 1 : 0;
    std::memset(log.path,0,sizeof(log.path));
    std::memcpy(log.path,path,chars*sizeof(*path));
    reason=InitializeNativePipeline(w.pipeline,*w.status,*w.ring,w.format,w.hash,now);
    if (reason!=TransportReason::None) {
        // No identity/ready/bootstrap was published by the owner. Release this
        // rejected candidate; retry qualification can take a new initial EOF.
        return RejectUnpublishedFile(w,reason,now);
    }
    if (!PublishLogIdentityV3(*w.status,log)) {
        LatchTransportFault(*w.status,TransportReason::ProfileUnsafe); return TransportReason::ProfileUnsafe;
    }
    w.qualifiedEpoch=epoch;
    Pause(w,TransportReason::None,now);
    return TransportReason::None;
}
void CycleNativeReceipts(NativeReceiptWorker& w) noexcept {
    if (!w.initialized || !w.qualifiedEpoch || !w.file.handle || w.clockFailed) return;
    std::uint64_t begin{};
    if (!Clock(w,begin)) return;
    const auto frequency=w.status->header.qpcFrequency;
    const auto interval=frequency/4+(frequency%4!=0);
    if (w.haveCycle && begin-w.lastCycle<interval) return;
    w.haveCycle=true; w.lastCycle=begin;
    if (!Add(w,w.counters.readCycles)) return;

    const auto before=w.pipeline.preparedSequence;
    if (!StatusRevoked(*w.status) && !PrepareNativeFrames(w.pipeline,begin)) { Publish(w); return; }
    std::uint64_t afterFormat{};
    if (!Clock(w,afterFormat)) return;
    if (!Add(w,w.counters.formatCalls,w.pipeline.preparedSequence-before) ||
        !Add(w,w.counters.formatTicks,afterFormat-begin)) return;
    if (!Ack(w,afterFormat)) {
        Pause(w,ReceiptAge(w,afterFormat),afterFormat); return;
    }
    DWORD budget=kNativeReadCycleBytes;
    TransportReason reason=TransportReason::None;
    while (budget) {
        DWORD got{};
        const auto wanted=(std::min)(budget,static_cast<DWORD>(sizeof(w.readBuffer)));
        reason=ReadNativeLogFile(w.file,w.scanner.offset,w.readBuffer,wanted,&got);
        w.counters.lastReadError=w.file.lastError;
        if (reason!=TransportReason::None) break;
        if (!got) break; // One observed EOF ends the cycle.
        budget-=got;
        if (!Add(w,w.counters.readBytes,got)) return;
        std::size_t parsed{};
        while (parsed<got) {
            const auto scan=ScanReceiptChunk(w.scanner,{&w.pipeline,MatchNativeReceipt},
                w.readBuffer+parsed,got-parsed);
            parsed+=scan.consumed;
            if (scan.disposition==ReceiptDisposition::Gap) { reason=TransportReason::ReceiptGap; break; }
            if (scan.disposition==ReceiptDisposition::Corrupt) { reason=TransportReason::ReceiptCorrupt; break; }
            if (scan.disposition==ReceiptDisposition::AwaitingSubmission) {
                std::uint64_t receiptQpc{};
                if (!Clock(w,receiptQpc)) return;
                if (!Ack(w,receiptQpc)) break;
            } else if (!scan.consumed) { reason=TransportReason::ReceiptCorrupt; break; }
        }
        if (reason!=TransportReason::None || w.scanner.awaitingSubmission) break;
    }
    std::uint64_t end{};
    if (!Clock(w,end)) return;
    if (!Add(w,w.counters.receiptTicks,end-afterFormat)) return;
    if (reason==TransportReason::None) {
        if (!budget && w.scanner.offset<w.file.maximumSize) reason=TransportReason::ReaderBehind;
        else reason=ReceiptAge(w,end);
    }
    Pause(w,reason,end);
}
void CloseNativeReceipts(NativeReceiptWorker& w) noexcept {
    if (!w.initialized) return;
    CloseNativeLogFile(w.file);
    Publish(w); // Stop/fault remains in independent sticky DATA, never a footer.
}
}
