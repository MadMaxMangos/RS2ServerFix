#include "companion/steam_reporting_pipeline.h"
#include <cstring>

namespace rs2fix::reporting {
namespace {
bool Loss(NativePipeline& p,Reason why=Reason::RecordLoss) noexcept {
    if (p.status) LoseStatus(*p.status,why);
    return false;
}
bool QueueState(NativePipeline& p,std::uint64_t& write,std::uint64_t& read) noexcept {
    write=ReadStatusWord(p.readyWrite); read=ReadStatusWord(p.readyRead);
    if (read>write || write-read>kNativeReadyCapacity) return Loss(p);
    return true;
}
bool LedgerValid(NativePipeline& p) noexcept {
    return p.ledgerRead<=p.nextFormat && p.nextFormat<=p.ledgerWrite &&
        p.ledgerWrite-p.ledgerRead<=kNativeLedgerCapacity;
}
}
TransportReason InitializeNativePipeline(NativePipeline& p,StatusWireV3& status,
    ReportRingV3& ring,const NativeFormatContext& context,const NativeHashOps& hash,
    std::uint64_t qpc) noexcept {
    if (p.initialized || !qpc || !hash.digest || ring.status!=&status ||
        ReadStatusWord(ring.ready)!=1) return TransportReason::ProfileUnsafe;
    // No positive record is consumed or native call admitted before this exact
    // bootstrap (including worst escaped path expansion) is fully prepared.
    auto& slot=p.ready[0];
    const auto reason=PrepareNativeBootstrap(context,p.bootstrap,sizeof(p.bootstrap),
        slot.message,std::size(slot.message),&p.bootstrapBytes);
    if (reason!=TransportReason::None) return reason;
    p.status=&status; p.ring=&ring; p.hash=hash; p.format=context;
    p.ledgerRead=0; p.ledgerWrite=1; p.nextFormat=1;
    p.preparedSequence=0; p.observedSequence=0; p.startupObserved=0; p.heldMatch=0;
    auto& entry=p.ledger[0]; entry={};
    entry.sequence=0; entry.preparedQpc=qpc; entry.messageBytes=static_cast<std::uint32_t>(p.bootstrapBytes);
    entry.state=LedgerState::Ready;
    slot.ticket=1; slot.sequence=0; slot.ledgerIndex=0; slot.chars=entry.messageBytes;
    StoreStatusWord(p.readyRead,0);
    StoreStatusWord(p.initialized,1);
    StoreStatusWord(p.readyWrite,1);
    return TransportReason::None;
}
bool PrepareNativeFrames(NativePipeline& p,std::uint64_t qpc) noexcept {
    if (!ReadStatusWord(p.initialized) || !p.status || !p.ring || !qpc) return false;
    if (!LedgerValid(p)) return Loss(p);
    // The worker may drain already accepted records after stop, but never
    // replay a frame whose call outcome is uncertain. Owner admission remains
    // closed separately; draining is not authority to submit after stop/fault.
    for (std::size_t count=0;count<kReportBatchLimit &&
        p.ledgerWrite-p.ledgerRead<kNativeLedgerCapacity;++count) {
        if (p.ledgerWrite==UINT64_MAX) return Loss(p,Reason::CounterOverflow);
        auto& entry=p.ledger[p.ledgerWrite%kNativeLedgerCapacity];
        if (entry.state!=LedgerState::Empty) return Loss(p);
        entry.state=LedgerState::Reserved;
        const auto read=DequeueReport(*p.ring,&entry.body.scalar);
        if (read==ReportReadResult::Empty) { entry={}; break; }
        if (read!=ReportReadResult::Record) { entry={}; return Loss(p); }
        entry.sequence=entry.body.scalar.header.sequence;
        entry.state=LedgerState::Scalar;
        ++p.ledgerWrite;
    }
    for (;p.nextFormat<p.ledgerWrite;) {
        std::uint64_t write{},read{};
        if (!QueueState(p,write,read)) return false;
        if (write-read==kNativeReadyCapacity) break;
        if (write==UINT64_MAX) return Loss(p,Reason::CounterOverflow);
        auto& entry=p.ledger[p.nextFormat%kNativeLedgerCapacity];
        if (entry.state!=LedgerState::Scalar || p.preparedSequence==UINT64_MAX ||
            entry.sequence!=p.preparedSequence+1) return Loss(p);
        std::size_t bytes{};
        if (!FormatNativeRecord(p.format,entry.body.scalar,p.scratch,sizeof(p.scratch),&bytes))
            return Loss(p);
        Sha256Digest digest{};
        if (!p.hash.digest(p.hash.context,p.scratch,bytes,&digest)) return Loss(p);
        auto& slot=p.ready[write%kNativeReadyCapacity];
        if (!native_log::PrepareMessage(p.scratch,bytes,slot.message,std::size(slot.message))) return Loss(p);
        slot.ticket=write+1; slot.sequence=entry.sequence;
        slot.ledgerIndex=static_cast<std::uint32_t>(p.nextFormat%kNativeLedgerCapacity);
        slot.chars=static_cast<std::uint32_t>(bytes);
        // Replace scalar data only once its immutable ready frame and digest
        // both exist; queue release cannot release this separate ledger home.
        entry.body={}; entry.body.digest=digest;
        entry.messageBytes=slot.chars; entry.preparedQpc=qpc; entry.state=LedgerState::Ready;
        p.preparedSequence=entry.sequence;
        ++p.nextFormat;
        StoreStatusWord(p.readyWrite,write+1);
    }
    return true;
}
const NativeReadyFrame* PeekNativeFrame(NativePipeline& p) noexcept {
    if (!ReadStatusWord(p.initialized) || !p.status) return nullptr;
    std::uint64_t write{},read{};
    if (!QueueState(p,write,read) || write==read) return nullptr;
    const auto& slot=p.ready[read%kNativeReadyCapacity];
    if (slot.ticket!=read+1 || slot.ledgerIndex>=kNativeLedgerCapacity ||
        !native_log::ValidMessage(slot.message,slot.chars)) { Loss(p); return nullptr; }
    return &slot;
}
bool ReleaseNativeFrame(NativePipeline& p,std::uint64_t ticket) noexcept {
    const auto* slot=PeekNativeFrame(p);
    if (!slot || slot->ticket!=ticket) return Loss(p);
    // No slot writes after publication of readyRead: the worker can immediately
    // reuse it. Ledger release is independent and belongs only to receipts.
    StoreStatusWord(p.readyRead,ticket);
    return true;
}
ReceiptDisposition MatchNativeReceipt(void* context,const char* bytes,std::size_t size) noexcept {
    if (!context) return ReceiptDisposition::Corrupt;
    auto& p=*static_cast<NativePipeline*>(context);
    if (!bytes || !ReadStatusWord(p.initialized) || p.heldMatch || !LedgerValid(p) ||
        p.ledgerRead==p.nextFormat) return ReceiptDisposition::Corrupt;
    Sha256Digest digest{};
    if (!p.hash.digest(p.hash.context,bytes,size,&digest)) {
        Loss(p); return ReceiptDisposition::Corrupt;
    }
    for (auto ticket=p.ledgerRead;ticket<p.nextFormat;++ticket) {
        auto& entry=p.ledger[ticket%kNativeLedgerCapacity];
        if (entry.state!=LedgerState::Ready || entry.messageBytes!=size) continue;
        const bool match=entry.sequence ?
            entry.body.digest==digest :
            size==p.bootstrapBytes && std::memcmp(bytes,p.bootstrap,size)==0;
        if (!match) continue;
        if (ticket!=p.ledgerRead) return ReceiptDisposition::Gap;
        entry.state=LedgerState::Matched;
        p.heldMatch=1;
        return ReceiptDisposition::AwaitingSubmission;
    }
    return ReceiptDisposition::Corrupt;
}
bool AcknowledgeNativeReceipt(NativePipeline& p,const OwnerSnapshotV3& owner) noexcept {
    if (!p.heldMatch || !LedgerValid(p) || owner.sequence<2 || (owner.sequence&1)) return false;
    auto& entry=p.ledger[p.ledgerRead%kNativeLedgerCapacity];
    if (entry.state!=LedgerState::Matched) return Loss(p);
    if (entry.sequence==0) {
        if (!owner.transport.startupSubmitted) return false;
        p.startupObserved=1;
    } else {
        if (entry.sequence>owner.transport.submittedSequence) return false;
        if (!p.startupObserved || p.observedSequence==UINT64_MAX ||
            entry.sequence!=p.observedSequence+1) return Loss(p);
        p.observedSequence=entry.sequence;
    }
    // Normally-returned publication must precede reuse. Do not reset offset,
    // bootstrap identity or other ledger slots when releasing this one match.
    entry={}; ++p.ledgerRead; p.heldMatch=0;
    return true;
}
} // namespace rs2fix::reporting
