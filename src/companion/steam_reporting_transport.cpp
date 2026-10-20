#include "companion/steam_reporting_transport.h"
#include "companion/steam_reporting_worker.h"
#include "companion/steam_reporting_hash.h"
#include "companion/steam_reporting_console.h"
#include <cstring>
#include <new>

namespace rs2fix::reporting {
namespace {
struct SinkRequest {
    std::uint64_t epoch,prefixMode,pathChars,reserved;
    std::uint16_t path[kNativeLogPathChars];
};
static_assert(sizeof(SinkRequest)%8==0 && alignof(SinkRequest)>=8);
struct QuiescenceSnapshot {
    std::uint64_t quiescent,generatedSequence,observedSequence,qualifiedEpoch;
};
}
struct NativeTransport {
    StatusWireV3* status;
    DWORD ownerThreadId;
    HANDLE wake,thread,finished;
    std::uint64_t armed,stop,startupReady,requestSequence,qualifiedEpoch;
    RecoveryStatusWireV1* recovery; // Cold attachment, immutable after armed.
    std::uint64_t quiescenceAvailable,quiescenceSequence,quiescenceFailed;
    QuiescenceSnapshot quiescence;
    NativeStartupSummary startup;
    SinkRequest request;
    PreparedNativeHash hash;
    NativeReceiptWorker worker;
    ReportingConsole console;
    bool startupCopied;
};
// Design's fixed-storage budget includes the external scalar ring and maximum
// prepared hash object. Thread/handle/kernel costs are separately OS-owned.
// Reserve64KiB here for P4 console state and subsequent owner-side additions.
static_assert(sizeof(NativeTransport)+sizeof(ReportRingV3)+65536+65536<768*1024);
namespace {
bool Owner(const NativeTransport* t) noexcept {
    return t && t->ownerThreadId==GetCurrentThreadId();
}
bool ReadRequest(const NativeTransport& t,SinkRequest& output) noexcept {
    for (unsigned retry=0;retry<3;++retry) {
        const auto before=ReadStatusWord(t.requestSequence);
        if (!before || (before&1)) continue;
        SinkRequest copy{};
        for (std::size_t offset=0;offset<sizeof(copy);offset+=8) {
            const auto* word=reinterpret_cast<const std::uint64_t*>(
                reinterpret_cast<const unsigned char*>(&t.request)+offset);
            const auto value=ReadStatusWord(*word);
            std::memcpy(reinterpret_cast<unsigned char*>(&copy)+offset,&value,8);
        }
        if (ReadStatusWord(t.requestSequence)==before) { output=copy; return true; }
    }
    return false;
}
void PublishQuiescence(NativeTransport& t) noexcept {
    // Sole receipt worker owns every ordinary pipeline/scanner/ledger field.
    // Cross-writer queue words and owner publication use existing atomic reads.
    auto& w=t.worker; const auto& p=w.pipeline;
    QuiescenceSnapshot copy{};
    copy.qualifiedEpoch=ReadStatusWord(t.qualifiedEpoch);
    copy.observedSequence=p.observedSequence;
    OwnerSnapshotV3 owner{};
    const auto ringWrite=ReadStatusWord(w.ring->reportWriteSequence);
    const auto ringRead=ReadStatusWord(w.ring->reportReadSequence);
    const auto readyWrite=ReadStatusWord(p.readyWrite);
    const auto readyRead=ReadStatusWord(p.readyRead);
    bool emptyLedger=p.ledgerRead==p.ledgerWrite && p.nextFormat==p.ledgerWrite;
    if (emptyLedger) for (const auto& entry:p.ledger)
        if (entry.state!=LedgerState::Empty) { emptyLedger=false; break; }
    if (ReadOwnerV3(*t.status,&owner)) {
        copy.generatedSequence=owner.transport.generatedSequence;
        copy.quiescent=w.initialized && ReadStatusWord(p.initialized)==1 && p.startupObserved==1 &&
            w.counters.startupObserved==1 && !w.clockFailed && !w.counters.pauseReason &&
            w.file.handle && !w.file.lastError && copy.qualifiedEpoch && w.qualifiedEpoch==copy.qualifiedEpoch &&
            emptyLedger && !p.heldMatch && !w.receiptWaitActive && !w.scanner.awaitingSubmission &&
            !w.scanner.carry && !w.scanner.failed && !w.scanner.oversized && !w.scanner.skipInitialSuffix &&
            w.scanner.offset==w.file.maximumSize && ringRead==ringWrite && readyRead==readyWrite &&
            p.preparedSequence==p.observedSequence && p.observedSequence==copy.generatedSequence &&
            owner.transport.submittedSequence==copy.generatedSequence && owner.owner.reportSequence==copy.generatedSequence &&
            ringWrite==copy.generatedSequence && ReadStatusWord(w.ring->reportWriteSequence)==ringWrite &&
            ReadStatusWord(w.ring->reportReadSequence)==ringRead && ReadStatusWord(p.readyWrite)==readyWrite &&
            ReadStatusWord(p.readyRead)==readyRead && ReadStatusWord(t.qualifiedEpoch)==copy.qualifiedEpoch;
    }
    const auto before=ReadStatusWord(t.quiescenceSequence);
    if ((before&1) || before>UINT64_MAX-2) {
        StoreStatusWord(t.quiescenceFailed,1); return; // Private evidence fails closed; no normal runtime fault.
    }
    StoreStatusWord(t.quiescenceSequence,before+1);
    StoreStatusWord(t.quiescence.quiescent,copy.quiescent);
    StoreStatusWord(t.quiescence.generatedSequence,copy.generatedSequence);
    StoreStatusWord(t.quiescence.observedSequence,copy.observedSequence);
    StoreStatusWord(t.quiescence.qualifiedEpoch,copy.qualifiedEpoch);
    StoreStatusWord(t.quiescenceSequence,before+2);
    StoreStatusWord(t.quiescenceAvailable,1);
}
DWORD WINAPI Run(void* context) noexcept {
    auto& t=*static_cast<NativeTransport*>(context);
    for (;;) {
        if (ReadStatusWord(t.stop) || ReadStatusWord(t.status->stopping)) {
            StoreStatusWord(t.quiescenceAvailable,0);
            if (t.startupCopied) CycleNativeReceipts(t.worker);
            break;
        }
        if (ReadStatusWord(t.armed) && ReadStatusWord(t.startupReady)==1) {
            // Invalidate the previous drain witness BEFORE any worker I/O or
            // mutation. No odd publication sequence crosses qualification/read.
            if (t.recovery) StoreStatusWord(t.quiescenceAvailable,0);
            if (!t.startupCopied) {
                t.worker.format.startup=t.startup;
                t.startupCopied=true;
            }
            SinkRequest request{};
            if (!StatusRevoked(*t.status) && ReadRequest(t,request) &&
                request.epoch!=ReadStatusWord(t.qualifiedEpoch)) {
                StoreStatusWord(t.qualifiedEpoch,0);
                const auto reason=QualifyNativeReceiptFile(t.worker,request.path,
                    static_cast<std::size_t>(request.pathChars),request.prefixMode,request.epoch);
                if (reason==TransportReason::None) StoreStatusWord(t.qualifiedEpoch,request.epoch);
                else if (reason>=TransportReason::ReceiptGap) LatchTransportFault(*t.status,reason);
            }
            CycleNativeReceipts(t.worker);
            if (t.recovery) PublishQuiescence(t);
        }
        const auto waited=WaitForSingleObject(t.wake,250);
        if (waited==WAIT_FAILED) { RevokeStatus(*t.status,Reason::WriterFailed); break; }
    }
    CloseNativeReceipts(t.worker);
    StoreStatusWord(t.quiescenceAvailable,0);
    CloseNativeHash(t.hash);
    SetEvent(t.finished);
    // Storage and thread/event handles remain process-resident. No game hook
    // joins or frees state while queued callbacks/readers can still reference it.
    return 0;
}
void CleanupUnpublished(NativeTransport* t) noexcept {
    if (!t) return;
    if (t->wake) CloseHandle(t->wake);
    if (t->finished) CloseHandle(t->finished);
    CloseNativeHash(t->hash);
    t->~NativeTransport();
    VirtualFree(t,0,MEM_RELEASE);
}
}
NativeTransport* PrepareNativeTransport(StatusWireV3& status,ReportRingV3& ring,
    const ConfigV3& config,const ReportingIdentities& identities,DWORD ownerThreadId,
    DWORD* error) noexcept {
    if (error) *error=ERROR_INVALID_PARAMETER;
    if (!error || !ownerThreadId || ownerThreadId!=GetCurrentThreadId() ||
        ReadStatusWord(status.headerReady)!=1 || status.header.validity!=CompleteHeaderIdentity ||
        ring.status!=&status || ReadStatusWord(ring.ready)!=1) return nullptr;
    void* storage=VirtualAlloc(nullptr,sizeof(NativeTransport),MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (!storage) { *error=ERROR_NOT_ENOUGH_MEMORY; return nullptr; }
    auto* t=::new(storage) NativeTransport{};
    t->status=&status; t->ownerThreadId=ownerThreadId;
    if (!PrepareNativeHash(t->hash)) { *error=t->hash.lastError; CleanupUnpublished(t); return nullptr; }
    NativeFormatContext format{};
    format.header=status.header; format.config=config; format.identities=identities;
    const auto& clock=ProductionNativeWorkerClock();
    FILETIME utc{};
    bool calibrated=clock.sample(clock.context,&format.log.calibrationQpcBefore);
    GetSystemTimePreciseAsFileTime(&utc);
    calibrated=calibrated && clock.sample(clock.context,&format.log.calibrationQpcAfter);
    format.log.utcFiletime=(static_cast<std::uint64_t>(utc.dwHighDateTime)<<32)|utc.dwLowDateTime;
    if (!calibrated || !format.log.utcFiletime ||
        format.log.calibrationQpcAfter<format.log.calibrationQpcBefore ||
        !InitializeNativeReceiptWorker(t->worker,status,ring,format,NativeHashOperations(t->hash),clock)) {
        *error=ERROR_INVALID_DATA; CleanupUnpublished(t); return nullptr;
    }
    t->wake=CreateEventW(nullptr,FALSE,FALSE,nullptr);
    t->finished=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    if (!t->wake || !t->finished) {
        *error=GetLastError(); CleanupUnpublished(t); return nullptr;
    }
    HMODULE retained{};
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(&Run),&retained)) {
        *error=GetLastError(); CleanupUnpublished(t); return nullptr;
    }
    t->thread=CreateThread(nullptr,0,Run,t,0,nullptr);
    if (!t->thread) { *error=GetLastError(); CleanupUnpublished(t); return nullptr; }
    // Optional direct-console diagnostics get one independent persistent worker.
    // Failure cannot disable repair/receipts; its DATA records the startup error.
    // The module is pinned and all storage is already process-resident here.
    StartReportingConsole(t->console,status);
    *error=ERROR_SUCCESS;
    return t;
}
bool CompleteNativeTransportStartup(NativeTransport* t,const NativeStartupSummary& startup) noexcept {
    if (!Owner(t) || ReadStatusWord(t->stop) ||
        InterlockedCompareExchange64(reinterpret_cast<volatile LONG64*>(&t->startupReady),2,0)!=0)
        return false;
    t->startup=startup;
    StoreStatusWord(t->startupReady,1);
    return true;
}
bool AttachNativeTransportRecovery(NativeTransport* t,RecoveryStatusWireV1* recovery) noexcept {
    if (!Owner(t) || !recovery || t->recovery || ReadStatusWord(t->armed) || ReadStatusWord(t->stop) ||
        !AttachReportingConsoleRecovery(t->console,recovery)) return false;
    t->recovery=recovery;
    return true;
}
void ArmNativeTransport(NativeTransport* t) noexcept {
    if (!Owner(t) || ReadStatusWord(t->stop)) return;
    // Installation may already have exposed a callback which revoked reporting.
    // The diagnostic thread must still be able to show disabled in that race.
    ArmReportingConsole(t->console);
    if (StatusRevoked(*t->status)) return;
    StoreStatusWord(t->armed,1);
    SetEvent(t->wake); // Startup API only; never called from a hook.
}
void StopNativeTransport(NativeTransport* t) noexcept {
    if (!t) return;
    StoreStatusWord(t->stop,1);
    StopReportingConsole(t->console);
    StoreStatusWord(t->qualifiedEpoch,0);
    SetEvent(t->wake); // Non-hook scheduling. Hooks publish StopStatus instead.
}
bool RequestNativeLogFile(NativeTransport* t,std::uint64_t epoch,std::uint64_t prefixMode,
    const std::uint16_t* path,std::size_t chars) noexcept {
    if (!Owner(t) || !ReadStatusWord(t->armed) || ReadStatusWord(t->stop) ||
        StatusRevoked(*t->status) || !epoch || prefixMode>1 || epoch<=t->request.epoch)
        return false;
    wchar_t checked[kNativeLogPathChars]{};
    if (!NativeLogPathSyntax(path,chars,checked)) return false;
    const auto before=ReadStatusWord(t->requestSequence);
    if ((before&1) || before>UINT64_MAX-2) { RevokeStatus(*t->status,Reason::CounterOverflow); return false; }
    SinkRequest copy{}; copy.epoch=epoch; copy.prefixMode=prefixMode; copy.pathChars=chars;
    std::memcpy(copy.path,path,chars*sizeof(*path));
    StoreStatusWord(t->requestSequence,before+1);
    for (std::size_t offset=0;offset<sizeof(copy);offset+=8) {
        std::uint64_t value{};
        std::memcpy(&value,reinterpret_cast<const unsigned char*>(&copy)+offset,8);
        auto* word=reinterpret_cast<std::uint64_t*>(reinterpret_cast<unsigned char*>(&t->request)+offset);
        StoreStatusWord(*word,value);
    }
    StoreStatusWord(t->requestSequence,before+2);
    // Deliberately no wake-up: the one worker polls at its bounded interval.
    return true;
}
std::uint64_t NativeTransportQualifiedEpoch(const NativeTransport* t) noexcept {
    return t && !ReadStatusWord(t->stop) && !ReadStatusWord(t->status->stopping) ?
        ReadStatusWord(t->qualifiedEpoch) : 0;
}
bool NativeTransportQuiescent(const NativeTransport* t,std::uint64_t expectedGenerated,
    std::uint64_t expectedEpoch) noexcept {
    if (!Owner(t) || !t->recovery || !expectedEpoch || !ReadStatusWord(t->armed) || ReadStatusWord(t->stop) ||
        ReadStatusWord(t->status->stopping) || ReadStatusWord(t->quiescenceFailed)) return false;
    const auto& p=t->worker.pipeline;
    const auto* ring=t->worker.ring; // Both immutable after cold preparation.
    for (unsigned retry=0;retry<3;++retry) {
        if (ReadStatusWord(t->quiescenceAvailable)!=1) return false;
        const auto before=ReadStatusWord(t->quiescenceSequence);
        if (before<2 || (before&1)) continue;
        QuiescenceSnapshot copy{};
        copy.quiescent=ReadStatusWord(t->quiescence.quiescent);
        copy.generatedSequence=ReadStatusWord(t->quiescence.generatedSequence);
        copy.observedSequence=ReadStatusWord(t->quiescence.observedSequence);
        copy.qualifiedEpoch=ReadStatusWord(t->quiescence.qualifiedEpoch);
        const bool current=copy.quiescent==1 && copy.generatedSequence==expectedGenerated &&
            copy.observedSequence==expectedGenerated && copy.qualifiedEpoch==expectedEpoch &&
            ReadStatusWord(t->qualifiedEpoch)==expectedEpoch &&
            ReadStatusWord(ring->reportWriteSequence)==expectedGenerated &&
            ReadStatusWord(ring->reportReadSequence)==expectedGenerated &&
            ReadStatusWord(p.readyRead)==ReadStatusWord(p.readyWrite);
        const auto after=ReadStatusWord(t->quiescenceSequence);
        if (after<before) return false;
        if (before==after && !(after&1)) return current && ReadStatusWord(t->quiescenceAvailable)==1 &&
            !ReadStatusWord(t->quiescenceFailed) && !ReadStatusWord(t->stop) &&
            !ReadStatusWord(t->status->stopping) && ReadStatusWord(t->qualifiedEpoch)==expectedEpoch &&
            ReadStatusWord(ring->reportWriteSequence)==expectedGenerated &&
            ReadStatusWord(ring->reportReadSequence)==expectedGenerated;
    }
    return false;
}
const NativeReadyFrame* NativeTransportFrame(NativeTransport* t,std::uint64_t epoch) noexcept {
    if (!Owner(t) || !epoch || ReadStatusWord(t->stop) || StatusRevoked(*t->status) ||
        ReadStatusWord(t->qualifiedEpoch)!=epoch || ReadStatusWord(t->status->logIdentityReady)!=1)
        return nullptr;
    const auto* frame=PeekNativeFrame(t->worker.pipeline);
    if (frame && frame->sequence && !ReadStatusWord(t->status->worker.startupObserved)) return nullptr;
    return frame;
}
bool NativeTransportReturned(NativeTransport* t,std::uint64_t ticket) noexcept {
    // Normal-return evidence remains recordable if a fault/stop raced the call.
    return Owner(t) && ReleaseNativeFrame(t->worker.pipeline,ticket);
}
#if defined(RS2_REPORTING_TESTING)
bool WaitNativeTransportForTest(NativeTransport* t,DWORD milliseconds) noexcept {
    return t && WaitForSingleObject(t->thread,milliseconds)==WAIT_OBJECT_0 &&
        (!t->console.thread || t->console.thread==INVALID_HANDLE_VALUE ||
         WaitForSingleObject(t->console.thread,milliseconds)==WAIT_OBJECT_0);
}
#endif
}
