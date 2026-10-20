#include "companion/steam_reporting_console.h"
#include <cstdio>
#include <cstring>

namespace rs2fix::reporting {
namespace {
ReporterStorage g_prearmDisabled{};
constexpr const char* kTransportNames[]{"none","awaiting-logger","category-suppressed",
    "force-flush-missing","framing-unsupported","sink-unsupported","file-manager-unsupported",
    "receipt-unavailable","reader-behind","receipt-overdue","credit-pressure",
    "same-file-requalification","receipt-gap","receipt-corrupt","file-identity-changed",
    "file-truncated","profile-unsafe","native-log-exception"};
static_assert(sizeof(kTransportNames)/sizeof(*kTransportNames)==static_cast<unsigned>(TransportReason::Count));
constexpr const char* kRecoveryPhases[]{"disabled","armed","requested","qualifying","finish-submitted",
    "finish-accepted","recreating","published","observed","failed","rejected"};
constexpr const char* kRecoveryReasons[]{"none","permission-disabled","invalid-request","source-unavailable",
    "source-changed","spectators-present","counts-invalid","native-profile-mismatch","lifecycle-changed",
    "kernel-changed","heartbeat-unavailable","schedule-unsupported","descriptor-unavailable","request-pool-unavailable",
    "generic-pool-unavailable","recording-not-quiescent","quota-unavailable","retirement-failed","recording-unavailable",
    "finish-enqueue-failed","callback-invalid","finish-rejected","finish-timeout","attempt-timeout","create-failed",
    "cache-cleared-no-session","clock-fault","native-exception","inverse-unavailable","control-worker-unavailable","binding-not-ready",
    "control-config-missing","control-config-invalid","control-identity-mismatch","control-path-rejected",
    "control-security-rejected","control-read-failure","control-endpoint-unavailable",
    "guard-snapshot-invalid-context","guard-snapshot-unreadable","guard-snapshot-changed",
    "guard-snapshot-budget","guard-snapshot-shape","guard-snapshot-alias",
    "guard-snapshot-descriptor","guard-snapshot-pool","guard-snapshot-readiness",
    "guard-snapshot-hook","guard-snapshot-allocator","guard-snapshot-import",
    "guard-snapshot-provenance","guard-readiness","guard-standalone","guard-session",
    "guard-issued-id","guard-finish-free","guard-create-free","guard-heartbeat-slot",
    "guard-heartbeat-type","guard-heartbeat-id","guard-generic-id",
    "guard-generic-holder","guard-heartbeat-references","snapshot-guard-passed"};
static_assert(std::size(kRecoveryPhases)==static_cast<std::size_t>(RecoveryPhase::Count));
static_assert(std::size(kRecoveryReasons)==static_cast<std::size_t>(RecoveryReason::Count));
#if defined(RS2_RECOVERY_GUARD_PROBE)
constexpr char kRecoveryModeSuffix[]="; guard_probe=read-only";
#else
constexpr char kRecoveryModeSuffix[]="";
#endif
const char* StateName(ConsoleStateV3 state) noexcept {
    switch(state) {
    case ConsoleStateV3::WaitingLogger:return "waiting-logger";
    case ConsoleStateV3::Paused:return "paused";
    case ConsoleStateV3::Ready:return "ready";
    case ConsoleStateV3::Disabled:return "disabled";
    default:return nullptr;
    }
}
bool LocalRead(void* context,std::size_t at,void* out,std::size_t bytes) noexcept {
    if (!out || (at%8) || (bytes%8) || at>sizeof(StatusWireV3) || bytes>sizeof(StatusWireV3)-at) return false;
    const auto* base=reinterpret_cast<const unsigned char*>(context);
    for (std::size_t i=0;i<bytes;i+=8) {
        const auto value=ReadStatusWord(*reinterpret_cast<const std::uint64_t*>(base+at+i));
        std::memcpy(static_cast<unsigned char*>(out)+i,&value,8);
    }
    return true;
}
bool Clock(void*,std::uint64_t* output) noexcept {
    LARGE_INTEGER value{};
    if (!QueryPerformanceCounter(&value) || value.QuadPart<=0) return false;
    *output=static_cast<std::uint64_t>(value.QuadPart); return true;
}
bool Add(std::uint64_t& value,std::uint64_t delta=1) noexcept {
    // Optional console diagnostics must never wrap or revoke reporting.
    if (delta>UINT64_MAX-value) { value=UINT64_MAX; return false; }
    value+=delta; return true;
}
bool Same(const ConsoleNoticeV3& a,const ConsoleNoticeV3& b) noexcept {
    return a.state==b.state && a.transportReason==b.transportReason && a.reason==b.reason &&
        a.epoch==b.epoch && a.ownerTransition==b.ownerTransition && a.workerCondition==b.workerCondition;
}
bool SameRecovery(const RecoveryStatusWireV1& a,const RecoveryStatusWireV1& b) noexcept {
    const auto& x=a.payload; const auto& y=b.payload;
    constexpr auto noticeFlags=RecoveryRestartRequired|RecoveryTerminal|RecoveryExceptionObserved;
    return a.pid==b.pid && !std::memcmp(a.runId,b.runId,sizeof(a.runId)) &&
        x.operationSequence==y.operationSequence && x.transitionSequence==y.transitionSequence &&
        x.phase==y.phase && x.reason==y.reason && (x.flags&noticeFlags)==(y.flags&noticeFlags);
}
bool RecoveryTerminalNotice(const RecoveryStatusWireV1& wire) noexcept {
    const auto& p=wire.payload;
    return (p.flags&(RecoveryTerminal|RecoveryExceptionObserved|RecoveryRestartRequired)) ||
        p.phase==static_cast<std::uint64_t>(RecoveryPhase::Failed) ||
        p.phase==static_cast<std::uint64_t>(RecoveryPhase::Rejected);
}
bool Publish(ReportingConsole& c) noexcept { return PublishConsoleV3(*c.status,c.diagnostics); }
bool Finish(ReportingConsole& c) noexcept {
    c.diagnostics.workerState=3; Publish(c); return false;
}
DWORD WINAPI Run(void* context) noexcept {
    auto& c=*static_cast<ReportingConsole*>(context);
    while(CycleReportingConsole(c)) c.ops.sleep(c.ops.context,kConsolePollMs);
    return 0;
}
}

bool SelectReportingConsoleNotice(const StatusSnapshotV3& snapshot,std::uint64_t now,
    ConsoleNoticeV3* output) noexcept {
    if (!output || !snapshot.coreAvailable || !snapshot.headerAvailable || !now) return false;
    *output={};
    const auto& w=snapshot.wire;
    const auto& t=w.ownerTransport;
    auto& n=*output;
    if (w.stopping || t.state==static_cast<std::uint64_t>(TransportState::Stopping)) return false;
    n.epoch=t.pauseEpoch; n.ownerTransition=t.transitionSequence;
    n.workerCondition=w.worker.pauseConditionSequence;
    n.sourceQpc=t.transitionQpc ? t.transitionQpc : w.owner.lastOwnerQpc;
    if (!n.sourceQpc) n.sourceQpc=now;
    if (w.fatalTransportReason || w.revokeReasons || w.lossReasons ||
        t.state==static_cast<std::uint64_t>(TransportState::Faulted) ||
        w.owner.phase==static_cast<std::uint64_t>(ReportPhaseV3::Rejected) ||
        w.owner.phase==static_cast<std::uint64_t>(ReportPhaseV3::Faulted)) {
        n.state=ConsoleStateV3::Disabled;
        n.transportReason=w.fatalTransportReason!=0;
        n.reason=w.fatalTransportReason;
        if (!n.transportReason) {
            const auto bits=w.revokeReasons|w.lossReasons;
            n.reason=w.owner.reason;
            if (!n.reason || n.reason>=kReasonCount || (bits && !(bits&(1ULL<<n.reason)))) {
                n.reason=static_cast<std::uint64_t>(Reason::StatusUnavailable);
                for (std::uint64_t bit=1;bit<kReasonCount;++bit)
                    if(bits&(1ULL<<bit)) { n.reason=bit; break; }
            }
        }
        return true;
    }
    // A receipt worker closes its gate before publishing the condition. Even
    // while owner DATA still says Running, never select the older ready notice.
    const auto workerReason=w.workerPauseReason ? w.workerPauseReason : w.worker.pauseReason;
    const auto reason=workerReason ? workerReason : t.reason;
    if (reason || snapshot.workerPauseChanged ||
        t.state==static_cast<std::uint64_t>(TransportState::WaitingLogger) ||
        t.state==static_cast<std::uint64_t>(TransportState::Paused)) {
        n.state=w.owner.readyQpc ? ConsoleStateV3::Paused : ConsoleStateV3::WaitingLogger;
        n.transportReason=true;
        n.reason=reason ? reason : static_cast<std::uint64_t>(TransportReason::AwaitingLogger);
        if (workerReason && w.worker.pauseReason==workerReason && w.worker.pauseConditionQpc)
            n.sourceQpc=w.worker.pauseConditionQpc;
        else if (workerReason && w.workerPauseReason!=w.worker.pauseReason) {
            // Gate-first publication: the newer condition identity is not yet
            // available. Do not attach the older condition's QPC/sequence to it.
            n.workerCondition=0; n.sourceQpc=now;
        }
        return true;
    }
    if (SnapshotCurrentlyReadyV3(snapshot,now,w.header.qpcFrequency)) {
        n.state=ConsoleStateV3::Ready; n.transportReason=true;
        if (!n.ownerTransition) n.sourceQpc=w.owner.readyQpc;
    } else {
        // Running transport alone is not ready: source/binding/owner freshness
        // and the first successful ManagePump (readyQpc) are still required.
        n.state=w.owner.readyQpc ? ConsoleStateV3::Paused : ConsoleStateV3::WaitingLogger;
        n.reason=w.owner.reason ? w.owner.reason : static_cast<std::uint64_t>(Reason::SourceUnavailable);
    }
    return true;
}
bool FormatReportingConsoleNotice(const StatusHeader& header,const ConsoleNoticeV3& n,
    const char* event,ConsoleReportContext* output) noexcept {
    if (!output) return false;
    *output={};
    const auto* state=StateName(n.state);
    if (!state || !event || (std::strcmp(event,"initial") && std::strcmp(event,"paused") &&
        std::strcmp(event,"resumed") && std::strcmp(event,"disabled")) ||
        (n.transportReason ? n.reason>=static_cast<std::uint64_t>(TransportReason::Count) : n.reason>=kReasonCount))
        return false;
    char run[33]{};
    constexpr char hex[]="0123456789abcdef";
    for(std::size_t i=0;i<16;++i) { run[i*2]=hex[header.runId[i]>>4]; run[i*2+1]=hex[header.runId[i]&15]; }
    const auto* reason=n.transportReason ? kTransportNames[n.reason] : ReasonName(static_cast<Reason>(n.reason));
    const int size=std::snprintf(output->line,sizeof(output->line),
        "[RS2SteamReport] v0.6.2.0; status=%s; event=%s; mode=%s; pid=%u; run_id=%s; "
        "epoch=%llu; qpc=%llu; reason_domain=%s; reason=%s; owner_transition=%llu; worker_condition=%llu\r\n",
        state,event,ModeName(static_cast<Mode>(header.configuredMode)),header.pid,run,
        static_cast<unsigned long long>(n.epoch),static_cast<unsigned long long>(n.sourceQpc),
        n.transportReason ? "transport" : "runtime",reason,
        static_cast<unsigned long long>(n.ownerTransition),static_cast<unsigned long long>(n.workerCondition));
    if (size<=0 || static_cast<std::size_t>(size)>=sizeof(output->line)) { *output={}; return false; }
    output->bytes=static_cast<DWORD>(size);
    return ValidConsoleReport(*output);
}
bool FormatRecoveryConsoleNotice(const RecoveryStatusWireV1& wire,ConsoleReportContext* output) noexcept {
    if (!output) return false;
    *output={};
    if (wire.schema!=kRecoveryStatusSchemaV1 || wire.bytes!=sizeof(wire) ||
        wire.artifactVersion!=kRecoveryArtifactVersion || wire.headerReady!=1 || !wire.pid ||
        !RecoveryPayloadValid(wire.payload)) return false;
    char run[33]{}; unsigned bits{}; constexpr char hex[]="0123456789abcdef";
    for(unsigned i=0;i<16;++i) {
        bits|=wire.runId[i]; run[2*i]=hex[wire.runId[i]>>4]; run[2*i+1]=hex[wire.runId[i]&15];
    }
    if (!bits) return false;
    const auto& p=wire.payload;
    const int size=std::snprintf(output->line,sizeof(output->line),
        "[RS2LeechRecovery] v0.6.2.0%s; pid=%u; run_id=%s; phase=%s; reason=%s; transition=%llu; "
        "last_valid_qpc=%llu; restart_required=%u\r\n",kRecoveryModeSuffix,wire.pid,run,kRecoveryPhases[p.phase],kRecoveryReasons[p.reason],
        static_cast<unsigned long long>(p.transitionSequence),static_cast<unsigned long long>(p.qpc),
        (p.flags&RecoveryRestartRequired) ? 1U : 0U);
    if (size<=0 || static_cast<std::size_t>(size)>=sizeof(output->line)) { *output={}; return false; }
    output->bytes=static_cast<DWORD>(size);
    return ValidConsoleReport(*output);
}

bool CycleReportingConsole(ReportingConsole& c) noexcept {
    if (!c.status) return false;
    if (ReadStatusWord(c.stop) || ReadStatusWord(c.status->stopping)) return Finish(c);
    if (!ReadStatusWord(c.armed)) return true;
    c.diagnostics.workerState=1;
    const auto ticks=c.ops.ticks(c.ops.context);
    if (c.haveClock && ticks<c.lastClockMs) {
        c.diagnostics.lastError=ERROR_INVALID_DATA; return Finish(c);
    }
    c.lastClockMs=ticks; c.haveClock=true;
    // Independent immutable identity/recovery read precedes every ordinary
    // CORE/readiness/selection failure. No normal fault grants recovery authority.
    StatusHeader recoveryIdentity{};
    RecoveryStatusSnapshot recovery{};
    bool recoverySelectable{};
    if (c.recovery && ReadReportingIdentityV3({c.status,LocalRead},&recoveryIdentity)==SnapshotResultV3::Coherent &&
        ReadRecoveryStatusSnapshot(*c.recovery,recoveryIdentity,&recovery)==RecoverySnapshotResult::Coherent) {
        const auto& p=recovery.wire.payload;
        recoverySelectable=p.phase!=static_cast<std::uint64_t>(RecoveryPhase::Disabled) || p.reason || p.flags;
        if (recoverySelectable && (!c.haveRecoverySelection || !SameRecovery(c.latestRecovery,recovery.wire))) {
            if (c.recoveryPending && !c.recoveryPendingAttempted && !Add(c.diagnostics.skippedTransitions)) return Finish(c);
            c.recoveryPending=true; c.recoveryPendingAttempted=false; c.haveRecoverySelection=true;
        }
        if (recoverySelectable) c.latestRecovery=recovery.wire;
    }
    std::uint64_t qpc{};
    if (!c.qpc(c.ops.context,&qpc) || !qpc) {
        c.diagnostics.lastError=ERROR_INVALID_DATA; return Publish(c) ? true : Finish(c);
    }
    if (qpc<c.lastClockQpc) { c.diagnostics.lastError=ERROR_INVALID_DATA; return Finish(c); }
    c.lastClockQpc=qpc;
    StatusSnapshotV3 snapshot{};
    const auto sampled=ReadStatusSnapshotV3({c.status,LocalRead},&snapshot);
    // The owner can publish between the first clock and the coherent read.
    // Judge freshness with a post-snapshot clock, otherwise a newer healthy
    // lastOwnerQpc looks like a future timestamp and fabricates a pause/resume.
    std::uint64_t snapshotQpc{};
    if (!c.qpc(c.ops.context,&snapshotQpc) || !snapshotQpc) {
        c.diagnostics.lastError=ERROR_INVALID_DATA; return Publish(c) ? true : Finish(c);
    }
    if (snapshotQpc<qpc) { c.diagnostics.lastError=ERROR_INVALID_DATA; return Finish(c); }
    qpc=snapshotQpc; c.lastClockQpc=qpc;
    ConsoleNoticeV3 notice{};
    const bool normalSelectable=sampled==SnapshotResultV3::Coherent && SelectReportingConsoleNotice(snapshot,qpc,&notice);
    if (!normalSelectable) c.diagnostics.lastError=sampled==SnapshotResultV3::Busy ? ERROR_RETRY : ERROR_INVALID_DATA;
    if (normalSelectable && (!c.haveSelection || !Same(c.latest,notice))) {
        // This counts notices actually superseded before an attempt. It cannot
        // reconstruct unseen intermediate states while stdout was blocked.
        if (c.pending && !c.pendingAttempted && !Add(c.diagnostics.skippedTransitions)) return Finish(c);
        c.latest=notice; c.haveSelection=true; c.pending=true; c.pendingAttempted=false;
    }
    const bool normalPending=normalSelectable && c.pending;
    const bool recoveryPending=recoverySelectable && c.recoveryPending;
    // Coalesced latest scalar selections, no FIFO. Choose the newest available
    // terminal/fault first; all channels share the same one-second attempt gate.
    const bool normalTerminal=normalPending && notice.state==ConsoleStateV3::Disabled;
    const bool recoveryTerminal=recoveryPending && RecoveryTerminalNotice(recovery.wire);
    const bool useRecovery=recoveryPending && (!normalPending ||
        (recoveryTerminal && !normalTerminal) ||
        (recoveryTerminal==normalTerminal && recovery.wire.payload.qpc>=notice.sourceQpc));
    if ((!normalPending && !recoveryPending) || (c.haveAttempt && ticks-c.lastAttemptMs<1000))
        return Publish(c) ? true : Finish(c);
    const char* event=notice.state==ConsoleStateV3::Disabled ? "disabled" :
        notice.state==ConsoleStateV3::Ready ? (c.everReady ? "resumed" : "initial") :
        c.haveNormalAttempt ? "paused" : "initial";
    ConsoleReportContext report{};
    if (!(useRecovery ? FormatRecoveryConsoleNotice(recovery.wire,&report) :
        FormatReportingConsoleNotice(snapshot.wire.header,notice,event,&report))) {
        c.diagnostics.lastError=ERROR_INVALID_DATA;
        if (useRecovery) c.recoveryPending=false; else c.pending=false;
        return Publish(c) ? true : Finish(c);
    }
    DWORD error{};
    const HANDLE output=c.ops.getStdOutput(c.ops.context,&error);
    // No saved queue: refuse a snapshot made stale during handle/format work.
    // State can still change after this check or while the synchronous write is
    // blocked; the line describes the selected epoch/QPC, never future readiness.
    if (ReadStatusWord(c.stop) || ReadStatusWord(c.status->stopping)) return Finish(c);
    if (useRecovery) {
        RecoveryStatusSnapshot current{};
        StatusHeader identity{};
        if (ReadReportingIdentityV3({c.status,LocalRead},&identity)!=SnapshotResultV3::Coherent ||
            std::memcmp(&identity,&recoveryIdentity,sizeof(identity)) ||
            ReadRecoveryStatusSnapshot(*c.recovery,identity,&current)!=RecoverySnapshotResult::Coherent ||
            current.wire.ownerSequence!=recovery.wire.ownerSequence) return Publish(c) ? true : Finish(c);
    } else if (ReadStatusWord(c.status->workerPauseReason)!=snapshot.wire.workerPauseReason ||
        ReadStatusWord(c.status->fatalTransportReason)!=snapshot.wire.fatalTransportReason ||
        ReadStatusWord(c.status->revokeReasons)!=snapshot.wire.revokeReasons ||
        ReadStatusWord(c.status->lossReasons)!=snapshot.wire.lossReasons ||
        ReadStatusWord(c.status->ownerSequence)!=snapshot.wire.ownerSequence ||
        ReadStatusWord(c.status->workerSequence)!=snapshot.wire.workerSequence) return Publish(c) ? true : Finish(c);
    const auto attemptTicks=c.ops.ticks(c.ops.context);
    std::uint64_t attemptQpc{};
    if (attemptTicks<ticks || (c.haveAttempt && attemptTicks-c.lastAttemptMs<1000) ||
        !c.qpc(c.ops.context,&attemptQpc) || !attemptQpc) {
        c.diagnostics.lastError=ERROR_INVALID_DATA; return Publish(c) ? true : Finish(c);
    }
    if (attemptQpc<qpc) { c.diagnostics.lastError=ERROR_INVALID_DATA; return Finish(c); }
    c.lastClockQpc=attemptQpc;
    // Even, in-flight DATA is visible before any potentially blocking stdout IO.
    // No lock, seqlock, native engine object or repair admission crosses WriteFile.
    if (c.diagnostics.attempts==UINT64_MAX) return Finish(c);
    ++c.diagnostics.attempts; c.diagnostics.lastAttemptQpc=attemptQpc;
    c.diagnostics.lastNoticeEpoch=useRecovery ? recovery.wire.payload.transitionSequence : notice.epoch;
    c.diagnostics.workerState=2; c.lastAttemptMs=attemptTicks; c.haveAttempt=true;
    if (useRecovery) c.recoveryPendingAttempted=true;
    else { c.pendingAttempted=true; c.haveNormalAttempt=true; }
    if (!PublishConsoleV3(*c.status,c.diagnostics)) return Finish(c);
    DWORD written{};
    const bool ok=output && output!=INVALID_HANDLE_VALUE &&
        c.ops.write(c.ops.context,output,report.line,report.bytes,&written,&error) && written==report.bytes;
    if(ok) {
        if (!Add(c.diagnostics.written)) return Finish(c);
        if (useRecovery) c.recoveryPending=false; else c.pending=false;
    } else if (!Add(c.diagnostics.failures)) return Finish(c);
    c.diagnostics.lastError=ok ? ERROR_SUCCESS : error ? error : ERROR_WRITE_FAULT;
    if(ok && !useRecovery && notice.state==ConsoleStateV3::Ready) c.everReady=true;
    c.diagnostics.workerState=1;
    if (!Publish(c)) return Finish(c);
    return !ReadStatusWord(c.stop) && !ReadStatusWord(c.status->stopping) ? true : Finish(c);
}
ReporterStartResult StartReportingConsole(ReportingConsole& c,StatusWireV3& status,
    const ConsoleStatusOps& ops,bool (*qpc)(void*,std::uint64_t*) noexcept) noexcept {
    if (!ops.ticks || !ops.sleep || !ops.getStdOutput || !ops.write || !ops.startThread || !qpc ||
        ReadStatusWord(status.headerReady)!=1) return {false,ERROR_INVALID_PARAMETER};
    if (InterlockedCompareExchange(&c.claimed,1,0)!=0) return {false,ERROR_ALREADY_EXISTS};
    c.status=&status; c.ops=ops; c.qpc=qpc;
    MemoryBarrier();
    DWORD error{};
    c.thread=ops.startThread(ops.context,Run,&c,&error);
    if (!c.thread || c.thread==INVALID_HANDLE_VALUE) {
        c.diagnostics.workerState=3; c.diagnostics.lastError=error ? error : ERROR_NOT_ENOUGH_MEMORY;
        Publish(c); return {false,static_cast<DWORD>(c.diagnostics.lastError)};
    }
    // Thread handle/storage survive process lifetime; no hook-side close/join.
    return {true,ERROR_SUCCESS};
}
ReporterStartResult StartReportingConsole(ReportingConsole& c,StatusWireV3& status) noexcept {
    return StartReportingConsole(c,status,ProductionConsoleStatusOps(),Clock);
}
bool AttachReportingConsoleRecovery(ReportingConsole& c,RecoveryStatusWireV1* recovery) noexcept {
    if (!c.status || !recovery || c.recovery || ReadStatusWord(c.armed) || ReadStatusWord(c.stop)) return false;
    StatusHeader identity{}; RecoveryStatusSnapshot snapshot{};
    if (ReadReportingIdentityV3({c.status,LocalRead},&identity)!=SnapshotResultV3::Coherent ||
        ReadRecoveryStatusSnapshot(*recovery,identity,&snapshot)!=RecoverySnapshotResult::Coherent) return false;
    c.recovery=recovery;
    // Only the arming release publishes this cold pointer to the worker.
    return true;
}
void ArmReportingConsole(ReportingConsole& c) noexcept { StoreStatusWord(c.armed,1); }
void StopReportingConsole(ReportingConsole& c) noexcept { StoreStatusWord(c.stop,1); }
void ScheduleReportingDisabledNotice(const StatusWireV3& status,Reason reason) noexcept {
    if (InterlockedCompareExchange(&g_prearmDisabled.claimed,0,0)) return;
    const auto* header=ReadStatusWord(status.headerReady)==1 ? &status.header : nullptr;
    const bool identified=header && (header->validity&CompleteHeaderIdentity)==CompleteHeaderIdentity;
    char run[33]{}; constexpr char hex[]="0123456789abcdef";
    if (identified) for(unsigned i=0;i<16;++i) {
        run[2*i]=hex[header->runId[i]>>4]; run[2*i+1]=hex[header->runId[i]&15];
    }
    ConsoleReportContext report{};
    const int bytes=std::snprintf(report.line,sizeof(report.line),
        "[RS2SteamReport] v0.6.2.0; status=disabled; mode=%s; reason=%s; run_id=%s; pid=%u\r\n",
        ModeName(header ? static_cast<Mode>(header->configuredMode) : Mode::Invalid),ReasonName(reason),
        identified ? run : "unavailable",header ? header->pid : 0);
    if (bytes>0 && static_cast<std::size_t>(bytes)<sizeof(report.line)) {
        report.bytes=static_cast<DWORD>(bytes);
        TryStartReporter(&g_prearmDisabled,report,ProductionConsoleStatusOps());
    }
}
}
