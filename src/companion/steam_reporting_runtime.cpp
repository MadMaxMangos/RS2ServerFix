#include "companion/steam_reporting_runtime.h"
#include "companion/leech_recovery.h"
#include <limits>

namespace rs2fix::reporting {
namespace {
constexpr std::uint64_t kInitialLifecycle = (1ULL << 32) | 1;
std::uint64_t Lifecycle(observer::DispatchState& state) noexcept {
    return static_cast<std::uint64_t>(InterlockedCompareExchange64(&state.lifecycle,0,0));
}
bool KnownLifecycle(observer::DispatchState& state) noexcept {
    return !InterlockedCompareExchange(&state.unknownLifecycle,0,0);
}
void Notice(Runtime& state, bool ready, Reason reason) noexcept {
    if (state.config.notice) state.config.notice(state.config.noticeContext,ready,reason);
}
void Count(Runtime& state, std::uint64_t& counter) noexcept {
    if (!IncrementCounter(counter)) RevokeRuntime(state,Reason::CounterOverflow);
}
void Bypass(Runtime& state, Reason reason) noexcept {
    if (reason==Reason::None) return;
    state.counters.reason=static_cast<std::uint64_t>(reason);
    const auto index=static_cast<std::size_t>(reason);
    if (index<kReasonCount) Count(state,state.counters.reasons[index]);
    if (state.producer.fault!=Reason::None) RevokeRuntime(state,state.producer.fault);
    if (ReadTaskPhase(state.task)==TaskPhase::Inert) RevokeRuntime(state,state.task.fault);
}
ReportRecordV3 Record(Runtime& state, RecordKindV3 kind, std::int64_t now, Reason reason=Reason::None) noexcept {
    ReportRecordV3 result{};
    result.header.qpc=now<0 ? 0 : static_cast<std::uint64_t>(now);
    result.header.sourceEpoch=state.counters.sourceEpoch;
    result.header.bindingEpoch=state.counters.bindingEpoch;
    result.header.kind=static_cast<std::uint32_t>(kind);
    result.header.reason=static_cast<std::uint32_t>(reason);
    return result;
}
bool Emit(Runtime& state, const ReportRecordV3& record,CaptureReservation* credit) noexcept {
    if (StatusRevoked(*state.config.status)) return false;
    const bool control=record.header.kind==static_cast<std::uint32_t>(RecordKindV3::Control);
    if (!credit || !credit->active || !credit->remaining || credit->control!=control ||
        !state.transport.reservedCredits) {
        LoseStatus(*state.config.status,Reason::RecordLoss); return false;
    }
    std::uint64_t sequence{};
    if (!state.config.sink.publish ||
        !state.config.sink.publish(state.config.sink.context,record,&sequence) || !sequence) {
        // The ring already distinguishes post-stop suppression from admitted
        // loss. A foreign sink must obey the same no-silent-loss contract.
        if (ReadStatusWord(state.config.status->stopping)) return false;
        if (!StatusRevoked(*state.config.status)) LoseStatus(*state.config.status,Reason::RecordLoss);
        Notice(state,false,Reason::RecordLoss);
        return false;
    }
    --credit->remaining; --state.transport.reservedCredits;
    state.counters.reportSequence=sequence;
    state.transport.generatedSequence=sequence;
    return true;
}
void EmitState(Runtime& state, std::int64_t now, CallerClass classification, Reason reason,CaptureReservation* credit) noexcept {
    auto record=Record(state,RecordKindV3::State,now,reason);
    auto& value=record.payload.state;
    value.phase=state.counters.phase;
    value.requestSequence=state.producer.requestSequence;
    value.witnessSequence=state.producer.witnessSequence;
    value.buildSequence=state.counters.buildSequence;
    value.pendingSinceQpc=state.producer.pending.active ? state.producer.pending.stagedQpc : 0;
    value.freshSinceQpc=state.producer.fresh.valid ? state.producer.fresh.lowerBoundQpc : 0;
    value.qualificationFlags=(state.sdkReady ? 1ULL : 0) | (state.sourceReady ? 2ULL : 0);
    value.clientQualificationMs=state.clientQualificationMs;
    value.nativeTaskState=state.sourceReady ? state.nativeTaskState : 0;
    if (state.sourceReady && state.schedule.valid) {
        const auto& schedule=state.schedule;
        value.nativeScheduleValid=1;
        value.nativeScheduleAnchorBits=schedule.anchorBits;
        value.nativeErrorsBits=static_cast<std::uint32_t>(schedule.errors);
        value.nativeThrottlesBits=static_cast<std::uint32_t>(schedule.throttles);
        value.nativeExpedite=schedule.expedite;
        value.nativeRetryLimit=schedule.retryLimit;
        value.nativeIntervalUnits=schedule.interval;
        value.nativeIntervalOverrideBits=static_cast<std::uint64_t>(schedule.intervalOverride);
        value.nativeRetryOverrideBits=static_cast<std::uint64_t>(schedule.retryOverride);
        value.nativeDelayUnits=schedule.delayUnits;
        value.nativeTier=static_cast<std::uint32_t>(schedule.tier);
    }
    value.mode=static_cast<std::uint32_t>(state.config.mode);
    value.classification=static_cast<std::uint32_t>(classification);
    if (state.sourceReady) {
        value.pi=state.source.outer.pi; value.bots=state.source.outer.bots;
        value.maximum=state.source.outer.maximum;
    }
    value.pending=state.producer.pending.active; value.fresh=state.producer.fresh.valid;
    value.bound=ReadTaskPhase(state.task)==TaskPhase::Armed;
    Emit(state,record,credit);
}
bool AcceptedInterface(void* context, std::uintptr_t object, std::uint64_t lifecycle) noexcept {
    auto& state=*static_cast<Runtime*>(context);
    observer::AcceptedBindingSnapshot binding{};
    return RuntimeAdmission(state) && observer::ReadAcceptedBinding(*state.config.dispatch,
        reinterpret_cast<const void*>(object),&binding) && binding.lifecycle==lifecycle;
}
SourceReadContext SourceContext(Runtime& state) noexcept {
    return {state.config.memory,state.config.hostBase,state.config.hostSize,
        state.idleLifecycle,&state,AcceptedInterface,&state.config.source};
}
bool SafeOwner(void* context) noexcept {
    const auto& state=*static_cast<Runtime*>(context);
    // Diagnostic revocation still permits one exact owned inverse. SDK teardown,
    // an overlapping lifecycle or a changed gate does not: thread identity alone
    // cannot establish that native table ownership remains safe.
    return RuntimeOwner(state) && state.sdkReady &&
        !ReadStatusWord(state.config.status->stopping) &&
        observer::ReadGate(*state.config.dispatch)==observer::Gate::Armed &&
        KnownLifecycle(*state.config.dispatch) && Lifecycle(*state.config.dispatch)==state.idleLifecycle;
}
bool OwnerThread(void* context) noexcept {
    return RuntimeOwner(*static_cast<Runtime*>(context));
}
Reason FaultReason(const Runtime& state) noexcept {
    auto reasons=ReadStatusWord(state.config.status->lossReasons);
    if (!reasons) reasons=ReadStatusWord(state.config.status->revokeReasons);
    for (std::size_t i=1;i<kReasonCount;++i)
        if (reasons&(1ULL<<i)) return static_cast<Reason>(i);
    return Reason::StatusUnavailable;
}
bool TaskAdmission(void* context) noexcept {
    auto& state=*static_cast<Runtime*>(context);
    return state.taskAdmission && state.sourceReady && RuntimeAdmission(state);
}
bool Exchange(void* context, std::uintptr_t address, std::uintptr_t expected,
    std::uintptr_t desired, std::uintptr_t* observed, DWORD* error) noexcept {
    if (!context || !address || (address&7) || !observed || !error) return false;
    if (!SafeOwner(context)) { *error=ERROR_INVALID_STATE; return false; }
    __try {
        *observed=reinterpret_cast<std::uintptr_t>(InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(address),reinterpret_cast<PVOID>(desired),
            reinterpret_cast<PVOID>(expected)));
        *error=ERROR_SUCCESS; return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        *error=GetExceptionCode(); return false;
    }
}
TaskAccess Access(Runtime& state) noexcept {
    return {state.config.memory,state.config.hostBase,state.config.hostSize,&state,
        Exchange,TaskAdmission,SafeOwner,OwnerThread};
}
void Retire(Runtime& state, Reason fault=Reason::None) noexcept {
    const auto result=RetireTaskBinding(state.task,Access(state),state.config.task,fault);
    if (result!=Reason::None && result!=Reason::TaskNotReady) Bypass(state,result);
}
void InvalidateSource(Runtime& state, Reason reason, std::int64_t now,CaptureReservation* credit=nullptr) noexcept {
    const bool changed=state.sourceReady || state.producer.epochReady;
    InvalidateProducer(state.producer);
    state.sourceReady=false;
    state.taskAdmission=false;
    state.schedule={}; state.nativeTaskState=0;
    // Source authority disappears BEFORE a queued-only healthy retirement. An
    // executing native task may retain an inert forwarding wrapper temporarily.
    Retire(state);
    Bypass(state,reason);
    if (changed && credit) EmitState(state,now,CallerClass::Unknown,reason,credit);
}
bool SameSource(const SourceSnapshot& a, const SourceSnapshot& b) noexcept {
    return EqualSourceIdentity(a.identity,b.identity) && a.maximum==b.maximum &&
        b.realTimeSeconds>=a.realTimeSeconds;
}
bool ObtainSource(Runtime& state, std::int64_t now, SourceSnapshot* output,CaptureReservation* credit) noexcept {
    const auto read=ReadSourceSnapshot(SourceContext(state),output);
    if (read!=Reason::None) { InvalidateSource(state,read,now,credit); return false; }
    if (state.sourceReady && !SameSource(state.source,*output))
        InvalidateSource(state,Reason::SourceLifetime,now,credit);
    if (StatusRevoked(*state.config.status)) return false;
    if (!state.sourceReady) {
        Count(state,state.counters.sourceEpoch);
        if (StatusRevoked(*state.config.status)) return false;
        state.sourceReady=true;
        state.source=*output;
        EmitState(state,now,CallerClass::Unknown,Reason::None,credit);
    } else state.source=*output;
    return !StatusRevoked(*state.config.status);
}
bool Writable(Runtime& state, std::uintptr_t address, std::size_t bytes, bool image) noexcept {
    if (!address || !bytes || bytes>(std::numeric_limits<std::uintptr_t>::max)()-address) return false;
    const auto end=address+bytes;
    for (unsigned i=0; address<end && i<4; ++i) {
        MemoryRegion region{}; DWORD error{};
        if (!state.config.memory.query(state.config.memory.context,address,&region,&error) ||
            region.state!=MEM_COMMIT || region.protect!=PAGE_READWRITE || region.base>address ||
            !region.size || region.size>(std::numeric_limits<std::uintptr_t>::max)()-region.base ||
            region.base+region.size<=address ||
            (image ? (region.type!=MEM_IMAGE || region.allocationBase!=state.config.hostBase) :
                region.type!=MEM_PRIVATE)) return false;
        address=region.base+region.size<end ? region.base+region.size : end;
    }
    return address==end;
}
ProducerSample Sample(const SourceSnapshot& source, std::int64_t now) noexcept {
    return {now,source.outer,source.bots,source.producerTimer,source.requested,source.dirty};
}
// Contains ONLY our admitted pair, never a native call. There is deliberately no
// retry/rollback through an object that might have faulted after the first store.
bool StagePair(std::uintptr_t wrapper, std::uint32_t bots) noexcept {
    __try {
        *reinterpret_cast<volatile std::uint32_t*>(wrapper+0x94)=bots;
        *reinterpret_cast<volatile std::uint8_t*>(wrapper+0xA0)=1;
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}
void EmitProducer(Runtime& state, RecordKindV3 kind, const SourceSnapshot& source,
    const PendingRequest& previous, std::int64_t now, Reason reason,CaptureReservation* credit) noexcept {
    auto record=Record(state,kind,now,reason);
    auto& value=record.payload.request;
    value.requestSequence=state.producer.requestSequence;
    value.witnessSequence=state.producer.witnessSequence;
    value.stagedQpc=previous.stagedQpc;
    value.previousSampleQpc=previous.previousSetQpc;
    value.observedQpc=now;
    value.freshSinceQpc=state.producer.fresh.valid ? state.producer.fresh.lowerBoundQpc : 0;
    value.sourceAgeTicks=state.producer.fresh.valid ? now-state.producer.fresh.lowerBoundQpc : 0;
    value.pi=source.outer.pi; value.bots=source.outer.bots; value.maximum=source.maximum;
    value.stagedBots=previous.bots; value.humanPlayers=source.humans; value.worldBots=source.bots;
    value.classification=static_cast<std::uint32_t>(CallerClass::NormalPump);
    value.pending=state.producer.pending.active;
    Emit(state,record,credit);
}
void UpdateProducer(Runtime& state, SourceSnapshot& source, std::int64_t now,CaptureReservation* credit) noexcept {
    if (state.resumeWaitNativeClear) {
        if (source.requested) return; // Do not overwrite a pre-pause native request.
        state.resumeWaitNativeClear=false;
    }
    const auto previous=state.producer.pending;
    const auto witnessed=state.producer.witnessSequence;
    auto reason=ObserveProducer(state.producer,Sample(source,now));
    Bypass(state,reason);
    if (state.producer.witnessSequence!=witnessed)
        EmitProducer(state,RecordKindV3::Witness,source,previous,now,reason,credit);
    else if (previous.active && !state.producer.pending.active)
        EmitState(state,now,CallerClass::NormalPump,reason,credit);
    reason=CanStageRequest(state.producer,now);
    if (reason!=Reason::None) { if (state.config.mode==Mode::Repair) Bypass(state,reason); return; }

    SourceSnapshot before{};
    const auto reread=ReadSourceSnapshot(SourceContext(state),&before);
    if (reread!=Reason::None || !SameSource(source,before) || before.bots!=source.bots) {
        InvalidateSource(state,reread==Reason::None ? Reason::SourceLifetime : reread,now,credit); return;
    }
    if (!Writable(state,before.identity.wrapper+0x94,0x0D,false)) {
        RevokeRuntime(state,Reason::WriteFault); return;
    }
    std::int64_t staged{};
    if (!RuntimeClock(state,&staged) || CanStageRequest(state.producer,staged)!=Reason::None ||
        !RuntimeCaptureAdmission(state) || !state.sourceReady ||
        ReadTaskPhase(state.task)!=TaskPhase::Armed) return;
    if (!StagePair(before.identity.wrapper,before.bots)) {
        RevokeRuntime(state,Reason::WriteFault); Retire(state,Reason::WriteFault); return;
    }
    // Establish the immutable staging/floor before ANY post-store probe can
    // revoke source authority (including a racing lifecycle or failed clock).
    reason=RecordStagedRequest(state.producer,staged,before.bots,before.maximum,
        Sample(before,staged),false);
    const auto stagedRequest=state.producer.pending;
    SourceSnapshot after{};
    const auto readback=ReadSourceSnapshot(SourceContext(state),&after);
    std::int64_t sampled=staged;
    const bool clock=RuntimeClock(state,&sampled);
    const bool valid=clock && readback==Reason::None && SameSource(before,after) &&
        before.bots==after.bots;
    if (valid) reason=ObserveProducer(state.producer,Sample(after,sampled));
    Bypass(state,reason);
    EmitProducer(state,RecordKindV3::Request,valid ? after : before,stagedRequest,sampled,reason,credit);
    if (!valid) {
        InvalidateSource(state,readback==Reason::None ? Reason::SourceLifetime : readback,sampled,credit);
        return;
    }
    source=after; state.source=after;
}
bool Bind(Runtime& state, std::int64_t now,CaptureReservation* credit) noexcept {
    if (state.bindingSuspended) return false; // Before taskAdmission, not an Inert reset.
    state.taskAdmission=true;
    TaskSnapshot observed{};
    bool rebound=false;
    if (ReadTaskPhase(state.task)==TaskPhase::Armed) {
        TaskSnapshot live{};
        const auto result=ReadBoundTask(state.task,Access(state),state.config.task,&live);
        if (result==Reason::None) observed=live;
        const bool same=result==Reason::None && EqualTaskIdentity(live.identity,state.task.identity);
        if (same && live.builder!=state.task.wrapper) {
            Retire(state,Reason::BuilderChanged); return false;
        }
        if (!same || state.task.epoch.source!=state.counters.sourceEpoch) {
            InvalidateProducer(state.producer);
            Retire(state);
            if (ReadTaskPhase(state.task)==TaskPhase::Armed) return false;
        }
    }
    if (ReadTaskPhase(state.task)==TaskPhase::Inert || StatusRevoked(*state.config.status)) return false;
    if (ReadTaskPhase(state.task)!=TaskPhase::Armed) {
        // A healthy retirement may keep the same native task identity, but it
        // always receives new DLL authority and cannot inherit a fresh tuple.
        TaskSnapshot candidate{};
        const auto read=ReadSelectedTask(Access(state),state.config.task,&candidate);
        if (read!=Reason::None || (candidate.state!=2 && candidate.state!=3)) {
            Bypass(state,read==Reason::None ? Reason::TaskNotReady : read); return false;
        }
        Count(state,state.counters.bindingEpoch);
        if (StatusRevoked(*state.config.status)) return false;
        const auto install=InstallTaskBinding(state.task,Access(state),state.config.task,
            {state.counters.sourceEpoch,state.counters.bindingEpoch},&observed);
        if (install!=Reason::None) { Bypass(state,install); return false; }
        rebound=true; // Diagnostics belong to Install's verified task, not the earlier candidate.
    }
    if (state.task.epoch.source!=state.counters.sourceEpoch ||
        state.task.epoch.binding!=state.counters.bindingEpoch) return false;
    Bypass(state,SetProducerEpoch(state.producer,state.counters.sourceEpoch,state.counters.bindingEpoch));
    const bool scheduleChanged=state.nativeTaskState!=observed.state || !EqualTaskSchedule(state.schedule,observed.schedule);
    state.nativeTaskState=observed.state; state.schedule=observed.schedule;
    if (rebound || scheduleChanged) EmitState(state,now,CallerClass::NormalPump,Reason::None,credit);
    return state.producer.epochReady && RuntimeCaptureAdmission(state);
}
void InitEntered(void* context, std::uint64_t lifecycle, bool owned) noexcept {
    auto& state=*static_cast<Runtime*>(context);
    if (!RuntimeOwner(state)) { RevokeRuntime(state,Reason::ForeignThread); return; }
    Count(state,state.initCalls);
    if (state.initCalls!=1) { RevokeRuntime(state,Reason::UnsupportedReinit); return; }
    if (!owned || lifecycle!=kInitialLifecycle || !KnownLifecycle(*state.config.dispatch)) {
        RevokeRuntime(state,Reason::LifecycleCrossing); return;
    }
    state.initialLifecycle=lifecycle;
}
void InitReturned(void* context, std::uint64_t lifecycle, bool owned, bool result) noexcept {
    auto& state=*static_cast<Runtime*>(context);
    if (!RuntimeOwner(state)) { RevokeRuntime(state,Reason::ForeignThread); return; }
    if (!result) { RevokeRuntime(state,Reason::InitFailed); return; }
    if (StatusRevoked(*state.config.status)) return;
    if (!owned || state.initCalls!=1 || lifecycle!=state.initialLifecycle ||
        lifecycle!=kInitialLifecycle || !KnownLifecycle(*state.config.dispatch)) {
        RevokeRuntime(state,Reason::LifecycleCrossing); return;
    }
    const auto qualified=state.config.qualifyClient();
    state.clientQualificationMs=qualified.elapsedMs;
    if (qualified.reason!=Reason::None || !qualified.referenceAcquired || !qualified.referenceReleased) {
        RevokeRuntime(state,qualified.reason==Reason::None ? Reason::SteamClientMismatch : qualified.reason); return;
    }
    if (Lifecycle(*state.config.dispatch)!=lifecycle || !KnownLifecycle(*state.config.dispatch) ||
        StatusRevoked(*state.config.status)) { RevokeRuntime(state,Reason::LifecycleCrossing); return; }
    state.clientQualified=true;
}
void InitFinished(void* context, std::uint64_t lifecycle, bool normal, bool result) noexcept {
    auto& state=*static_cast<Runtime*>(context);
    if (!RuntimeOwner(state)) { RevokeRuntime(state,Reason::ForeignThread); return; }
    if (!normal || !result) RevokeRuntime(state,Reason::InitFailed);
    if (!StatusRevoked(*state.config.status)) {
        if (!state.clientQualified || state.initCalls!=1 || lifecycle!=(kInitialLifecycle-1) ||
            !KnownLifecycle(*state.config.dispatch)) RevokeRuntime(state,Reason::LifecycleCrossing);
        else { state.sdkReady=true; state.idleLifecycle=lifecycle; }
    }
    std::int64_t now{};
    if (RuntimeClock(state,&now)) {
        CaptureReservation initial{};
        if (ReserveCapture(state,initial,1)) EmitState(state,now,CallerClass::Unknown,Reason::None,&initial);
        ReleaseCapture(state,initial);
        PublishRuntimeStatus(state,now,false);
    }
}
void ShutdownEntered(void* context, std::uint64_t) noexcept {
    auto& state=*static_cast<Runtime*>(context);
    LARGE_INTEGER now{};
    const bool clock=QueryPerformanceCounter(&now) && now.QuadPart>=0;
    StopStatus(*state.config.status,clock ? static_cast<std::uint64_t>(now.QuadPart) : 0);
    if (!clock) RevokeStatus(*state.config.status,Reason::ClockFailed);
    if (!RuntimeOwner(state)) { RevokeRuntime(state,Reason::ForeignThread); return; }
    if (!clock) FailRuntimeTiming(state,Reason::ClockFailed);
    else ValidateRuntimeEntry(state,now.QuadPart);
    state.sdkReady=false; state.sourceReady=false; state.taskAdmission=false;
    InvalidateProducer(state.producer);
    // No native table work at the SDK lifecycle boundary. Resident wrappers
    // remain callable and pass through with all reporting authority revoked.
    PublishRuntimeStatus(state,clock ? now.QuadPart : 0,false);
}
} // namespace


bool ReserveCapture(Runtime& state,CaptureReservation& credit,std::uint64_t amount,bool control) noexcept {
    if (!RuntimeOwner(state)) { RevokeRuntime(state,Reason::ForeignThread); return false; }
    if (StatusRevoked(*state.config.status)) return false;
    if (credit.active || !amount || amount>(control ? 1ULL : 9ULL)) {
        LoseStatus(*state.config.status,Reason::RecordLoss); return false;
    }
    const auto observed=ReadStatusWord(state.config.status->worker.observedSequence);
    const auto generated=state.counters.reportSequence;
    const auto reserved=state.transport.reservedCredits;
    if (observed>generated || reserved>256 || generated-observed>256) {
        LoseStatus(*state.config.status,Reason::RecordLoss); return false;
    }
    const std::uint64_t limit=control ? 256 : 254;
    const auto outstanding=generated-observed;
    if (outstanding>limit || reserved>limit-outstanding || amount>limit-outstanding-reserved) return false;
    state.transport.reservedCredits+=amount;
    credit={amount,true,control};
    return true;
}
bool RecoveryRuntimeSafeOwner(Runtime& state) noexcept { return SafeOwner(&state); }
Reason RecoveryRuntimeSource(Runtime& state,SourceSnapshot* output) noexcept {
    if (!output || !RuntimeCaptureAdmission(state)) return Reason::SourceUnavailable;
    const auto result=ReadSourceSnapshot(SourceContext(state),output);
    if (result!=Reason::None) return result;
    // Normal reporting deliberately tolerates the engine's negative spectator
    // accounting. This experimental lifecycle operation requires EXACT zero.
    const auto game=output->identity.game;
    if (game>UINTPTR_MAX-0x2E0) return Reason::SourceUnavailable;
    std::int32_t first{},second{}; DWORD error{};
    if (!state.config.memory.read(state.config.memory.context,game+0x2E0,&first,sizeof(first),&error) ||
        !state.config.memory.read(state.config.memory.context,game+0x2E0,&second,sizeof(second),&error))
        return Reason::SourceUnavailable;
    if (first!=0 || second!=0) return Reason::SpectatorsPresent;
    return RuntimeCaptureAdmission(state) ? Reason::None : Reason::SourceUnavailable;
}
Reason RecoveryRuntimeTask(Runtime& state,TaskSnapshot* output) noexcept {
    if (!RuntimeCaptureAdmission(state) || !state.sourceReady) return Reason::SourceUnavailable;
    state.taskAdmission=true;
    const auto result=ReadSelectedTask(Access(state),state.config.task,output);
    state.taskAdmission=false;
    return result;
}
Reason RecoveryRuntimeRetire(Runtime& state) noexcept {
    if (!RuntimeCaptureAdmission(state) || !state.sourceReady) return Reason::SourceUnavailable;
    state.taskAdmission=true;
    const auto result=RetireTaskBinding(state.task,Access(state),state.config.task);
    state.taskAdmission=false;
    return result;
}
bool EmitRecoveryRuntimeRecord(Runtime& state,const ReportRecoveryPayload& payload,
    std::int64_t headerQpc,std::uint64_t* acceptedSequence) noexcept {
    if (acceptedSequence) *acceptedSequence=0;
    if (!RuntimeOwner(state) || !acceptedSequence || headerQpc<0) return false;
    auto record=Record(state,RecordKindV3::Recovery,headerQpc);
    record.payload.recovery=payload;
    record.payload.recovery.recordSequence=0; // Ring owns the sequence assignment.
    if (!Emit(state,record,&state.recoveryQuota)) return false;
    *acceptedSequence=state.counters.reportSequence;
    return true;
}
void ReleaseCapture(Runtime& state,CaptureReservation& credit) noexcept {
    if (!credit.active) return;
    if (!RuntimeOwner(state)) { RevokeStatus(*state.config.status,Reason::ForeignThread); return; }
    if (credit.remaining>state.transport.reservedCredits) LoseStatus(*state.config.status,Reason::RecordLoss);
    else state.transport.reservedCredits-=credit.remaining;
    credit={};
}
void PauseRuntimeTransport(Runtime& state,TransportReason reason,std::int64_t now) noexcept {
    if (!RuntimeOwner(state) || StatusRevoked(*state.config.status)) return;
    if (reason>=TransportReason::ReceiptGap) { LatchTransportFault(*state.config.status,reason); return; }
    if (reason==TransportReason::None) return;
    auto& t=state.transport;
    t.reason=static_cast<std::uint64_t>(reason);
    t.actualRepairAdmitted=0;
    if (t.state!=static_cast<std::uint64_t>(TransportState::Running)) return;
    auto record=Record(state,RecordKindV3::Control,now);
    auto& p=record.payload.control;
    p.event=1; p.transportState=static_cast<std::uint64_t>(TransportState::Paused);
    p.transportReason=t.reason;
    p.abandonedPendingRequest=state.producer.pending.active ? state.producer.pending.sequence : 0;
    p.abandonedWitness=state.producer.fresh.valid ? state.producer.fresh.witness : 0;
    p.lastRequestQpc=state.producer.haveRequest ? state.producer.lastRequestQpc : 0;
    p.generatedBefore=state.counters.reportSequence; p.submittedBefore=t.submittedSequence;
    p.observedBefore=ReadStatusWord(state.config.status->worker.observedSequence);
    p.forwardedPumpWithoutCapture=t.forwardedPumpWithoutCapture;
    p.forwardedBuilderWithoutCapture=t.forwardedBuilderWithoutCapture;
    p.timingAccountedThroughQpc=state.counters.timingAccountedThroughQpc;
    t.state=p.transportState;
    Count(state,t.pauseEpoch); Count(state,t.transitionSequence);
    t.transitionQpc=now<0 ? 0 : static_cast<std::uint64_t>(now);
    InvalidateProducer(state.producer); // Never clears native bits or request floor.
    state.resumeWaitNativeClear=true;
    if (StatusRevoked(*state.config.status)) return;
    if (state.counters.reportSequence==UINT64_MAX) { RevokeRuntime(state,Reason::CounterOverflow); return; }
    t.pauseBoundarySequence=state.counters.reportSequence+1;
    p.pauseEpoch=t.pauseEpoch; p.pauseBoundarySequence=t.pauseBoundarySequence;
    CaptureReservation control{};
    if (!ReserveCapture(state,control,1,true)) {
        if (!StatusRevoked(*state.config.status)) LoseStatus(*state.config.status,Reason::RecordLoss);
        return;
    }
    Emit(state,record,&control);
    ReleaseCapture(state,control);
}

Reason InitializeRuntime(Runtime& state, const RuntimeConfig& config, std::int64_t frequency) noexcept {
    state={}; state.config=config;
    if (!config.status || !config.dispatch || !config.hostBase || !config.hostSize ||
        !config.memory.read || !config.memory.query || !config.pumpOriginal ||
        !config.builderOriginal || !config.builderWrapper || !config.qualifyClient ||
        !config.sink.publish || config.ownerThreadId!=GetCurrentThreadId() ||
        ReadStatusWord(config.status->headerReady)!=1 ||
        config.status->header.validity!=CompleteHeaderIdentity ||
        config.status->header.configuredMode!=static_cast<std::uint32_t>(config.mode) ||
        config.status->header.qpcFrequency!=static_cast<std::uint64_t>(frequency))
        return Reason::PreparationFailed;
    auto result=InitializeProducer(state.producer,config.mode,frequency);
    if (result!=Reason::None) return result;
    result=InitializeTaskBinding(state.task,reinterpret_cast<std::uintptr_t>(config.builderOriginal),config.builderWrapper);
    if (result!=Reason::None) return result;
    state.counters.ownerThreadId=config.ownerThreadId;
    state.counters.phase=static_cast<std::uint64_t>(ReportPhaseV3::AwaitingInit);
    state.transport.state=static_cast<std::uint64_t>(TransportState::WaitingLogger);
    state.transport.reason=static_cast<std::uint64_t>(TransportReason::AwaitingLogger);
    return PublishOwnerV3(*config.status,state.counters,state.transport) ? Reason::None : Reason::StatusUnavailable;
}
observer::LifecycleSink RuntimeLifecycleSink(Runtime& state) noexcept {
    return {&state,InitEntered,InitReturned,InitFinished,ShutdownEntered};
}
bool RuntimeOwner(const Runtime& state) noexcept { return GetCurrentThreadId()==state.config.ownerThreadId; }
void RevokeRuntime(Runtime& state, Reason reason) noexcept {
    RevokeStatus(*state.config.status,reason);
    Notice(state,false,reason); // Atomic-only request, never formats in a hook.
    if (!RuntimeOwner(state)) return;
    state.counters.reason=static_cast<std::uint64_t>(reason);
    state.sourceReady=false; state.taskAdmission=false;
    InvalidateProducer(state.producer);
}
bool RuntimeAdmission(Runtime& state) noexcept {
    if (!RuntimeOwner(state) || StatusRevoked(*state.config.status) || !state.sdkReady) return false;
    if (observer::ReadGate(*state.config.dispatch)!=observer::Gate::Armed ||
        !KnownLifecycle(*state.config.dispatch) || Lifecycle(*state.config.dispatch)!=state.idleLifecycle) {
        RevokeRuntime(state,Reason::LifecycleCrossing); return false;
    }
    return true;
}
bool RuntimeCleanupAdmission(Runtime& state) noexcept {
    // A worker/foreign fault may arrive outside any managed owner operation.
    // It revokes immediately, but the next qualified normal owner return can
    // still perform the single owned inverse. No source pointer is consulted.
    return SafeOwner(&state) && StatusRevoked(*state.config.status) &&
        ReadTaskPhase(state.task)!=TaskPhase::Inert && state.task.haveIdentity;
}
bool RuntimeCaptureAdmission(Runtime& state) noexcept {
    const auto& wire=*state.config.status;
    return RuntimeAdmission(state) &&
        state.transport.state==static_cast<std::uint64_t>(TransportState::Running) &&
        state.transport.startupSubmitted==1 && state.transport.qualifiedSinkEpoch!=0 &&
        ReadStatusWord(wire.logIdentityReady)==1 && ReadStatusWord(wire.worker.startupObserved)==1 &&
        ReadStatusWord(wire.workerPauseReason)==0;
}
void CleanupRevokedRuntime(Runtime& state, CallerClass classification) noexcept {
    if (classification!=CallerClass::NormalPump || !RuntimeCleanupAdmission(state)) return;
    const auto reason=FaultReason(state);
    RevokeRuntime(state,reason);
    Retire(state,reason);
}
bool RuntimeClock(Runtime& state, std::int64_t* now) noexcept {
    LARGE_INTEGER value{};
    if (!now || !RuntimeOwner(state)) return false;
    if (!QueryPerformanceCounter(&value) || value.QuadPart<0 ||
        (state.haveClock && value.QuadPart<state.lastClock)) {
        FailRuntimeTiming(state,Reason::ClockFailed); return false;
    }
    *now=value.QuadPart; state.lastClock=value.QuadPart; state.haveClock=true;
    return true;
}
void FailRuntimeTiming(Runtime& state, Reason reason) noexcept {
    // Foreign callers only set existing sticky status. Never touch owner-private
    // timing state from their failure path.
    if (RuntimeOwner(state)) state.timingGap=true;
    RevokeRuntime(state,reason);
}
bool ValidateRuntimeEntry(Runtime& state, std::int64_t entryQpc) noexcept {
    if (!RuntimeOwner(state) || state.timingGap) return false;
    if (entryQpc<0 || (state.haveClock && entryQpc<state.lastClock)) {
        FailRuntimeTiming(state,Reason::ClockFailed); return false;
    }
    state.lastClock=entryQpc; state.haveClock=true;
    return true;
}

void RefreshRuntimeTransport(Runtime& state,const NativeServiceResult& service,std::int64_t now) noexcept {
    if (!RuntimeOwner(state) || !RuntimeAdmission(state)) return;
    auto& t=state.transport;
    const auto waiting=static_cast<std::uint64_t>(TransportState::WaitingLogger);
    const auto running=static_cast<std::uint64_t>(TransportState::Running);
    const auto paused=static_cast<std::uint64_t>(TransportState::Paused);
    auto reason=service.reason;
    if (!service.qualified && reason==TransportReason::None) reason=TransportReason::AwaitingLogger;
    const auto workerReason=ReadStatusWord(state.config.status->workerPauseReason);
    if (workerReason>static_cast<std::uint64_t>(TransportReason::SameFileRequalification)) {
        RevokeRuntime(state,Reason::StatusUnavailable); return;
    }
    if (reason==TransportReason::None && workerReason) reason=static_cast<TransportReason>(workerReason);
    if (reason==TransportReason::None &&
        (!t.startupSubmitted || !ReadStatusWord(state.config.status->worker.startupObserved) ||
         ReadStatusWord(state.config.status->logIdentityReady)!=1 || !t.qualifiedSinkEpoch))
        reason=TransportReason::AwaitingLogger;
    if (reason!=TransportReason::None) { PauseRuntimeTransport(state,reason,now); return; }
    if (t.state==running) { t.reason=0; return; }
    if (t.state==waiting) {
        t.state=running; t.reason=0; Count(state,t.transitionSequence);
        t.transitionQpc=static_cast<std::uint64_t>(now);
        return; // Source/binding readiness is established separately by ManagePump.
    }
    if (t.state!=paused) return;
    if (state.bindingSuspended) return; // No logging-driven rebind during recovery.
    const auto observed=ReadStatusWord(state.config.status->worker.observedSequence);
    if (observed<state.counters.reportSequence || observed<t.pauseBoundarySequence || t.reservedCredits)
        return; // Includes any accepted finish emitted after the pause control.

    SourceSnapshot current{};
    const auto sourceReason=ReadSourceSnapshot(SourceContext(state),&current);
    if (sourceReason!=Reason::None) { InvalidateSource(state,sourceReason,now); return; }
    if (state.sourceReady && !SameSource(state.source,current)) {
        InvalidateSource(state,Reason::SourceLifetime,now);
        return; // Genuine lifecycle handling, not a logging-driven reinstall.
    }
    if (!state.sourceReady && ReadTaskPhase(state.task)==TaskPhase::Armed) {
        Retire(state);
        if (ReadTaskPhase(state.task)==TaskPhase::Armed || StatusRevoked(*state.config.status)) return;
    }
    if (ReadTaskPhase(state.task)==TaskPhase::Armed) {
        state.taskAdmission=true; // Read/ownership check, not a repair write.
        TaskSnapshot bound{};
        const auto boundReason=ReadBoundTask(state.task,Access(state),state.config.task,&bound);
        state.taskAdmission=false;
        if (boundReason!=Reason::None) { Bypass(state,boundReason); return; }
        if (bound.builder!=state.task.wrapper) { RevokeRuntime(state,Reason::BuilderChanged); return; }
        if (state.task.epoch.source!=state.counters.sourceEpoch ||
            state.task.epoch.binding!=state.counters.bindingEpoch) {
            RevokeRuntime(state,Reason::LifecycleCrossing); return;
        }
    }
    if (ReadTaskPhase(state.task)==TaskPhase::Inert || StatusRevoked(*state.config.status)) return;
    if (state.sourceReady) state.source=current;
    // Recheck the worker gate after potentially slow source/binding reads.
    if (ReadStatusWord(state.config.status->workerPauseReason) || !RuntimeAdmission(state)) return;
    CaptureReservation control{};
    if (!ReserveCapture(state,control,1,true)) {
        if (!StatusRevoked(*state.config.status)) LoseStatus(*state.config.status,Reason::RecordLoss);
        return;
    }
    auto record=Record(state,RecordKindV3::Control,now);
    auto& p=record.payload.control;
    p.event=2; p.transportState=running; p.pauseEpoch=t.pauseEpoch;
    p.pauseBoundarySequence=t.pauseBoundarySequence;
    p.lastRequestQpc=state.producer.haveRequest ? state.producer.lastRequestQpc : 0;
    p.generatedBefore=state.counters.reportSequence; p.submittedBefore=t.submittedSequence;
    p.observedBefore=observed; p.forwardedPumpWithoutCapture=t.forwardedPumpWithoutCapture;
    p.forwardedBuilderWithoutCapture=t.forwardedBuilderWithoutCapture;
    p.timingAccountedThroughQpc=state.counters.timingAccountedThroughQpc;
    const bool emitted=Emit(state,record,&control);
    ReleaseCapture(state,control);
    if (!emitted || StatusRevoked(*state.config.status)) return;
    t.state=running; t.reason=0; Count(state,t.transitionSequence);
    t.transitionQpc=static_cast<std::uint64_t>(now);
    // InvalidateProducer already removed old witnesses; UpdateProducer requires
    // the old native request to clear, then a new staged/witnessed request.
}

void ManagePump(Runtime& state, CallerClass classification, std::int64_t now,CaptureReservation& reservation) noexcept {
    if (!RuntimeOwner(state)) { RevokeRuntime(state,Reason::ForeignThread); return; }
    if (!RuntimeCaptureAdmission(state)) return;
    if (classification!=CallerClass::NormalPump) {
        RevokeRuntime(state,classification==CallerClass::Truncated ? Reason::TruncatedStack : Reason::UnknownAncestry);
        return;
    }
    if (state.bindingSuspended) return;
    if (!ReserveCapture(state,reservation,9)) { PauseRuntimeTransport(state,TransportReason::CreditPressure,now); return; }
    auto* credit=&reservation;
    Count(state,state.counters.normalPumpClassifications);
    Count(state,state.counters.managementCalls);
    state.counters.lastManagementQpc=now;
    state.lastManagement=now; state.haveManagement=true;
    SourceSnapshot source{};
    if (ObtainSource(state,now,&source,credit) && Bind(state,now,credit)) {
        if (!state.readyNotified && RuntimeAdmission(state)) {
            state.readyNotified=true; state.counters.readyQpc=now;
            Notice(state,true,Reason::None);
        }
        UpdateProducer(state,source,now,credit);
    }
    state.taskAdmission=false;
    if (StatusRevoked(*state.config.status)) Retire(state,FaultReason(state));
}
void PrepareBuilder(Runtime& state, CallerClass classification, void* holder,
    std::int64_t now, std::uint64_t classificationTicks, BuilderDecision* decision) noexcept {
    if (!decision) return;
    *decision={}; decision->startedQpc=now;
    if (!RuntimeOwner(state)) { RevokeRuntime(state,Reason::ForeignThread); return; }
    if (!RuntimeCaptureAdmission(state)) return;
    if (classification==CallerClass::KnownSpin) { Bypass(state,Reason::KnownSpin); return; }
    if (classification==CallerClass::ShutdownDrain) {
        StopStatus(*state.config.status,now); InvalidateProducer(state.producer);
        state.sourceReady=false; state.taskAdmission=false; return;
    }
    if (classification!=CallerClass::NormalBuilder) {
        RevokeRuntime(state,classification==CallerClass::Truncated ? Reason::TruncatedStack : Reason::UnknownAncestry); return;
    }
    if (!ReserveCapture(state,decision->credit,9)) { PauseRuntimeTransport(state,TransportReason::CreditPressure,now); return; }
    auto* credit=&decision->credit;
    decision->attempted=true;
    Count(state,state.counters.normalAttempts);
    Count(state,state.counters.normalBuilderClassifications);
    Count(state,state.counters.buildSequence);
    state.counters.lastBuilderQpc=now;
    auto& event=decision->event;
    event=Record(state,RecordKindV3::BuilderEnter,now);
    auto& value=event.payload.builder;
    value.buildSequence=state.counters.buildSequence;
    value.entryQpc=now;
    value.classification=static_cast<std::uint32_t>(classification);
    value.classificationElapsedTicks=classificationTicks;
    Reason reason=Reason::None;
    SourceSnapshot source{};
    if (!ObtainSource(state,now,&source,credit)) reason=static_cast<Reason>(state.counters.reason);
    if (reason==Reason::None) {
        state.taskAdmission=true;
        TaskSnapshot task{};
        reason=ValidateBuilderTask(state.task,Access(state),state.config.task,
            {state.counters.sourceEpoch,state.counters.bindingEpoch},holder,&task);
        state.taskAdmission=false;
    }
    FreshTuple fresh{};
    if (reason==Reason::None && state.config.mode==Mode::Repair)
        reason=ReadFreshTuple(state.producer,now,source.outer,source.bots,&fresh);
    if (reason==Reason::None) {
        PreparedSnapshot prepared{};
        PreparedDiagnostic diagnostic{};
        reason=ReadPreparedState({state.config.memory,state.config.hostBase,state.config.hostSize,&state.config.prepared},
            source.outer,state.scratch,sizeof(state.scratch),&prepared,&diagnostic);
        if (diagnostic.valid) {
            value.preparedValid=1; value.preparedMismatchMask=diagnostic.mismatchMask;
            value.preparedMaximum=diagnostic.maximum; value.preparedMembers=diagnostic.membersCount;
            value.preparedPi=diagnostic.json.pi; value.preparedBots=diagnostic.json.bots;
            value.preparedJsonMaximum=diagnostic.json.maximum; value.preparedJsonBytes=diagnostic.jsonBytes;
        }
        // Optional read-only evidence. Unavailable/unstable dirty bits do not
        // change builder admission or become an invented zero observation.
        const auto savedError=GetLastError();
        const auto rva=state.config.prepared.fullDirty;
        std::uint8_t first{},second{}; DWORD error{};
        if (rva<state.config.hostSize && Writable(state,state.config.hostBase+rva,1,true) &&
            state.config.memory.read(state.config.memory.context,state.config.hostBase+rva,&first,1,&error) &&
            state.config.memory.read(state.config.memory.context,state.config.hostBase+rva,&second,1,&error) &&
            first<=1 && first==second) {
            value.preparedDirtyValid=1; value.preparedDirtyAtEntry=first;
        }
        SetLastError(savedError);
    }
    std::int64_t finalQpc=now;
    if (reason==Reason::None) {
        SourceSnapshot finalSource{};
        reason=ReadSourceSnapshot(SourceContext(state),&finalSource);
        if (reason==Reason::None && (!SameSource(source,finalSource) ||
            source.bots!=finalSource.bots || !EqualCounts(source.outer,finalSource.outer))) reason=Reason::SourceLifetime;
        if (reason==Reason::None && !RuntimeClock(state,&finalQpc)) reason=Reason::ClockFailed;
        if (reason==Reason::None && state.config.mode==Mode::Repair)
            reason=ReadFreshTuple(state.producer,finalQpc,finalSource.outer,finalSource.bots,&fresh);
        if (reason!=Reason::None && reason!=Reason::FreshnessExpired && reason!=Reason::PreparedMismatch)
            InvalidateSource(state,reason,finalQpc,credit);
    }
    value.pi=source.outer.pi; value.bots=source.outer.bots; value.maximum=source.outer.maximum;
    // A newer request can be pending while the prior witnessed tuple is still
    // valid. Selection belongs to THAT witness's request, not the newest staged
    // request. Latest global sequences remain in State/Anchor/DATA counters.
    value.requestSequence=fresh.valid ? fresh.request : state.producer.requestSequence;
    value.witnessSequence=fresh.valid ? fresh.witness : state.producer.witnessSequence;
    value.pending=state.producer.pending.active; value.fresh=state.producer.fresh.valid;
    if (fresh.valid) value.sourceAgeTicks=finalQpc-fresh.lowerBoundQpc;
    if (reason==Reason::None && state.config.mode==Mode::Repair) {
        const auto rva=state.config.prepared.fullDirty;
        if (rva>=state.config.hostSize || !Writable(state,state.config.hostBase+rva,1,true)) reason=Reason::WriteFault;
        else decision->dirtyAddress=state.config.hostBase+rva;
    }
    if (reason==Reason::None && !RuntimeCaptureAdmission(state)) reason=Reason::LifecycleCrossing;
    Bypass(state,reason);
    event.header.reason=static_cast<std::uint32_t>(reason);
    if (!RuntimeClock(state,&decision->probeFinishedQpc)) decision->probeFinishedQpc=finalQpc;
    value.probeElapsedTicks=decision->probeFinishedQpc>=now ? decision->probeFinishedQpc-now : 0;
    // Enter records precede the final store admission. A failed publication
    // immediately prevents selection; Return states what actually happened.
    decision->eligible=reason==Reason::None && state.config.mode==Mode::Repair;
    value.selected=0;
    Emit(state,event,credit);
    decision->eligible=decision->eligible && RuntimeCaptureAdmission(state);
}
void FinishBuilder(Runtime& state, BuilderDecision& decision, bool returned,
    bool result, bool selected, std::int64_t returnQpc, std::uint64_t nativeTicks) noexcept {
    if (!RuntimeOwner(state)) return;
    if (!decision.attempted) return;
    auto* credit=&decision.credit;
    auto event=decision.event;
    event.header.sequence=0;
    event.header.kind=static_cast<std::uint32_t>(returned ? RecordKindV3::BuilderReturn : RecordKindV3::BuilderUnwind);
    event.header.qpc=returnQpc<0 ? 0 : static_cast<std::uint64_t>(returnQpc);
    auto& value=event.payload.builder;
    value.returnQpc=event.header.qpc; value.originalElapsedTicks=nativeTicks;
    value.selected=selected; value.result=result;
    if (selected) {
        Count(state,state.counters.fullSelected);
        if (value.witnessSequence!=state.counters.lastSelectedWitness) {
            state.counters.lastSelectedWitness=value.witnessSequence;
            Count(state,state.counters.distinctSelectedWitnesses);
        }
    }
    if (returned) {
        Count(state,state.counters.normalReturns);
        if (!result) Count(state,state.counters.falseReturns);
        if (selected && result) Count(state,state.counters.selectedTrue);
    } else {
        Count(state,state.counters.nativeUnwinds);
        event.header.reason=static_cast<std::uint32_t>(Reason::NativeUnwind);
    }
    Emit(state,event,credit);
    if (!returned) RevokeRuntime(state,Reason::NativeUnwind);
}
void PublishRuntimeStatus(Runtime& state, std::int64_t now, bool allowAnchor,CaptureReservation* credit) noexcept {
    if (!RuntimeOwner(state)) return;
    // Covers nested children and terminal owner lifecycle publications as well
    // as ordinary callbacks. A latched gap permanently suppresses this drain.
    ConsumeRuntimeDuration(state);
    auto& value=state.counters;
    value.lastOwnerQpc=now<0 ? 0 : static_cast<std::uint64_t>(now);
    value.pending=state.producer.pending.active; value.fresh=state.producer.fresh.valid;
    value.pendingSinceQpc=value.pending ? state.producer.pending.stagedQpc : 0;
    value.freshSinceQpc=value.fresh ? state.producer.fresh.lowerBoundQpc : 0;
    value.requestSequence=state.producer.requestSequence; value.witnessSequence=state.producer.witnessSequence;
    value.builderBound=ReadTaskPhase(state.task)==TaskPhase::Armed;
    value.pi=state.sourceReady ? state.source.outer.pi : 0;
    value.bots=state.sourceReady ? state.source.outer.bots : 0;
    value.maximum=state.sourceReady ? state.source.outer.maximum : 0;
    const auto& wire=*state.config.status;
    if (ReadStatusWord(wire.stopping)) value.phase=static_cast<std::uint64_t>(ReportPhaseV3::Stopping);
    else if (StatusRevoked(wire)) value.phase=static_cast<std::uint64_t>(ReportPhaseV3::Faulted);
    else if (!state.sdkReady) value.phase=static_cast<std::uint64_t>(ReportPhaseV3::AwaitingInit);
    else if (!state.sourceReady || !value.builderBound) value.phase=static_cast<std::uint64_t>(ReportPhaseV3::Prepared);
    else value.phase=static_cast<std::uint64_t>(state.config.mode==Mode::Repair ? ReportPhaseV3::Repairing : ReportPhaseV3::Observing);
    const auto cadence=state.producer.frequency*(state.config.diagnostics==Diagnostics::Operational ? 60 :
        state.config.diagnostics==Diagnostics::Detailed ? 1 : 10);
    if (allowAnchor && !state.bindingSuspended && state.readyNotified && RuntimeCaptureAdmission(state) && now>=0 &&
        (!state.haveAnchor || now-state.lastAnchor>=cadence)) {
        CaptureReservation own{};
        auto* reserved=credit && credit->active && credit->remaining>=2 ? credit : &own;
        if (reserved==&own && !ReserveCapture(state,own,2)) {
            PauseRuntimeTransport(state,TransportReason::CreditPressure,now);
        } else {
            auto record=Record(state,RecordKindV3::Anchor,now);
            auto summary=Record(state,RecordKindV3::TransportSummary,now);
            auto& anchor=record.payload.anchor;
            anchor.normalAttempts=value.normalAttempts; anchor.fullSelected=value.fullSelected;
            anchor.selectedTrue=value.selectedTrue; anchor.normalReturns=value.normalReturns;
            anchor.falseReturns=value.falseReturns; anchor.nativeUnwinds=value.nativeUnwinds;
            anchor.requestSequence=value.requestSequence; anchor.witnessSequence=value.witnessSequence;
            anchor.buildSequence=value.buildSequence; anchor.distinctSelectedWitnesses=value.distinctSelectedWitnesses;
            for (std::size_t i=0; i<kDurationClassCount; ++i) {
                const auto& duration=value.durations[i];
                anchor.durations[i]={duration.calls,duration.elapsedTicks,duration.maximumTicks,duration.overFiveMilliseconds};
            }
            const auto& t=state.transport;
            auto& p=summary.payload.transport;
            p.nativeSubmitCalls=t.nativeSubmitCalls; p.nativeSubmitElapsedTicks=t.nativeSubmitElapsedTicks;
            p.nativeSubmitMaximumTicks=t.nativeSubmitMaximumTicks;
            p.nativeSubmitOverFiveMilliseconds=t.nativeSubmitOverFiveMilliseconds;
            p.forwardedPumpWithoutCapture=t.forwardedPumpWithoutCapture;
            p.forwardedBuilderWithoutCapture=t.forwardedBuilderWithoutCapture;
            p.transportState=t.state; p.transportReason=t.reason; p.pauseEpoch=t.pauseEpoch;
            p.pauseBoundarySequence=t.pauseBoundarySequence; p.submittedSequence=t.submittedSequence;
            p.observedSequence=ReadStatusWord(wire.worker.observedSequence);
            p.timingAccountedThroughQpc=value.timingAccountedThroughQpc;
            p.generatedSequence=value.reportSequence; // Pre-submission snapshot, before either record.
            if (Emit(state,record,reserved)) {
                p.anchorSequence=value.reportSequence;
                Emit(state,summary,reserved);
            }
            state.lastAnchor=now; state.haveAnchor=true; // No catch-up bursts.
        }
        ReleaseCapture(state,own);
    }
    // Anchor-credit refusal can have entered a pause since the earlier copy.
    value.pending=state.producer.pending.active; value.fresh=state.producer.fresh.valid;
    value.pendingSinceQpc=value.pending ? state.producer.pending.stagedQpc : 0;
    value.freshSinceQpc=value.fresh ? state.producer.fresh.lowerBoundQpc : 0;
    state.transport.generatedSequence=value.reportSequence;
    if (ReadStatusWord(wire.stopping)) state.transport.state=static_cast<std::uint64_t>(TransportState::Stopping);
    else if (StatusRevoked(wire)) {
        state.transport.state=static_cast<std::uint64_t>(TransportState::Faulted);
        const auto fatal=ReadStatusWord(wire.fatalTransportReason);
        if (fatal) state.transport.reason=fatal;
    }
    if (!ReadStatusWord(wire.stopping) && !StatusRevoked(wire)) {
        if (state.transport.state==static_cast<std::uint64_t>(TransportState::WaitingLogger))
            value.phase=static_cast<std::uint64_t>(ReportPhaseV3::WaitingLogger);
        else if (state.transport.state==static_cast<std::uint64_t>(TransportState::Paused))
            value.phase=static_cast<std::uint64_t>(ReportPhaseV3::Paused);
    }
    state.transport.actualRepairAdmitted=state.config.mode==Mode::Repair && state.sourceReady &&
        value.builderBound && RuntimeCaptureAdmission(state) ? 1 : 0;
    if (!PublishOwnerV3(*state.config.status,value,state.transport)) RevokeRuntime(state,Reason::StatusUnavailable);
}
static bool AccountRuntimeDuration(Runtime& state, DurationClass kind, std::uint64_t ticks,
    std::int64_t entryQpc, bool topLevel) noexcept {
    if (!RuntimeOwner(state) || state.timingGap) return false;
    const auto index=static_cast<std::size_t>(kind);
    if (entryQpc<0 || !state.haveClock || entryQpc>state.lastClock ||
        (topLevel && static_cast<std::uint64_t>(entryQpc)<state.counters.timingAccountedThroughQpc)) {
        FailRuntimeTiming(state,Reason::ClockFailed); return false;
    }
    if (index>=kDurationClassCount) { FailRuntimeTiming(state,Reason::CounterOverflow); return false; }
    auto next=state.counters.durations[index];
    if (!AccountDuration(next,ticks,state.producer.frequency)) {
        FailRuntimeTiming(state,Reason::CounterOverflow); return false;
    }
    // All validation precedes this owner-only transaction. No fallible call or
    // callback may separate the duration commit from its completed-root marker.
    state.counters.durations[index]=next;
    if (topLevel) state.counters.timingAccountedThroughQpc=static_cast<std::uint64_t>(entryQpc);
    return true;
}
bool ConsumeRuntimeDuration(Runtime& state) noexcept {
    if (!RuntimeOwner(state) || state.timingGap) return false;
    if (!state.pendingDuration.valid) return true;
    const auto& pending=state.pendingDuration;
    if (state.producer.frequency<=0 ||
        static_cast<std::uint64_t>(state.producer.frequency)!=state.config.status->header.qpcFrequency) {
        FailRuntimeTiming(state,Reason::CounterOverflow); return false;
    }
    if (!AccountRuntimeDuration(state,pending.kind,pending.ticks,pending.entryQpc,pending.topLevel)) return false;
    // The counter/watermark transaction has succeeded. No fallible call is
    // allowed before clearing its one pending record; failures above retain it.
    state.pendingDuration.valid=false;
    return true;
}
bool StageRuntimeDuration(Runtime& state, DurationClass kind, std::uint64_t ticks,
    std::int64_t entryQpc, bool topLevel) noexcept {
    if (!RuntimeOwner(state) || state.timingGap) return false;
    if (state.pendingDuration.valid) {
        FailRuntimeTiming(state,Reason::Reentry); return false;
    }
    if (entryQpc<0 || !state.haveClock || entryQpc>state.lastClock ||
        (topLevel && static_cast<std::uint64_t>(entryQpc)<state.counters.timingAccountedThroughQpc)) {
        FailRuntimeTiming(state,Reason::ClockFailed); return false;
    }
    const auto index=static_cast<std::size_t>(kind);
    constexpr auto maximum=(std::numeric_limits<std::uint64_t>::max)();
    if (index>=kDurationClassCount || state.producer.frequency<=0 ||
        state.producer.frequency>(std::numeric_limits<std::int64_t>::max)()/45 ||
        static_cast<std::uint64_t>(state.producer.frequency)!=state.config.status->header.qpcFrequency ||
        state.counters.durations[index].calls==maximum ||
        ticks>maximum-state.counters.durations[index].elapsedTicks) {
        FailRuntimeTiming(state,Reason::CounterOverflow); return false;
    }
    // Cheap reservation outside the end clock. Counter invariants (each bucket
    // and overrun <= calls) make these two checked increments sufficient; full
    // histogram/copy work executes only in the next measured owner interval.
    state.pendingDuration={kind,ticks,entryQpc,topLevel,true};
    return true;
}
} // namespace rs2fix::reporting
