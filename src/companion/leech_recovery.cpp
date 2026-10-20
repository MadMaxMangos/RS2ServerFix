#include "companion/leech_recovery.h"
#include "companion/steam_reporting_runtime.h"
#include <cstring>
#include <limits>

namespace rs2fix::reporting {
namespace {
PVOID volatile g_recovery{};
#if defined(RS2_REPORTING_TESTING)
struct CaptureFixture {std::uint32_t frames[kCaptureFrames];std::size_t count;bool enabled,truncated,success;};
CaptureFixture g_captureFixture{};
#endif
constexpr std::uint64_t kFinishSeconds=60, kAttemptSeconds=120;
bool PureClock(std::uint64_t* output) noexcept {
    const DWORD error=GetLastError(); LARGE_INTEGER qpc{};
    const bool ok=output && QueryPerformanceCounter(&qpc) && qpc.QuadPart>0;
    if (output) *output=ok ? static_cast<std::uint64_t>(qpc.QuadPart) : 0;
    SetLastError(error); return ok;
}
LeechRecovery* Current() noexcept {
    return static_cast<LeechRecovery*>(InterlockedCompareExchangePointer(&g_recovery,nullptr,nullptr));
}
RecoveryPhase Phase(const LeechRecovery& r) noexcept {return static_cast<RecoveryPhase>(r.value.phase);}
std::uint64_t Fingerprint(const void* bytes,std::size_t count) noexcept {
    if (!count) return 0;
    auto* data=static_cast<const unsigned char*>(bytes); std::uint64_t result=14695981039346656037ULL;
    for(std::size_t i=0;i<count;++i) {result^=data[i];result*=1099511628211ULL;}
    return result; // Diagnostic identity only; mutations compare complete tokens.
}
bool SameBytes(const RecoveryNativeString& a,const unsigned char* aa,
    const RecoveryNativeString& b,const unsigned char* bb) noexcept {
    return a.object==b.object && a.data==b.data && a.size==b.size && a.capacity==b.capacity &&
        !std::memcmp(a.header,b.header,sizeof(a.header)) && !std::memcmp(aa,bb,static_cast<std::size_t>(a.size));
}
void Fault(LeechRecovery& r,RecoveryReason reason,RecoveryOutcome outcome,bool restart) noexcept {
    if (r.terminal) {
        if(restart) r.value.flags|=RecoveryRestartRequired;
        if(reason==RecoveryReason::NativeException ||
            (reason==RecoveryReason::InverseUnavailable && !(r.value.flags&RecoveryExceptionObserved))) {
            r.value.reason=static_cast<std::uint64_t>(reason);r.value.outcome=static_cast<std::uint64_t>(outcome);
        }
        return;
    }
    r.terminal=true; r.finalPending=true;
    r.value.reason=static_cast<std::uint64_t>(reason);r.value.outcome=static_cast<std::uint64_t>(outcome);
    if(restart) r.value.flags|=RecoveryRestartRequired;
    // No exported publication, ring/quota operation, native inverse or logger
    // here: callbacks and SEARCH filters only retain these bounded scalars.
}
bool Queue(LeechRecovery& r,RecoveryEvent event) noexcept {
    if(r.pendingCount==9) {Fault(r,RecoveryReason::QuotaUnavailable,RecoveryOutcome::MechanicsFailed,true);return false;}
    auto copy=r.value;copy.event=static_cast<std::uint64_t>(event);copy.recordSequence=0;
    r.pendingRecords[r.pendingCount++]=copy;return true;
}
bool Transition(LeechRecovery& r,RecoveryPhase phase,std::uint64_t qpc) noexcept {
    if(Phase(r)==phase) return true;
    if(r.value.transitionSequence==UINT64_MAX) {Fault(r,RecoveryReason::QuotaUnavailable,RecoveryOutcome::MechanicsFailed,true);return false;}
    r.value.phase=static_cast<std::uint64_t>(phase);++r.value.transitionSequence;r.value.qpc=qpc;
    return Queue(r,RecoveryEvent::Transition);
}
void TimingCopy(LeechRecovery& r) noexcept {
    if(r.callbackTiming.phase==PrimaryCallbackTimingPhase::CompleteValid) {
        r.value.callbackOwnTicks=r.callbackTiming.ticks;r.value.flags|=RecoveryCallbackOwnTimingValid;
    } else {r.value.callbackOwnTicks=0;r.value.flags&=~RecoveryCallbackOwnTimingValid;}
}
bool Publish(LeechRecovery& r) noexcept {
    TimingCopy(r);auto copy=r.value;copy.event=static_cast<std::uint64_t>(RecoveryEvent::None);
    const bool published=r.status && PublishRecoveryStatus(*r.status,copy);
    if(!published && r.prepared) Fault(r,RecoveryReason::RecordingUnavailable,RecoveryOutcome::RecordingUnavailable,r.cancelEntered);
    return published;
}
bool Flush(Runtime& state,LeechRecovery& r) noexcept {
    while(r.pendingRead<r.pendingCount) {
        if(!state.recoveryQuota.active || !state.recoveryQuota.remaining) return false;
        if(state.transport.state==static_cast<std::uint64_t>(TransportState::Paused)) {
            const auto& record=r.pendingRecords[r.pendingRead];
            const bool allowed=record.phase==static_cast<std::uint64_t>(RecoveryPhase::Failed) &&
                (record.flags&RecoveryRestartRequired) &&
                (record.event==static_cast<std::uint64_t>(RecoveryEvent::Transition) || record.event==static_cast<std::uint64_t>(RecoveryEvent::Final));
            if(!allowed) {++r.pendingRead;continue;} // No ordinary capture authority in a pause.
        }
        std::int64_t now{};
        if(!RuntimeClock(state,&now) || now<0 || static_cast<std::uint64_t>(now)<r.lastEmissionQpc) return false;
        std::uint64_t sequence{};
        if(!EmitRecoveryRuntimeRecord(state,r.pendingRecords[r.pendingRead],now,&sequence)) return false;
        r.lastEmissionQpc=static_cast<std::uint64_t>(now);r.value.recordSequence=sequence;
        if(r.pendingRecords[r.pendingRead].phase==static_cast<std::uint64_t>(RecoveryPhase::Qualifying))
            r.qualifyingRecordSequence=sequence;
        ++r.pendingRead;
    }
    r.pendingRead=0;r.pendingCount=0;return Publish(r);
}
bool LoggerLease(Runtime& state) noexcept {
    const auto& log=state.nativeLog;
    std::uint64_t qualified=NativeTransportQualifiedEpoch(log.transport);
#if defined(RS2_REPORTING_TESTING)
    // Existing own-code native-log fixtures supply just this mailbox scalar.
    // Mutable snapshot equality and every native/source admission remain real.
    if(log.ops.qualified) qualified=log.ops.qualified(log.ops.context);
#endif
    if(!log.haveSnapshot || !log.epoch || state.transport.qualifiedSinkEpoch!=log.epoch ||
        qualified!=log.epoch) return false;
    NativeLogSnapshot current{};
    return ReadNativeLogSnapshot(log.read,&current)==TransportReason::None &&
        !std::memcmp(&current,&log.snapshot,sizeof(current)) && RuntimeCaptureAdmission(state);
}
bool Lifetime(const LeechRecovery& r,const RecoveryNativeSnapshot& n) noexcept {
    // Each allocation was freshly validated. Metadata may reallocate an unchanged
    // IP, and authorization tokens rotate; neither is a core-lifetime change.
    return n.httpManager==r.before.httpManager && n.asyncManager==r.before.asyncManager && n.gmalloc==r.before.gmalloc &&
        n.publicIpCount==r.before.publicIpCount &&
        !std::memcmp(n.publicIpChars,r.before.publicIpChars,static_cast<std::size_t>(n.publicIpCount)*sizeof(n.publicIpChars[0])) &&
        n.finish.descriptor==r.before.finish.descriptor && n.finish.type==r.before.finish.type &&
        n.create.descriptor==r.before.create.descriptor && n.create.type==r.before.create.type &&
        n.heartbeat.descriptor==r.before.heartbeat.descriptor && n.heartbeat.type==r.before.heartbeat.type &&
        SameBytes(n.coreGuid,n.coreGuidBytes,r.before.coreGuid,r.before.coreGuidBytes);
}
bool Lease(Runtime& state,LeechRecovery& r,std::uint32_t standalone,bool oldSession) noexcept {
    if(r.terminal || !RuntimeCaptureAdmission(state) || state.idleLifecycle!=r.value.sdkEpoch ||
        state.counters.sourceEpoch!=r.value.sourceEpoch || !LoggerLease(state)) return false;
    DWORD error{};
    if(ValidateNativeRecoveryProfile(state.config.hostBase,r.startup,state.config.memory,
        *r.native.imports,&error)!=ProfileResult::Ready ||
        RecoveryRuntimeSource(state,&r.scratchSource)!=Reason::None ||
        !EqualSourceIdentity(r.scratchSource.identity,r.source.identity) ||
        r.scratchSource.maximum!=r.source.maximum || r.scratchSource.realTimeSeconds<r.source.realTimeSeconds || r.scratchSource.bots!=0 ||
        ReadNativeRecoverySnapshot(r.native,&r.current,&error)!=RecoveryNativeResult::Ready ||
        RequireNativeRecoveryReady(r.current)!=RecoveryNativeResult::Ready ||
        r.current.standalone!=standalone || !Lifetime(r,r.current)) return false;
    if(oldSession && !SameBytes(r.current.sdkSession,r.current.sdkBytes,r.before.sdkSession,r.before.sdkBytes)) return false;
    std::int64_t now{};
    if(!RuntimeClock(state,&now) || now<0) {RecoveryOwnerClockFault(state);return false;}
    if(static_cast<std::uint64_t>(now)>=r.value.overallDeadlineQpc ||
        (!r.createInstalled && static_cast<std::uint64_t>(now)>=r.value.finishDeadlineQpc)) return false;
    r.value.qpc=static_cast<std::uint64_t>(now);
    return RuntimeCaptureAdmission(state);
}
bool Inverse(Runtime& state,LeechRecovery& r) noexcept {
    // A partially throwing BIND may have changed the holder or reference count.
    // Neither the preceding allocation nor a readable refcount proves its inverse.
    if(r.bindEntered && !r.bindCompleted) return false;
    if(!RecoveryRuntimeSafeOwner(state) || state.idleLifecycle!=r.value.sdkEpoch) return false;
    DWORD error{}; const auto resource=static_cast<ResourcePhase>(r.value.resourcePhase);
    const bool bound=resource==ResourcePhase::BoundLocal || resource==ResourcePhase::EnqueueEntered;
    return ValidateNativeRecoveryProfile(state.config.hostBase,r.startup,state.config.memory,
        *r.native.imports,&error)==ProfileResult::Ready &&
        RequireRecoveryFinishInverse(r.native,r.finishDescriptor,r.finishType,r.finishSlot,bound,
            r.holder,&error)==RecoveryNativeResult::Ready && RecoveryRuntimeSafeOwner(state);
}
void ReleaseOwned(Runtime& state,LeechRecovery& r) {
    const auto phase=static_cast<ResourcePhase>(r.value.resourcePhase);
    if(phase==ResourcePhase::None || phase==ResourcePhase::LocalReleased || r.resourceReleaseAttempted) return;
    if(!Inverse(state,r)) {Fault(r,RecoveryReason::InverseUnavailable,RecoveryOutcome::NativeUnwind,true);return;}
    r.resourceReleaseAttempted=true;r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::LocalRelease);
    if(phase==ResourcePhase::AllocatedUnbound) r.calls.finishRelease(reinterpret_cast<void*>(r.finishDescriptor),r.finishSlot);
    else r.calls.releaseHolder(&r.holder);
    r.value.resourcePhase=static_cast<std::uint64_t>(ResourcePhase::LocalReleased);
}
int ObserveFailure(LeechRecovery& r,DWORD code,bool callback) noexcept {
    std::uint64_t qpc{};bool clock=false;
    if(callback) {clock=PureClock(&qpc);BeginPrimaryCallbackFilter(r.callbackTiming,clock,qpc);}
    r.value.exceptionCode=code;r.value.flags|=RecoveryExceptionObserved;r.exceptionPending=true;
    r.recipeReturned=false;r.value.flags&=~RecoveryRecipeNormalCompleted;
    Fault(r,RecoveryReason::NativeException,RecoveryOutcome::NativeUnwind,true);
    if(callback) {clock=PureClock(&qpc);EndPrimaryCallbackFilter(r.callbackTiming,clock,qpc);}
    return EXCEPTION_CONTINUE_SEARCH; // Never convert the engine exception to refusal.
}
void FinishObservation(LeechRecovery& r,const bool* result,std::uint32_t id,bool errorCall,std::int32_t code) noexcept {
    auto& state=*r.runtime;
    if(!RuntimeOwner(state)) {InterlockedCompareExchange(&r.foreignFault,1,0);return;}
    if(r.terminal || Phase(r)!=RecoveryPhase::FinishSubmitted) return;
    if(r.finishObserved || !id || (r.finishId && id!=r.finishId) || state.idleLifecycle!=r.value.sdkEpoch) {
        Fault(r,RecoveryReason::CallbackInvalid,RecoveryOutcome::MechanicsFailed,true);return;
    }
    r.finishObserved=true;r.value.flags|=RecoveryCallbackObserved;r.value.callbackId=id;r.callbackError=static_cast<std::uint32_t>(code);
    if(!PureClock(&r.callbackQpc) || r.callbackQpc<r.value.qpc) {
        Fault(r,RecoveryReason::ClockFault,RecoveryOutcome::MechanicsFailed,true);return;
    }
    r.value.qpc=r.callbackQpc;
    if(r.callbackQpc>=r.value.finishDeadlineQpc || r.callbackQpc>=r.value.overallDeadlineQpc) {
        Fault(r,RecoveryReason::FinishTimeout,RecoveryOutcome::MechanicsFailed,true);return;
    }
    if(errorCall) {Fault(r,RecoveryReason::FinishRejected,RecoveryOutcome::MechanicsFailed,true);return;}
    unsigned char byte{};DWORD error{};
    if(!result) r.value.callbackResult=static_cast<std::uint64_t>(CallbackResult::Null);
    else if(!state.config.memory.read(state.config.memory.context,reinterpret_cast<std::uintptr_t>(result),&byte,1,&error))
        r.value.callbackResult=static_cast<std::uint64_t>(CallbackResult::Unreadable);
    else r.value.callbackResult=static_cast<std::uint64_t>(byte==1 ? CallbackResult::True : byte==0 ? CallbackResult::False : CallbackResult::Invalid);
    r.finishTrue=r.value.callbackResult==static_cast<std::uint64_t>(CallbackResult::True);
    if(!r.finishTrue) Fault(r,RecoveryReason::FinishRejected,RecoveryOutcome::MechanicsFailed,true);
}
void FinishSuccess(const bool* result,std::uint32_t id) noexcept {
    const DWORD incoming=GetLastError();if(auto* r=Current()) FinishObservation(*r,result,id,false,0);SetLastError(incoming);
}
bool FinishError(std::int32_t code,std::uint32_t id) noexcept {
    const DWORD incoming=GetLastError();if(auto* r=Current()) FinishObservation(*r,nullptr,id,true,code);SetLastError(incoming);return true;
}

// The capture MUST remain directly in this noinline callback. Neither the
// guard nor native forward is permitted to borrow an earlier Steam-pump frame.
__declspec(noinline) void CreateSuccess(const void* result,std::uint32_t id) {
    const DWORD incoming=GetLastError();auto* pointer=Current();
    if(!pointer || !pointer->runtime) {SetLastError(incoming);return;}
    auto& r=*pointer;auto& state=*r.runtime;
    if(!RuntimeOwner(state)) {InterlockedCompareExchange(&r.foreignFault,1,0);SetLastError(incoming);return;}
    if(r.terminal || !r.createInstalled || Phase(r)!=RecoveryPhase::Recreating || id!=r.createId || !id) {SetLastError(incoming);return;}
    if(r.callbackDepth) {InvalidatePrimaryCallbackTiming(r.callbackTiming);Fault(r,RecoveryReason::CallbackInvalid,RecoveryOutcome::MechanicsFailed,true);SetLastError(incoming);return;}
    // Attribute BEFORE claiming measurement. A disposed/reused slot is not an
    // observed primary callback merely because its former request ID matches.
    DWORD headerError{};
    const auto taskRva=r.native.layout->genericPool+r.createSlot*0x78U;
    unsigned char raw[0x78]{};std::uint32_t liveState{},liveId{},liveHolder{};std::uintptr_t liveSuccess{};
    if(r.createSlot>=128 || !ReadImageRange(r.native.hostBase,r.native.hostImageSize,taskRva,raw,sizeof(raw),r.native.memory,&headerError)) {
        Fault(r,RecoveryReason::CallbackInvalid,RecoveryOutcome::MechanicsFailed,true);SetLastError(incoming);return;
    }
    std::memcpy(&liveState,raw,4);std::memcpy(&liveId,raw+4,4);std::memcpy(&liveHolder,raw+0x38,4);std::memcpy(&liveSuccess,raw+0x48,8);
    if(liveState!=4 || liveId!=r.createId || liveHolder!=r.createHolder || liveSuccess!=reinterpret_cast<std::uintptr_t>(&CreateSuccess)) {
        Fault(r,RecoveryReason::CallbackInvalid,RecoveryOutcome::MechanicsFailed,true);SetLastError(incoming);return;
    }
    ++r.callbackDepth;std::uint64_t qpc{};bool clock=PureClock(&qpc);
    const bool claimed=ClaimPrimaryCallbackTiming(r.callbackTiming,clock,qpc);
    r.value.flags|=RecoveryCreateCallbackObserved;r.value.callbackId=id;
    bool nativeReturned=false;DWORD outgoing=incoming;
    __try {
        __try {
            std::uint32_t frames[kCaptureFrames]{};std::size_t count{};bool truncated{};DWORD error{};
            r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::CreateGuard);
            bool captured{};
#if defined(RS2_REPORTING_TESTING)
            if(g_captureFixture.enabled) {
                std::memcpy(frames,g_captureFixture.frames,sizeof(frames));
                count=g_captureFixture.count;truncated=g_captureFixture.truncated;captured=g_captureFixture.success;
            } else
#endif
            captured=CaptureHostCallers(r.createCapture,frames,&count,&truncated);
            RecoveryNativeString string{};
            bool safe=claimed && captured && ClassifyRecoveryCreateFrames(frames,count,truncated)==RecoveryCallbackClass::NormalLeechSuccess &&
                !state.pumpDepth && !state.builderDepth && !state.timingDepth && r.callbackDepth==1 &&
                Lease(state,r,2,false) && r.current.sdkSession.size==0 &&
                ReadCreateResultString(r.native,result,&string,&error)==RecoveryNativeResult::Ready;
            if(safe) {
                const auto& task=r.current.generic[r.createSlot];
                safe=task.state==4 && task.id==r.createId && task.holder==r.createHolder &&
                    task.success==reinterpret_cast<std::uintptr_t>(&CreateSuccess) && task.error==0 && task.interval==0 &&
                    (task.holder>>16)==r.current.create.type && r.current.genericFree>=1 && r.current.issuedId<UINT32_MAX &&
                    RequireHeartbeatFirstFree(r.current,r.before,r.oldHeartbeat.identity.holder)==RecoveryNativeResult::Ready &&
                    RuntimeCaptureAdmission(state);
            }
            if(!safe || r.createForwarded) Fault(r,RecoveryReason::CallbackInvalid,RecoveryOutcome::MechanicsFailed,true);
            else {
                r.createForwarded=true;r.value.flags|=RecoveryCreateForwardEntered;r.value.flags&=~RecoveryRecipeNormalCompleted;
                r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::CreateForward);
                clock=PureClock(&qpc);EnterPrimaryCallbackNative(r.callbackTiming,clock,qpc);
                SetLastError(incoming);r.calls.createSuccess(result,id);
                outgoing=GetLastError();nativeReturned=true;
                clock=PureClock(&qpc);LeavePrimaryCallbackNative(r.callbackTiming,clock,qpc);
                r.createReturned=true;r.value.flags|=RecoveryCreateForwardNormalCompleted|RecoveryRecipeNormalCompleted;
            }
        } __finally {
            const DWORD last=GetLastError();
            if(AbnormalTermination()) {
                clock=PureClock(&qpc);BeginPrimaryCallbackUnwind(r.callbackTiming,clock,qpc);
                r.createReturned=false;
            }
            --r.callbackDepth;
            clock=PureClock(&qpc);FinalizePrimaryCallbackTiming(r.callbackTiming,clock,qpc);
            SetLastError(nativeReturned ? outgoing : last);
        }
    } __except(ObserveFailure(r,GetExceptionCode(),true)) { /* ContinueSearch cannot enter this handler. */ }
    SetLastError(nativeReturned ? outgoing : incoming);
}
bool ChangedOnlyCreate(LeechRecovery& r,bool installed) noexcept {
    const auto& n=r.current;
    if(r.beforeCreateIssued==UINT32_MAX || n.issuedId!=r.beforeCreateIssued+1) return false;
    unsigned found{},slot{};
    for(unsigned i=0;i<kRecoveryGenericSlots;++i) {
        const auto& task=n.generic[i];
        if(task.state==2 && task.id==n.issuedId && !r.beforeCreate[i].state) {++found;slot=i;}
        else if(std::memcmp(&task,&r.beforeCreate[i],sizeof(task))) return false;
    }
    if(found!=1) return false;
    const auto& task=n.generic[slot];
    if(task.component!=n.componentName || task.error || task.interval ||
        (task.holder>>16)!=n.create.type || (task.holder&0xffff)!=r.beforeCreateRequestSlot ||
        task.success!=reinterpret_cast<std::uintptr_t>(installed ? &CreateSuccess : r.calls.createSuccess)) return false;
    if(installed && (slot!=r.createSlot || task.id!=r.createId || task.holder!=r.createHolder)) return false;
    r.createSlot=slot;r.createId=task.id;r.createHolder=task.holder;return true;
}
bool InstallCreateGuard(Runtime& state,LeechRecovery& r) noexcept {
    if(!ChangedOnlyCreate(r,false)) return false;
    const auto rva=r.native.layout->genericPool+r.createSlot*0x78U+0x48U;
    DWORD error{};
    if(!ImageRangeProtection(r.native.hostBase,r.native.hostImageSize,rva,8,PAGE_READWRITE,r.native.memory,&error)) return false;
    r.callbackTiming={}; // Once, BEFORE installation, not reset by any callback.
    r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::GuardInstall);
    std::uintptr_t observed{};bool written=false;
    __try {
        observed=reinterpret_cast<std::uintptr_t>(InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(r.native.hostBase+rva),reinterpret_cast<PVOID>(&CreateSuccess),
            reinterpret_cast<PVOID>(r.calls.createSuccess)));
        written=observed==reinterpret_cast<std::uintptr_t>(r.calls.createSuccess);
    } __except(EXCEPTION_EXECUTE_HANDLER) { written=false; }
    // Never restore a field after an ambiguous write: only the operator can
    // restart the training process, which also owns any outstanding native task.
    if(!written || !Lease(state,r,2,false) || !ChangedOnlyCreate(r,true)) return false;
    r.createInstalled=true;r.value.requestId=r.createId;
    r.value.flags|=RecoveryCreateGuardInstalled|RecoveryAttributionValid;return true;
}
void SubmitFinish(Runtime& state,LeechRecovery& r) {
    r.recipeEntered=true;r.recipeReturned=false;r.value.flags|=RecoveryRecipeEntered;
    __try {
        __try {
            r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::Descriptor);
            // BAF0F0 is a registry lookup, but invokes getters on earlier,
            // unrelated descriptors. Use the independently qualified UNIQUE
            // Finish descriptor instead: no constructor/refcount side effect
            // is skipped and no unqualified earlier getter is called.
            if(!Lease(state,r,3,true)) {
                Fault(r,RecoveryReason::DescriptorUnavailable,RecoveryOutcome::MechanicsFailed,false);__leave;
            }
            r.finishDescriptor=r.current.finish.descriptor;
            r.finishType=r.calls.finishType(reinterpret_cast<void*>(r.finishDescriptor));
            if(r.finishType!=r.current.finish.type || !r.finishType || r.finishType>=256 || !Lease(state,r,3,true) ||
                RequireFinishFirstFree(r.current)!=RecoveryNativeResult::Ready) {
                Fault(r,RecoveryReason::RequestPoolUnavailable,RecoveryOutcome::MechanicsFailed,false);__leave;
            }
            r.calls.initHolder(&r.holder);
            if(r.holder) {Fault(r,RecoveryReason::DescriptorUnavailable,RecoveryOutcome::MechanicsFailed,false);__leave;}
            r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::Allocate);
            r.finishSlot=r.calls.finishAllocate(reinterpret_cast<void*>(r.finishDescriptor));
            if(r.finishSlot>=16) {Fault(r,RecoveryReason::RequestPoolUnavailable,RecoveryOutcome::MechanicsFailed,false);__leave;}
            r.value.resourcePhase=static_cast<std::uint64_t>(ResourcePhase::AllocatedUnbound);
            if(!Lease(state,r,3,true)) {Fault(r,RecoveryReason::SourceChanged,RecoveryOutcome::MechanicsFailed,false);__leave;}
            r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::Bind);
            r.bindEntered=true;
            r.calls.bindHolder(&r.holder,r.finishType,r.finishSlot);
            r.bindCompleted=true;
            r.value.resourcePhase=static_cast<std::uint64_t>(ResourcePhase::BoundLocal);
            if(r.holder!=(static_cast<std::uint32_t>(r.finishType)<<16|r.finishSlot) || !Lease(state,r,3,true)) {
                Fault(r,RecoveryReason::DescriptorUnavailable,RecoveryOutcome::MechanicsFailed,true);__leave;
            }
            auto* request=r.calls.resolveHolder(&r.holder);
            if(reinterpret_cast<std::uintptr_t>(request)!=r.current.finish.slots[r.finishSlot].payload || !Lease(state,r,3,true)) {
                Fault(r,RecoveryReason::DescriptorUnavailable,RecoveryOutcome::MechanicsFailed,true);__leave;
            }
            r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::Copy);
            r.calls.copyString(request,reinterpret_cast<const void*>(r.current.sdkSession.object),0,SIZE_MAX);
            if(!Lease(state,r,3,true)) {Fault(r,RecoveryReason::SourceChanged,RecoveryOutcome::MechanicsFailed,false);__leave;}
            // The whole cancel/enqueue lease has passed before retirement. No
            // logger, exported publisher, worker handoff or yield occurs here.
            state.bindingSuspended=true;r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::Retire);
            if(RecoveryRuntimeRetire(state)!=Reason::None || !Lease(state,r,3,true)) {
                Fault(r,RecoveryReason::RetirementFailed,RecoveryOutcome::MechanicsFailed,ReadTaskPhase(state.task)==TaskPhase::Inert);__leave;
            }
            TaskSnapshot retired{};
            if(RecoveryRuntimeTask(state,&retired)!=Reason::None || !EqualTaskIdentity(retired.identity,r.oldHeartbeat.identity) ||
                !EqualTaskSchedule(retired.schedule,r.oldHeartbeat.schedule) || retired.state!=2 || retired.builder!=state.task.original) {
                Fault(r,RecoveryReason::HeartbeatUnavailable,RecoveryOutcome::MechanicsFailed,false);__leave;
            }
            r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::Cancel);r.cancelEntered=true;
            auto* heartbeat=reinterpret_cast<std::uint32_t*>(state.config.hostBase+r.native.layout->heartbeatId);
            r.calls.cancel(heartbeat);
            if(!Lease(state,r,3,true) || r.current.heartbeatId!=r.current.invalidId ||
                r.current.generic[r.oldHeartbeat.identity.slot].state!=0 ||
                r.current.heartbeat.slots[r.oldHeartbeat.identity.holder&0xffff].references!=-1) {
                Fault(r,RecoveryReason::LifecycleChanged,RecoveryOutcome::MechanicsFailed,true);__leave;
            }
            r.value.flags|=RecoveryCancellationCompleted;
            if(!Transition(r,RecoveryPhase::FinishSubmitted,r.value.qpc)) __leave;
            r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::Enqueue);
            r.value.resourcePhase=static_cast<std::uint64_t>(ResourcePhase::EnqueueEntered);
            const auto id=r.calls.enqueueFinish(reinterpret_cast<const char*>(r.current.componentName),&r.holder,FinishSuccess,FinishError);
            r.enqueueReturned=true;r.value.apiReturnedId=id;
            if((id && r.finishObserved && id!=r.value.callbackId) || (!id && !r.finishObserved)) {
                Fault(r,RecoveryReason::FinishEnqueueFailed,RecoveryOutcome::MechanicsFailed,true);__leave;
            }
            r.finishId=id ? id : static_cast<std::uint32_t>(r.value.callbackId);r.value.requestId=r.finishId;
            if(!r.finishId) {Fault(r,RecoveryReason::CallbackInvalid,RecoveryOutcome::MechanicsFailed,true);__leave;}
            r.value.flags|=RecoveryAttributionValid;r.recipeReturned=true;r.value.flags|=RecoveryRecipeNormalCompleted;
        } __finally {
            const DWORD outgoing=GetLastError();
            ReleaseOwned(state,r);
            if(AbnormalTermination()) ReleaseCapture(state,state.recoveryQuota);
            SetLastError(outgoing);
        }
    } __except(ObserveFailure(r,GetExceptionCode(),false)) { /* Propagate unchanged. */ }
}
void Recreate(Runtime& state,LeechRecovery& r) {
    r.recipeReturned=false;r.value.flags&=~RecoveryRecipeNormalCompleted;
    __try {
        __try {
            if(!Lease(state,r,3,true) || RequireCreateFirstFree(r.current)!=RecoveryNativeResult::Ready ||
                RequireHeartbeatFirstFree(r.current,r.before,r.oldHeartbeat.identity.holder)!=RecoveryNativeResult::Ready ||
                r.current.issuedId>=UINT32_MAX-2) {
                Fault(r,RecoveryReason::RequestPoolUnavailable,RecoveryOutcome::MechanicsFailed,true);__leave;
            }
            // The acknowledged Finish is deliberately serviced on a LATER
            // owner visit. Cleanup/Start/Create/install are uninterrupted.
            r.value.requestId=0;r.value.callbackId=0;r.value.apiReturnedId=0;r.value.flags&=~RecoveryAttributionValid;
            if(!Transition(r,RecoveryPhase::Recreating,r.value.qpc)) __leave;
            r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::Cleanup);r.calls.cleanup();
            if(!Lease(state,r,0,false) || r.current.sdkSession.size || RequireCreateFirstFree(r.current)!=RecoveryNativeResult::Ready) {
                Fault(r,RecoveryReason::LifecycleChanged,RecoveryOutcome::MechanicsFailed,true);__leave;
            }
            r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::Start);r.calls.start();
            if(!Lease(state,r,1,false) || r.current.sdkSession.size || RequireCreateFirstFree(r.current)!=RecoveryNativeResult::Ready) {
                Fault(r,RecoveryReason::CreateFailed,RecoveryOutcome::ClearedCacheNoSession,true);__leave;
            }
            r.beforeCreateIssued=r.current.issuedId;r.beforeCreateRequestSlot=r.current.create.firstFree;
            std::memcpy(r.beforeCreate,r.current.generic,sizeof(r.beforeCreate));
            r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::Create);r.calls.create();
            if(!Lease(state,r,2,false) || r.current.sdkSession.size || !InstallCreateGuard(state,r)) {
                Fault(r,RecoveryReason::CreateFailed,RecoveryOutcome::ClearedCacheNoSession,true);__leave;
            }
            r.recipeReturned=true;r.value.flags|=RecoveryRecipeNormalCompleted;
        } __finally {
            const DWORD outgoing=GetLastError();
            if(AbnormalTermination()) ReleaseCapture(state,state.recoveryQuota);
            SetLastError(outgoing);
        }
    } __except(ObserveFailure(r,GetExceptionCode(),false)) { /* Never adopt/restore a task. */ }
}
bool CacheMatches(const RecoveryNativeSnapshot& n) noexcept {
    // Both native values are narrow strings; their NUL/range/shape checks are
    // already part of the fresh snapshot. Publication needs the nonempty value,
    // not an encoding conversion or identical allocation.
    return n.sdkSession.size && n.sdkSession.size==n.cacheSession.size &&
        !std::memcmp(n.sdkBytes,n.cacheBytes,static_cast<std::size_t>(n.sdkSession.size));
}
RecoveryReason NativeSnapshotGuardReason(RecoveryNativeResult result) noexcept {
    switch(result) {
    case RecoveryNativeResult::Ready: return RecoveryReason::SnapshotGuardPassed;
    case RecoveryNativeResult::InvalidContext: return RecoveryReason::GuardSnapshotInvalidContext;
    case RecoveryNativeResult::Unreadable: return RecoveryReason::GuardSnapshotUnreadable;
    case RecoveryNativeResult::Changed: return RecoveryReason::GuardSnapshotChanged;
    case RecoveryNativeResult::Budget: return RecoveryReason::GuardSnapshotBudget;
    case RecoveryNativeResult::Shape: return RecoveryReason::GuardSnapshotShape;
    case RecoveryNativeResult::Alias: return RecoveryReason::GuardSnapshotAlias;
    case RecoveryNativeResult::Descriptor: return RecoveryReason::GuardSnapshotDescriptor;
    case RecoveryNativeResult::Pool: return RecoveryReason::GuardSnapshotPool;
    case RecoveryNativeResult::Readiness: return RecoveryReason::GuardSnapshotReadiness;
    case RecoveryNativeResult::Hook: return RecoveryReason::GuardSnapshotHook;
    case RecoveryNativeResult::Allocator: return RecoveryReason::GuardSnapshotAllocator;
    case RecoveryNativeResult::Import: return RecoveryReason::GuardSnapshotImport;
    case RecoveryNativeResult::Provenance: return RecoveryReason::GuardSnapshotProvenance;
    }
    return RecoveryReason::NativeProfileMismatch;
}
RecoveryReason NativeGuardReason(RecoveryNativeResult readResult,const RecoveryNativeSnapshot& before,
    const TaskSnapshot& heartbeat) noexcept {
    if(readResult!=RecoveryNativeResult::Ready) return NativeSnapshotGuardReason(readResult);
    if(RequireNativeRecoveryReady(before)!=RecoveryNativeResult::Ready) return RecoveryReason::GuardReadiness;
    if(before.standalone!=3) return RecoveryReason::GuardStandalone;
    if(!before.sdkSession.size) return RecoveryReason::GuardSession;
    if(before.issuedId>=UINT32_MAX-3) return RecoveryReason::GuardIssuedId;
    if(RequireFinishFirstFree(before)!=RecoveryNativeResult::Ready) return RecoveryReason::GuardFinishFree;
    if(RequireCreateFirstFree(before)!=RecoveryNativeResult::Ready) return RecoveryReason::GuardCreateFree;
    if(heartbeat.identity.slot>=kRecoveryGenericSlots ||
        (heartbeat.identity.holder&0xffff)>=kRecoveryTypedSlots) return RecoveryReason::GuardHeartbeatSlot;
    if((heartbeat.identity.holder>>16)!=before.heartbeat.type) return RecoveryReason::GuardHeartbeatType;
    if(before.heartbeatId!=heartbeat.identity.id) return RecoveryReason::GuardHeartbeatId;
    if(before.generic[heartbeat.identity.slot].id!=heartbeat.identity.id) return RecoveryReason::GuardGenericId;
    if(before.generic[heartbeat.identity.slot].holder!=heartbeat.identity.holder) return RecoveryReason::GuardGenericHolder;
    if(before.heartbeat.slots[heartbeat.identity.holder&0xffff].references!=1)
        return RecoveryReason::GuardHeartbeatReferences;
    return RecoveryReason::SnapshotGuardPassed;
}
void FinishTerminal(Runtime& state,LeechRecovery& r,std::uint64_t now) noexcept {
    (void)now; // Record headers sample a fresh clock; payload preserves fault time.
    TimingCopy(r);
    const auto phase=(r.cancelEntered || (r.value.flags&RecoveryRestartRequired)) ? RecoveryPhase::Failed : RecoveryPhase::Rejected;
    if(Phase(r)!=RecoveryPhase::Observed) {
        r.value.flags|=RecoveryTerminal;Transition(r,phase,r.value.qpc);
        if(r.exceptionPending && RuntimeCaptureAdmission(state)) {Queue(r,RecoveryEvent::Exception);r.exceptionPending=false;}
    }
    if(r.finalPending) {Queue(r,RecoveryEvent::Final);r.finalPending=false;}
    if(!Flush(state,r)) {r.pendingRead=0;r.pendingCount=0;Publish(r);}
    ReleaseCapture(state,state.recoveryQuota);
    if(!r.cancelEntered && !(r.value.flags&RecoveryRestartRequired) && RecoveryRuntimeSafeOwner(state) &&
        ReadTaskPhase(state.task)!=TaskPhase::Inert) state.bindingSuspended=false;
}
} // namespace

bool PrepareLeechRecovery(LeechRecovery& r,Runtime& state,const StartupProfile& startup,
    const wchar_t* directory,HMODULE companion) noexcept {
    r.runtime=&state;r.status=&RS2LeechRecovery_StatusV1;r.startup=startup;
    r.native={state.config.hostBase,state.config.hostSize,state.config.memory,&ProductionNativeImportOps(),&ProductionRecoveryNativeLayout()};
    r.value.ownerThreadId=state.config.ownerThreadId;r.value.reason=static_cast<std::uint64_t>(RecoveryReason::PermissionDisabled);
    if(ReadStatusWord(r.status->headerReady)!=1) InitializeRecoveryStatus(*r.status,state.config.status->header);
    DWORD error{};
    const auto control=recovery::InitializeControl(r.control,directory,state.config.status->header.pid,state.config.status->header.runId,&error);
    if(control!=recovery::ControlResult::Ready) {
        using C=recovery::ControlResult;
        const auto reason=control==C::Disabled ? RecoveryReason::PermissionDisabled :
            control==C::Missing ? RecoveryReason::ControlConfigMissing :
            control==C::InvalidConfig ? RecoveryReason::ControlConfigInvalid :
            control==C::InvalidIdentity ? RecoveryReason::ControlIdentityMismatch :
            control==C::InvalidPath ? RecoveryReason::ControlPathRejected :
            control==C::SecurityRejected ? RecoveryReason::ControlSecurityRejected :
            control==C::ReadFailure || control==C::PendingWrite ? RecoveryReason::ControlReadFailure :
            control==C::EndpointUnavailable ? RecoveryReason::ControlEndpointUnavailable :
            RecoveryReason::ControlWorkerUnavailable;
        r.value.reason=static_cast<std::uint64_t>(reason);Publish(r);return false;
    }
    const void* prefix[]{reinterpret_cast<const void*>(&CreateSuccess)};
    if(ValidateNativeRecoveryProfile(state.config.hostBase,startup,state.config.memory,*r.native.imports,&error)!=ProfileResult::Ready ||
        !PrepareCaptureProfile(companion,state.config.hostBase,state.config.hostSize,prefix,1,&r.createCapture)) {
        r.value.reason=static_cast<std::uint64_t>(RecoveryReason::NativeProfileMismatch);Publish(r);return false;
    }
#if defined(RS2_RECOVERY_GUARD_PROBE)
    // Defense in depth: this build retains no recipe pointers. The compiled-out
    // owner call sites below are the primary no-native-mutation boundary.
    r.calls={};
#else
    r.calls=NativeRecoveryCallAddresses(state.config.hostBase);
#endif
    r.prepared=true;return true;
}
void ArmLeechRecovery(LeechRecovery& r) noexcept {
    if(!r.prepared || !r.runtime || !RuntimeOwner(*r.runtime)) return;
    DWORD error{};
    if(InterlockedCompareExchangePointer(&g_recovery,&r,nullptr)!=nullptr || !recovery::StartControl(r.control,&error)) {
        r.prepared=false;r.value.reason=static_cast<std::uint64_t>(RecoveryReason::ControlWorkerUnavailable);Publish(r);return;
    }
    r.controlStarted=true;r.value.flags=RecoveryPermissionEnabled;r.value.phase=static_cast<std::uint64_t>(RecoveryPhase::Armed);
    r.value.transitionSequence=1;r.value.reason=0;PureClock(&r.value.qpc);Publish(r);
}
bool RecoveryServiceDue(const Runtime& state) noexcept {
    const auto* r=state.config.recovery;
    if(!r || !r->prepared || !r->controlStarted) return false;
    if(r->requested) return !r->terminal || r->finalPending || r->pendingCount!=0;
    const auto result=static_cast<recovery::ControlResult>(InterlockedCompareExchange(const_cast<volatile LONG*>(&r->control.result),0,0));
    return InterlockedCompareExchange(const_cast<volatile LONG*>(&r->control.latched),0,0)!=0 ||
        (result!=recovery::ControlResult::Ready && result!=recovery::ControlResult::Missing && result!=recovery::ControlResult::PendingWrite);
}
void RecoveryOwnerClockFault(Runtime& state) noexcept {
    auto* r=state.config.recovery;
    if(r && r->prepared && RuntimeOwner(state) && r->requested && !r->terminal)
    {
        Fault(*r,RecoveryReason::ClockFault,RecoveryOutcome::MechanicsFailed,r->cancelEntered);
        // Timing loss is sticky. No clockless SDK progress or terminal emission,
        // but the owner SERVICE can release bookkeeping credits exactly once.
        // A directly guarded Create callback keeps them for that later boundary.
        if(!r->callbackDepth) ReleaseCapture(state,state.recoveryQuota);
    }
}
bool ServiceLeechRecovery(Runtime& state,CallerClass classification,std::size_t count,bool truncated,std::int64_t qpc) {
    auto* pointer=state.config.recovery;
    if(!pointer || !pointer->prepared || !RuntimeOwner(state)) return false;
    auto& r=*pointer;const DWORD incoming=GetLastError();
    if(classification!=CallerClass::NormalPump || truncated || qpc<0 || state.pumpDepth!=1 || state.builderDepth || state.timingDepth!=1) {
        // Unsupported capture grants no forward, inverse or record authority.
        // The existing top-level owner frame can still expire an active attempt
        // and finish scalar/bookkeeping work without parking ordinary revocation.
        if(r.requested && state.pumpDepth==1 && !state.builderDepth && state.timingDepth==1 && !r.callbackDepth) {
            if(!r.terminal && qpc>=0) r.value.qpc=static_cast<std::uint64_t>(qpc);
            if(InterlockedCompareExchange(&r.foreignFault,0,0))
                Fault(r,RecoveryReason::CallbackInvalid,RecoveryOutcome::MechanicsFailed,true);
            if(!r.terminal) {
                if(qpc<0) Fault(r,RecoveryReason::ClockFault,RecoveryOutcome::MechanicsFailed,r.cancelEntered);
                else if(static_cast<std::uint64_t>(qpc)>=r.value.overallDeadlineQpc)
                    Fault(r,RecoveryReason::AttemptTimeout,RecoveryOutcome::MechanicsFailed,r.cancelEntered);
                else if((Phase(r)==RecoveryPhase::Qualifying || Phase(r)==RecoveryPhase::FinishSubmitted || Phase(r)==RecoveryPhase::FinishAccepted) &&
                        static_cast<std::uint64_t>(qpc)>=r.value.finishDeadlineQpc)
                    Fault(r,RecoveryReason::FinishTimeout,RecoveryOutcome::MechanicsFailed,r.cancelEntered);
            }
            if(r.terminal) {
                const auto phase=Phase(r)==RecoveryPhase::Observed ? RecoveryPhase::Observed :
                    (r.cancelEntered || (r.value.flags&RecoveryRestartRequired)) ? RecoveryPhase::Failed : RecoveryPhase::Rejected;
                if(Phase(r)!=phase) {
                    if(r.value.transitionSequence!=UINT64_MAX) ++r.value.transitionSequence;
                    r.value.phase=static_cast<std::uint64_t>(phase);
                }
                r.value.flags|=RecoveryTerminal;
                r.pendingRead=0;r.pendingCount=0;r.finalPending=false;
                Publish(r);ReleaseCapture(state,state.recoveryQuota);
                // Management can be rate-limited on this fallthrough. Only a
                // clean pre-cancel rejection may resume ordinary binding.
                if(!r.cancelEntered && !(r.value.flags&RecoveryRestartRequired) && RecoveryRuntimeSafeOwner(state) &&
                    ReadTaskPhase(state.task)!=TaskPhase::Inert) state.bindingSuspended=false;
            }
        }
        SetLastError(incoming);
        return false;
    }
    const auto now=static_cast<std::uint64_t>(qpc);
    if(r.requested && !r.terminal) r.value.qpc=now;
    if(InterlockedCompareExchange(&r.foreignFault,0,0)) Fault(r,RecoveryReason::CallbackInvalid,RecoveryOutcome::MechanicsFailed,true);
    if(!r.requested) {
        recovery::ControlRequest request{};
        if(!recovery::ReadLatchedControl(r.control,&request)) {
            r.requested=true;Fault(r,RecoveryReason::InvalidRequest,RecoveryOutcome::MechanicsFailed,false);
        } else {
            r.requested=true;r.value.operationSequence=1;r.value.sourceEpoch=state.counters.sourceEpoch;r.value.sdkEpoch=state.idleLifecycle;
            const auto frequency=state.producer.frequency;
            if(frequency<=0 || static_cast<std::uint64_t>(frequency)>static_cast<std::uint64_t>(INT64_MAX)/kAttemptSeconds ||
                now>static_cast<std::uint64_t>(INT64_MAX)-static_cast<std::uint64_t>(frequency)*kAttemptSeconds)
                Fault(r,RecoveryReason::ClockFault,RecoveryOutcome::MechanicsFailed,false);
            else {
                r.value.overallDeadlineQpc=now+static_cast<std::uint64_t>(frequency)*kAttemptSeconds;
                r.value.finishDeadlineQpc=now+static_cast<std::uint64_t>(frequency)*kFinishSeconds;
                Transition(r,RecoveryPhase::Requested,now);
            }
        }
    }
    if(!r.terminal && now>=r.value.overallDeadlineQpc) Fault(r,RecoveryReason::AttemptTimeout,RecoveryOutcome::MechanicsFailed,r.cancelEntered);
    if(r.terminal) {FinishTerminal(state,r,now);SetLastError(incoming);return true;}
    if(!RuntimeCaptureAdmission(state)) {
        Fault(r,RecoveryReason::RecordingUnavailable,RecoveryOutcome::RecordingUnavailable,r.cancelEntered);
        FinishTerminal(state,r,now);SetLastError(incoming);return true;
    }
    if(Phase(r)==RecoveryPhase::Requested) {
        if(!ReserveCapture(state,state.recoveryQuota,1)) {
            Fault(r,RecoveryReason::QuotaUnavailable,RecoveryOutcome::MechanicsFailed,false);
            FinishTerminal(state,r,now);SetLastError(incoming);return true;
        }
        const bool requestedWritten=Flush(state,r);ReleaseCapture(state,state.recoveryQuota);
        if(!requestedWritten) {Fault(r,RecoveryReason::RecordingUnavailable,RecoveryOutcome::RecordingUnavailable,false);FinishTerminal(state,r,now);SetLastError(incoming);return true;}
        Transition(r,RecoveryPhase::Qualifying,now);
        if(!ReserveCapture(state,state.recoveryQuota,1)) Fault(r,RecoveryReason::QuotaUnavailable,RecoveryOutcome::MechanicsFailed,false);
        else {if(!Flush(state,r)) Fault(r,RecoveryReason::RecordingUnavailable,RecoveryOutcome::RecordingUnavailable,false);ReleaseCapture(state,state.recoveryQuota);}
        if(r.terminal) FinishTerminal(state,r,now);
        SetLastError(incoming);return true;
    }
    if(Phase(r)==RecoveryPhase::Qualifying) {
        if(now>=r.value.finishDeadlineQpc) {
            Fault(r,RecoveryReason::FinishTimeout,RecoveryOutcome::MechanicsFailed,false);
            FinishTerminal(state,r,now);SetLastError(incoming);return true;
        }
        if(!r.qualifyingRecordSequence || ReadStatusWord(state.config.status->worker.observedSequence)<r.qualifyingRecordSequence) return true;
        if(!RecoveryPumpHeadroomAvailable(classification,count,truncated) || RecoveryRuntimeSource(state,&r.source)!=Reason::None ||
            r.source.bots!=0 || r.source.humans!=2 || RecoveryRuntimeTask(state,&r.oldHeartbeat)!=Reason::None ||
            r.oldHeartbeat.state!=2 || !r.oldHeartbeat.schedule.valid || r.oldHeartbeat.schedule.interval!=30000 ||
            r.oldHeartbeat.schedule.errors || r.oldHeartbeat.schedule.throttles || r.oldHeartbeat.schedule.expedite ||
            r.oldHeartbeat.schedule.intervalOverride || r.oldHeartbeat.schedule.retryOverride || r.oldHeartbeat.schedule.retryLimit!=3) {
            Fault(r,RecoveryReason::HeartbeatUnavailable,RecoveryOutcome::MechanicsFailed,false);
        } else {
            DWORD error{};
            const auto readResult=ReadNativeRecoverySnapshot(r.native,&r.before,&error);
            const auto guard=NativeGuardReason(readResult,r.before,r.oldHeartbeat);
            if(guard!=RecoveryReason::SnapshotGuardPassed) {
#if defined(RS2_RECOVERY_GUARD_PROBE)
                Fault(r,guard,RecoveryOutcome::MechanicsFailed,false);
#else
                Fault(r,RecoveryReason::NativeProfileMismatch,RecoveryOutcome::MechanicsFailed,false);
#endif
            } else {
#if !defined(RS2_RECOVERY_GUARD_PROBE)
                r.value.oldSdkFingerprint=Fingerprint(r.before.sdkBytes,static_cast<std::size_t>(r.before.sdkSession.size));
                r.value.oldCacheFingerprint=Fingerprint(r.before.cacheBytes,static_cast<std::size_t>(r.before.cacheSession.size));
#endif
                const auto generated=state.counters.reportSequence;
                if(!state.transport.reservedCredits && state.transport.generatedSequence==generated && state.transport.submittedSequence==generated &&
                    ReadStatusWord(state.config.status->worker.observedSequence)==generated &&
                    NativeTransportQuiescent(state.config.nativeTransport,generated,state.nativeLog.epoch) && LoggerLease(state) &&
                    Lease(state,r,3,true) && ReserveCapture(state,state.recoveryQuota,9)) {
#if defined(RS2_RECOVERY_GUARD_PROBE)
                    Fault(r,RecoveryReason::SnapshotGuardPassed,RecoveryOutcome::Inconclusive,false);
#else
                    SubmitFinish(state,r);
#endif
                }
                // Quiescence can legitimately be unavailable for this visit.
            }
        }
    }
#if !defined(RS2_RECOVERY_GUARD_PROBE)
    else if(Phase(r)==RecoveryPhase::FinishSubmitted) {
        if(now>=r.value.finishDeadlineQpc) Fault(r,RecoveryReason::FinishTimeout,RecoveryOutcome::MechanicsFailed,true);
        else if(!Lease(state,r,3,true)) Fault(r,RecoveryReason::LifecycleChanged,RecoveryOutcome::MechanicsFailed,true);
        else if(r.finishObserved && r.finishTrue && r.enqueueReturned && r.value.callbackId==r.finishId)
            Transition(r,RecoveryPhase::FinishAccepted,now); // Never recreate on the enqueue visit.
    } else if(Phase(r)==RecoveryPhase::FinishAccepted) {
        if(now>=r.value.finishDeadlineQpc) Fault(r,RecoveryReason::FinishTimeout,RecoveryOutcome::MechanicsFailed,true);
        else if(!RecoveryPumpHeadroomAvailable(classification,count,truncated)) Fault(r,RecoveryReason::NativeProfileMismatch,RecoveryOutcome::MechanicsFailed,true);
        else Recreate(state,r);
    } else if(Phase(r)==RecoveryPhase::Recreating && r.createReturned) {
        if(!Lease(state,r,3,false) || !r.current.sdkSession.size ||
            (r.current.sdkSession.size==r.before.sdkSession.size && !std::memcmp(r.current.sdkBytes,r.before.sdkBytes,static_cast<std::size_t>(r.current.sdkSession.size))))
            Fault(r,RecoveryReason::CreateFailed,RecoveryOutcome::MechanicsFailed,true);
        else if(CacheMatches(r.current)) {
            TaskSnapshot fresh{};
            if(RecoveryRuntimeTask(state,&fresh)==Reason::None && fresh.identity.id!=r.oldHeartbeat.identity.id && fresh.state==2 && fresh.builder==state.task.original) {
                r.value.newSdkFingerprint=Fingerprint(r.current.sdkBytes,static_cast<std::size_t>(r.current.sdkSession.size));
                r.value.newCacheFingerprint=Fingerprint(r.current.cacheBytes,static_cast<std::size_t>(r.current.cacheSession.size));
                r.publishedSession=r.current.sdkSession;
                std::memcpy(r.publishedSessionBytes,r.current.sdkBytes,sizeof(r.publishedSessionBytes));
                r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::Publish);TimingCopy(r);
                Transition(r,RecoveryPhase::Published,now);state.bindingSuspended=false;
            }
        }
    } else if(Phase(r)==RecoveryPhase::Published) {
        if(!Lease(state,r,3,false) || !SameBytes(r.current.sdkSession,r.current.sdkBytes,r.publishedSession,r.publishedSessionBytes) ||
            !CacheMatches(r.current)) Fault(r,RecoveryReason::LifecycleChanged,RecoveryOutcome::MechanicsFailed,true);
        else if(ReadTaskPhase(state.task)==TaskPhase::Armed) {
            r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::Rebind);r.value.outcome=static_cast<std::uint64_t>(RecoveryOutcome::PublishedNotDelivered);
            r.value.flags|=RecoveryTerminal;Transition(r,RecoveryPhase::Observed,now);r.terminal=true;r.finalPending=true;
        } else {Publish(r);SetLastError(incoming);return false;} // Ordinary fresh Bind gets NEW authority.
    }
#endif
    if(r.terminal) FinishTerminal(state,r,now);
    else {Flush(state,r);Publish(r);}
    SetLastError(incoming);return true;
}
#if defined(RS2_REPORTING_TESTING)
RecoveryReason NativeGuardReasonForTest(RecoveryNativeResult result,const RecoveryNativeSnapshot& before,
    const TaskSnapshot& heartbeat) noexcept {return NativeGuardReason(result,before,heartbeat);}
void SetLeechRecoveryCurrentForTest(LeechRecovery* r) noexcept {InterlockedExchangePointer(&g_recovery,r);}
void ObserveLeechFinishForTest(LeechRecovery& r,const bool* value,std::uint32_t id,bool errorCall,std::int32_t code) noexcept {
    FinishObservation(r,value,id,errorCall,code);
}
bool FinishLeechErrorForTest(LeechRecovery& r,std::int32_t code,std::uint32_t id) noexcept {
    SetLeechRecoveryCurrentForTest(&r);const bool handled=FinishError(code,id);SetLeechRecoveryCurrentForTest(nullptr);return handled;
}
void FinishLeechTerminalForTest(Runtime& state,LeechRecovery& r,std::uint64_t qpc) noexcept {FinishTerminal(state,r,qpc);}
void ReleaseLeechOwnedForTest(Runtime& state,LeechRecovery& r) {ReleaseOwned(state,r);}
void SubmitLeechFinishForTest(Runtime& state,LeechRecovery& r) {SubmitFinish(state,r);}
void RecreateLeechForTest(Runtime& state,LeechRecovery& r) {Recreate(state,r);}
bool ChangedOnlyLeechCreateForTest(LeechRecovery& r,bool installed) noexcept {return ChangedOnlyCreate(r,installed);}
bool InstallLeechCreateGuardForTest(Runtime& state,LeechRecovery& r) noexcept {return InstallCreateGuard(state,r);}
void InvokeLeechCreateSuccessForTest(LeechRecovery& r,const void* result,std::uint32_t id) {
    SetLeechRecoveryCurrentForTest(&r);CreateSuccess(result,id);
}
void SetLeechCreateCaptureForTest(const std::uint32_t* frames,std::size_t count,bool truncated,bool success) noexcept {
    g_captureFixture={};if(!frames) return;
    g_captureFixture.enabled=true;g_captureFixture.count=count;g_captureFixture.truncated=truncated;g_captureFixture.success=success;
    std::memcpy(g_captureFixture.frames,frames,(count<kCaptureFrames ? count : kCaptureFrames)*sizeof(std::uint32_t));
}
#endif
} // namespace rs2fix::reporting
