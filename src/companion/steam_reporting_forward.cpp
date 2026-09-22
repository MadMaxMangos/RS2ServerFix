#include "companion/steam_reporting_forward.h"
#include <intrin.h>
#include <limits>

namespace rs2fix::reporting {
namespace {
PVOID volatile g_runtime{};
struct CallFrame {
    std::int64_t start;
    std::int64_t nativeStart;
    std::int64_t nativeEnd;
    DWORD incoming;
    bool owner;
    bool depthOwned;
    bool topLevel;
    bool returned;
    bool managed;
};
Runtime& Current() noexcept {
    auto* state=static_cast<Runtime*>(InterlockedCompareExchangePointer(&g_runtime,nullptr,nullptr));
    if (!state) __fastfail(7);
    return *state;
}
bool Clock(std::int64_t* value) noexcept {
    LARGE_INTEGER now{};
    const bool ok=QueryPerformanceCounter(&now) && now.QuadPart>=0;
    *value=ok ? now.QuadPart : -1;
    return ok;
}
void Begin(Runtime& state, CallFrame& frame, std::uint32_t& depth) noexcept {
    if (!frame.owner) { RevokeRuntime(state,Reason::ForeignThread); return; }
    if (depth==(std::numeric_limits<std::uint32_t>::max)() ||
        state.timingDepth==(std::numeric_limits<std::uint32_t>::max)()) {
        FailRuntimeTiming(state,Reason::CounterOverflow); return;
    }
    frame.depthOwned=true;
    frame.topLevel=state.timingDepth==0;
    ++depth; ++state.timingDepth;
    if (depth!=1) RevokeRuntime(state,Reason::Reentry);
    ValidateRuntimeEntry(state,frame.start);
}
std::uint64_t NativeTicks(Runtime& state, const CallFrame& frame) noexcept {
    if (frame.nativeStart<frame.start || frame.nativeEnd<frame.nativeStart || frame.start<0) {
        FailRuntimeTiming(state,Reason::ClockFailed); return 0;
    }
    return static_cast<std::uint64_t>(frame.nativeEnd-frame.nativeStart);
}
void End(Runtime& state, CallFrame& frame, std::uint32_t& depth, DurationClass kind) noexcept {
    if (!frame.owner) return;
    if (frame.depthOwned) {
        if (!depth || !state.timingDepth) FailRuntimeTiming(state,Reason::Reentry);
        else { --depth; --state.timingDepth; }
    }
    std::int64_t now{};
    if (!RuntimeClock(state,&now)) return;
    // Queue/anchor/status work and balanced-depth cleanup are inside measured
    // own time, including this entire status copy. The current interval is not
    // complete at this publication's lastOwnerQpc. Only a previously completed
    // top-level invocation may advance timingAccountedThroughQpc. A nested child
    // publication must not imply that its unfinished parent is already counted.
    PublishRuntimeStatus(state,now,true);
    std::int64_t end{};
    if (!RuntimeClock(state,&end)) return;
    const auto native=NativeTicks(state,frame);
    if (frame.start<0 || end<frame.start || static_cast<std::uint64_t>(end-frame.start)<native) {
        FailRuntimeTiming(state,Reason::ClockFailed); return;
    }
    StageRuntimeDuration(state,kind,static_cast<std::uint64_t>(end-frame.start)-native,
        frame.start,frame.topLevel);
    // Only checked single-slot staging/return work remains outside the measured
    // interval. The exact-path fixture retains every paired class residual.
}
__declspec(noinline) void AfterPump(Runtime& state, CallFrame& frame) noexcept {
    if (!frame.owner || state.pumpDepth!=1) return;
    const bool cleanup=RuntimeCleanupAdmission(state);
    if (!cleanup && !RuntimeAdmission(state)) return;
    std::int64_t now{};
    const bool clock=RuntimeClock(state,&now);
    if (!clock && !cleanup) return;
    const auto frequency=state.producer.frequency;
    // Stable idle state needs fewer full observations. First binding, source/
    // epoch loss, pending producer consumption and owned cleanup retain the
    // fast lane. This changes only OUR management opportunities, not native
    // callbacks/backoff; each builder still performs its own full live checks.
    const bool idle=!cleanup && state.sourceReady && state.producer.epochReady &&
        ReadTaskPhase(state.task)==TaskPhase::Armed && !state.producer.pending.active;
    // Producer frequency is bounded by INT64_MAX/45 at initialization, so the
    // idle multiplication is safe. A delayed pump may run later than two seconds.
    // Ceiling preserves the at-most-four-Hz fast lane for unusual frequencies.
    const auto interval=idle ? frequency*2 :
        frequency/kManagementHz+(frequency%kManagementHz!=0 ? 1 : 0);
    if (clock && state.haveManagement && now-state.lastManagement<interval) return;
    if (cleanup && clock) { state.haveManagement=true; state.lastManagement=now; }
    frame.managed=true;
    std::uint32_t callers[kCaptureFrames]{};
    std::size_t count{}; bool truncated{};
    const bool captured=CaptureHostCallers(state.config.pumpCapture,callers,&count,&truncated);
    const auto classification=captured ? ClassifyPumpFrames(state.config.ancestry,callers,count,truncated) : CallerClass::Unknown;
    if (cleanup) CleanupRevokedRuntime(state,classification);
    else ManagePump(state,classification,now);
}
__declspec(noinline) void BeforeBuilder(Runtime& state, void* holder, CallFrame& frame,
    BuilderDecision& decision) noexcept {
    if (!frame.owner || state.builderDepth!=1 || !RuntimeAdmission(state) ||
        ReadTaskPhase(state.task)!=TaskPhase::Armed) return;
    std::int64_t start{};
    if (!RuntimeClock(state,&start)) return;
    std::uint32_t callers[kCaptureFrames]{};
    std::size_t count{}; bool truncated{};
    const bool captured=CaptureHostCallers(state.config.builderCapture,callers,&count,&truncated);
    const auto classification=captured ? ClassifyBuilderFrames(state.config.ancestry,callers,count,truncated) : CallerClass::Unknown;
    std::int64_t classified{};
    if (!RuntimeClock(state,&classified)) return;
    frame.managed=classification==CallerClass::NormalBuilder;
    PrepareBuilder(state,classification,holder,start,static_cast<std::uint64_t>(classified-start),&decision);
}
bool FinalSelection(Runtime& state, const BuilderDecision& decision) noexcept {
    if (!decision.eligible || !decision.dirtyAddress || !RuntimeAdmission(state) ||
        !state.sourceReady || ReadTaskPhase(state.task)!=TaskPhase::Armed ||
        state.task.epoch.source!=state.counters.sourceEpoch ||
        state.task.epoch.binding!=state.counters.bindingEpoch) return false;
    std::int64_t now{}; FreshTuple fresh{};
    if (!RuntimeClock(state,&now)) return false;
    return ReadFreshTuple(state.producer,now,state.source.outer,state.source.bots,&fresh)==Reason::None &&
        fresh.witness==decision.event.payload.builder.witnessSequence && RuntimeAdmission(state);
}
// This helper's exception region contains ONLY our store. Original executes
// outside it, so a genuine C++/SEH exception can never be caught as a write fault.
// A successful store falls directly into original(holder), with no second gate,
// logger, counter, clock API or native call interposed.
__declspec(noinline) bool ForwardBuilder(Runtime& state, void* holder,
    std::uintptr_t dirty, bool* selected, CallFrame& frame) {
    if (*selected) {
        __try { *reinterpret_cast<volatile std::uint8_t*>(dirty)=1; }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            *selected=false;
            RevokeRuntime(state,Reason::WriteFault);
            // Own exception handling is NOT charged to native execution. The
            // successful store path has no such intervening timestamp/call.
            if (!Clock(&frame.nativeStart)) FailRuntimeTiming(state,Reason::ClockFailed);
            SetLastError(frame.incoming);
        }
    }
    return state.config.builderOriginal(holder);
}
} // namespace

bool PrepareRuntimeCapture(Runtime& state, HMODULE companion) noexcept {
    const void* pump[]{reinterpret_cast<const void*>(&AfterPump),reinterpret_cast<const void*>(&PumpEntry)};
    const void* builder[]{reinterpret_cast<const void*>(&BeforeBuilder),reinterpret_cast<const void*>(&BuilderEntry)};
    return PrepareCaptureProfile(companion,state.config.hostBase,state.config.hostSize,pump,2,&state.config.pumpCapture) &&
        PrepareCaptureProfile(companion,state.config.hostBase,state.config.hostSize,builder,2,&state.config.builderCapture);
}
bool PublishRuntime(Runtime& state) noexcept {
    if (!RuntimeOwner(state) || !state.config.pumpOriginal || !state.config.builderOriginal ||
        state.config.pumpCapture.prefixCount!=3 || state.config.builderCapture.prefixCount!=3 ||
        StatusRevoked(*state.config.status)) return false;
    return InterlockedCompareExchangePointer(&g_runtime,&state,nullptr)==nullptr;
}
__declspec(noinline) void PumpEntry() {
    const DWORD incoming=GetLastError();
    std::int64_t entryQpc;
    Clock(&entryQpc);
    Runtime& state=Current();
    CallFrame frame{};
    frame.incoming=incoming;
    frame.owner=RuntimeOwner(state);
    frame.start=entryQpc;
    // Preparing calls participate in the same four-cell commit gate, even if
    // they came from a foreign thread and will only forward afterwards.
    observer::AdmitExternalCall(*state.config.dispatch);
    if (frame.owner) Begin(state,frame,state.pumpDepth);
    else RevokeRuntime(state,Reason::ForeignThread);
    __try {
        if (frame.owner) ConsumeRuntimeDuration(state);
        if (!Clock(&frame.nativeStart)) FailRuntimeTiming(state,Reason::ClockFailed);
        SetLastError(frame.incoming);
        state.config.pumpOriginal();
        const DWORD outgoing=GetLastError();
        if (!Clock(&frame.nativeEnd)) FailRuntimeTiming(state,Reason::ClockFailed);
        frame.returned=true;
        AfterPump(state,frame);
        SetLastError(outgoing);
    } __finally {
        const DWORD outgoing=GetLastError();
        if (!frame.returned) {
            if (!Clock(&frame.nativeEnd)) FailRuntimeTiming(state,Reason::ClockFailed);
            RevokeRuntime(state,Reason::NativeUnwind);
        }
        if (frame.owner) End(state,frame,state.pumpDepth,
            frame.managed ? DurationClass::PumpManagement : DurationClass::PumpForward);
        SetLastError(outgoing);
    }
}
__declspec(noinline) bool BuilderEntry(void* holder) {
    const DWORD incoming=GetLastError();
    std::int64_t entryQpc;
    Clock(&entryQpc);
    Runtime& state=Current();
    CallFrame frame{}; BuilderDecision decision{};
    frame.incoming=incoming; frame.owner=RuntimeOwner(state);
    frame.start=entryQpc;
    if (frame.owner) Begin(state,frame,state.builderDepth);
    else RevokeRuntime(state,Reason::ForeignThread);
    bool result=false, selected=false;
    __try {
        if (frame.owner) ConsumeRuntimeDuration(state);
        BeforeBuilder(state,holder,frame,decision);
        selected=FinalSelection(state,decision);
        if (!Clock(&frame.nativeStart)) {
            FailRuntimeTiming(state,Reason::ClockFailed);
            selected=false;
        }
        SetLastError(frame.incoming);
        result=ForwardBuilder(state,holder,decision.dirtyAddress,&selected,frame);
        const DWORD outgoing=GetLastError();
        if (!Clock(&frame.nativeEnd)) FailRuntimeTiming(state,Reason::ClockFailed);
        frame.returned=true;
        SetLastError(outgoing);
    } __finally {
        const DWORD outgoing=GetLastError();
        if (!frame.returned && !Clock(&frame.nativeEnd)) FailRuntimeTiming(state,Reason::ClockFailed);
        if (frame.owner) {
            FinishBuilder(state,decision,frame.returned,result,selected,frame.nativeEnd,NativeTicks(state,frame));
            if (!frame.returned) RevokeRuntime(state,Reason::NativeUnwind);
            End(state,frame,state.builderDepth,
                frame.managed ? DurationClass::BuilderProbe : DurationClass::BuilderForward);
        }
        SetLastError(outgoing);
    }
    return result;
}
#if defined(RS2_REPORTING_TESTING)
void ResetPublishedRuntimeForTest() noexcept { InterlockedExchangePointer(&g_runtime,nullptr); }
#endif
} // namespace rs2fix::reporting
