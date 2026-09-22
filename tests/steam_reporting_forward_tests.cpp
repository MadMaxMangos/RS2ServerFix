#include "companion/steam_reporting_forward.h"
#include "test_framework.h"

#include <cstring>
#include <intrin.h>
#include <limits>
#include <thread>

namespace {
using namespace rs2fix;
using namespace rs2fix::reporting;
namespace obs = rs2fix::observer;
constexpr DWORD kIncoming = 0x41524331;
constexpr DWORD kOutgoing = 0x41524332;
constexpr DWORD kProbeError = 0x41524333;
constexpr DWORD kNativeSeh = 0xE0425141;
constexpr int kNativeCpp = 97;
constexpr std::uint64_t kIdle = 1ULL << 32;
enum class Outcome { False, True, Cpp, Seh };
struct Fixture;
Fixture* g_fixture{};
std::uintptr_t g_host{};
std::uint32_t g_pumpReturns[3]{}, g_builderReturns[8]{};

__declspec(noinline) void NativePump();
__declspec(noinline) bool NativeBuilder(void*);
std::uint32_t Rva(const void* address) noexcept {
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(address) - g_host);
}

// Independent return-address oracles run through the SAME indirect fixture
// callsite as the real entry. No expected RVA is learned from the stack walker.
// Volatile indirect targets/results prevent constant propagation or tail calls
// from manufacturing a different stack in optimized MSVC builds.
__declspec(noinline) void PumpOracle() { g_pumpReturns[0] = Rva(_ReturnAddress()); }
__declspec(noinline) void PumpAdapter(obs::ShutdownFn target) {
    g_pumpReturns[1] = Rva(_ReturnAddress());
    volatile obs::ShutdownFn indirect = target;
    indirect();
    volatile unsigned completed = 1; (void)completed;
}
__declspec(noinline) void PumpWorld(obs::ShutdownFn target) {
    g_pumpReturns[2] = Rva(_ReturnAddress());
    PumpAdapter(target);
    volatile unsigned completed = 1; (void)completed;
}
__declspec(noinline) void PumpEngine(obs::ShutdownFn target) {
    PumpWorld(target);
    volatile unsigned completed = 1; (void)completed;
}
__declspec(noinline) bool BuilderOracle(void*) {
    g_builderReturns[0] = Rva(_ReturnAddress());
    return true;
}
__declspec(noinline) bool BuilderAdapter(BuilderFn target, void* holder) {
    g_builderReturns[1] = Rva(_ReturnAddress());
    volatile BuilderFn indirect = target;
    volatile bool result = indirect(holder); return result;
}
__declspec(noinline) bool TaskDispatch(BuilderFn target, void* holder) {
    g_builderReturns[2] = Rva(_ReturnAddress());
    volatile bool result = BuilderAdapter(target, holder); return result;
}
__declspec(noinline) bool TaskPump(BuilderFn target, void* holder) {
    g_builderReturns[3] = Rva(_ReturnAddress());
    volatile bool result = TaskDispatch(target, holder); return result;
}
__declspec(noinline) bool LeechUpdate(BuilderFn target, void* holder) {
    g_builderReturns[4] = Rva(_ReturnAddress());
    volatile bool result = TaskPump(target, holder); return result;
}
__declspec(noinline) bool LeechTick(BuilderFn target, void* holder) {
    g_builderReturns[5] = Rva(_ReturnAddress());
    volatile bool result = LeechUpdate(target, holder); return result;
}
__declspec(noinline) bool Subsystem(BuilderFn target, void* holder) {
    g_builderReturns[6] = Rva(_ReturnAddress());
    volatile bool result = LeechTick(target, holder); return result;
}
__declspec(noinline) bool BuilderWorld(BuilderFn target, void* holder) {
    g_builderReturns[7] = Rva(_ReturnAddress());
    volatile bool result = Subsystem(target, holder); return result;
}
__declspec(noinline) bool BuilderEngine(BuilderFn target, void* holder) {
    volatile bool result = BuilderWorld(target, holder); return result;
}

ClientQualification InertQualification() noexcept {
    ClientQualification result{};
    result.referenceAcquired = true; result.referenceReleased = true;
    return result;
}
struct Fixture {
    StatusWire status{};
    ReportRing ring{};
    obs::DispatchState dispatch{};
    Runtime runtime{};
    Outcome outcome{Outcome::True};
    bool nested{};
    bool crossNested{};
    bool nestedEntered{};
    bool breakFinalClock{};
    bool live{};
    std::uint64_t nestedPrivateCutoff{}, nestedPublishedCutoff{};
    void* holder{reinterpret_cast<void*>(1)}; // Intentionally unreadable and opaque.
    volatile LONG pumpCalls{}, builderCalls{}, argumentErrors{}, queries{}, reads{}, notices{};

    Fixture() {
        ResetPublishedRuntimeForTest();
        g_fixture = this;
        const auto self = GetModuleHandleW(nullptr);
        g_host = reinterpret_cast<std::uintptr_t>(self);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_host);
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(g_host + dos->e_lfanew);
        LARGE_INTEGER frequency{};
        RS2_CHECK(QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0);
        StatusHeader header{};
        header.validity = CompleteHeaderIdentity;
        header.configuredMode = static_cast<std::uint32_t>(Mode::Observe);
        header.qpcFrequency = static_cast<std::uint64_t>(frequency.QuadPart);
        header.pid = GetCurrentProcessId(); header.runId[0] = 1;
        RS2_CHECK(InitializeStatus(status, header, {}));
        RS2_CHECK(InitializeReportRing(ring, status, GetCurrentThreadId()));
        obs::InitializeDispatch(dispatch, {}, {});
        InterlockedExchange(&dispatch.gate, static_cast<LONG>(obs::Gate::Armed));
        RuntimeConfig config{};
        config.mode = Mode::Observe;
        config.ownerThreadId = GetCurrentThreadId();
        config.hostBase = g_host; config.hostSize = nt->OptionalHeader.SizeOfImage;
        config.memory = {this, Query, Read};
        config.dispatch = &dispatch; config.status = &status; config.sink = ReportRingSink(ring);
        config.pumpOriginal = NativePump; config.builderOriginal = NativeBuilder;
        config.builderWrapper = reinterpret_cast<std::uintptr_t>(&BuilderEntry);
        // Owned fixture RVAs only. Deny-all MemoryOps never dereferences these
        // source/task locations, even when the actual stack classifier admits.
        config.source = {0x3000, 0x3008, 0x3010, 0x3018};
        config.prepared = ProductionPreparedLayout();
        config.task = ProductionTaskLayout();
        config.ancestry = ProductionAncestryProfile();
        config.noticeContext = this; config.notice = Notice; config.qualifyClient = InertQualification;
        const bool initialized = InitializeRuntime(runtime, config, frequency.QuadPart) == Reason::None;
        RS2_CHECK(initialized);
        const bool captured = initialized && PrepareRuntimeCapture(runtime, self);
        RS2_CHECK(captured);
        live = captured && PublishRuntime(runtime);
        RS2_CHECK(live);
    }
    ~Fixture() { ResetPublishedRuntimeForTest(); g_fixture = nullptr; }
    static bool Query(void* context, std::uintptr_t, MemoryRegion*, DWORD* error) noexcept {
        InterlockedIncrement(&static_cast<Fixture*>(context)->queries);
        *error = ERROR_NOACCESS; SetLastError(kProbeError); return false;
    }
    static bool Read(void* context, std::uintptr_t, void*, std::size_t, DWORD* error) noexcept {
        InterlockedIncrement(&static_cast<Fixture*>(context)->reads);
        *error = ERROR_PARTIAL_COPY; SetLastError(kProbeError); return false;
    }
    static void Notice(void* context, bool, Reason) noexcept {
        InterlockedIncrement(&static_cast<Fixture*>(context)->notices);
        SetLastError(kProbeError); // Stress restoration around own diagnostics.
    }
    void Ready() {
        const auto sink = RuntimeLifecycleSink(runtime);
        InterlockedExchange64(&dispatch.lifecycle, static_cast<LONG64>(kIdle | 1));
        sink.initEntered(sink.context, kIdle | 1, true);
        sink.initReturned(sink.context, kIdle | 1, true, true);
        InterlockedExchange64(&dispatch.lifecycle, static_cast<LONG64>(kIdle));
        sink.initFinished(sink.context, kIdle, true, true);
        RS2_CHECK(runtime.sdkReady && !StatusRevoked(status));
    }
    bool Revoked(Reason reason) const noexcept {
        return (ReadStatusWord(status.revokeReasons) & (1ULL << static_cast<unsigned>(reason))) != 0;
    }
    void ClearProbes() noexcept { InterlockedExchange(&queries, 0); InterlockedExchange(&reads, 0); }
};

void Incoming(Fixture& f, void* holder, bool builder) noexcept {
    if (GetLastError() != kIncoming || (builder && holder != f.holder)) InterlockedIncrement(&f.argumentErrors);
}
void OriginalOutcome(Fixture& f) {
    // Existing owner-clock state is the fault seam: the real End clock can no
    // longer satisfy monotonicity. No replacement QPC or production hook needed.
    if (f.breakFinalClock) {
        f.runtime.lastClock = (std::numeric_limits<std::int64_t>::max)();
        f.runtime.haveClock = true;
    }
    SetLastError(kOutgoing);
    if (f.outcome == Outcome::Cpp) throw kNativeCpp;
    if (f.outcome == Outcome::Seh) RaiseException(kNativeSeh, 0, 0, nullptr);
}
__declspec(noinline) void NativePump() {
    auto& f = *g_fixture;
    Incoming(f, nullptr, false); InterlockedIncrement(&f.pumpCalls);
    if (f.nested && !f.nestedEntered) {
        f.nestedEntered = true;
        SetLastError(kIncoming);
        if (f.crossNested) (void)BuilderEntry(f.holder); else PumpEntry();
        if (GetLastError() != kOutgoing) InterlockedIncrement(&f.argumentErrors);
        f.nestedPrivateCutoff=f.runtime.counters.timingAccountedThroughQpc;
        f.nestedPublishedCutoff=ReadStatusWord(f.status.owner.timingAccountedThroughQpc);
    }
    OriginalOutcome(f);
}
__declspec(noinline) bool NativeBuilder(void* holder) {
    auto& f = *g_fixture;
    Incoming(f, holder, true); InterlockedIncrement(&f.builderCalls);
    if (f.nested && !f.nestedEntered) {
        f.nestedEntered = true;
        SetLastError(kIncoming);
        const bool result = f.crossNested ? (PumpEntry(),true) : BuilderEntry(holder);
        if (GetLastError() != kOutgoing || (!f.crossNested && result != (f.outcome == Outcome::True)))
            InterlockedIncrement(&f.argumentErrors);
        f.nestedPrivateCutoff=f.runtime.counters.timingAccountedThroughQpc;
        f.nestedPublishedCutoff=ReadStatusWord(f.status.owner.timingAccountedThroughQpc);
    }
    OriginalOutcome(f);
    return f.outcome == Outcome::True;
}
DWORD CatchSeh(bool builder, void* holder, DWORD* outgoing) {
    __try { if (builder) (void)BuilderEntry(holder); else PumpEntry(); }
    __except(GetExceptionCode() == kNativeSeh ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        *outgoing = GetLastError(); return GetExceptionCode();
    }
    *outgoing = GetLastError(); return 0;
}

void TransparentAndInactive() {
    for (const auto phase : {TaskPhase::Empty, TaskPhase::Preparing, TaskPhase::Retired, TaskPhase::Inert}) {
        for (const bool value : {false, true}) {
            Fixture f; if (!f.live) continue;
            f.Ready();
            InterlockedExchange(&f.runtime.task.phase, static_cast<LONG>(phase));
            f.outcome = value ? Outcome::True : Outcome::False;
            f.ClearProbes();
            SetLastError(kIncoming); const bool result = BuilderEntry(f.holder);
            const DWORD outgoing = GetLastError();
            RS2_CHECK(result == value && outgoing == kOutgoing && f.builderCalls == 1 && f.argumentErrors == 0);
            RS2_CHECK(f.runtime.builderDepth == 0 && f.queries == 0 && f.reads == 0);
            RS2_CHECK(f.runtime.counters.normalAttempts == 0 && f.runtime.counters.fullSelected == 0);
        }
    }
    { Fixture f; if (!f.live) return;
      InterlockedExchange(&f.dispatch.gate, static_cast<LONG>(obs::Gate::Preparing));
      SetLastError(kIncoming); PumpEntry(); const DWORD outgoing = GetLastError();
      RS2_CHECK(outgoing == kOutgoing && f.pumpCalls == 1 && f.argumentErrors == 0);
      RS2_CHECK(obs::ReadGate(f.dispatch) == obs::Gate::Contaminated);
      RS2_CHECK(f.runtime.pumpDepth == 0 && f.queries == 0 && f.reads == 0); }
    { Fixture f; if (!f.live) return;
      f.Ready(); RevokeStatus(f.status, Reason::RecordLoss);
      SetLastError(kIncoming); PumpEntry(); const DWORD outgoing = GetLastError();
      RS2_CHECK(outgoing == kOutgoing && f.pumpCalls == 1 && f.argumentErrors == 0);
      RS2_CHECK(f.queries == 0 && f.reads == 0 && f.runtime.pumpDepth == 0); }
}
void GenuineUnwindAndNestedDepth() {
    for (const bool builder : {false, true}) for (const auto outcome : {Outcome::Cpp, Outcome::Seh}) {
        Fixture f; if (!f.live) continue;
        f.outcome = outcome;
        DWORD outgoing{}; bool caught{};
        SetLastError(kIncoming);
        if (outcome == Outcome::Seh) caught = CatchSeh(builder, f.holder, &outgoing) == kNativeSeh;
        else {
            try { if (builder) (void)BuilderEntry(f.holder); else PumpEntry(); }
            catch (int value) { caught = value == kNativeCpp; }
            outgoing = GetLastError();
        }
        RS2_CHECK(caught && outgoing == kOutgoing && f.argumentErrors == 0);
        RS2_CHECK((builder ? f.builderCalls : f.pumpCalls) == 1);
        RS2_CHECK(f.runtime.builderDepth == 0 && f.runtime.pumpDepth == 0);
        RS2_CHECK(f.queries == 0 && f.reads == 0 && f.Revoked(Reason::NativeUnwind));
    }
    for (const bool builder : {false, true}) for (const bool throws : {false, true})
        for (const bool cross : {false,true}) {
        Fixture f; if (!f.live) continue;
        f.nested = true; f.crossNested=cross; f.outcome = throws ? Outcome::Cpp : Outcome::False;
        bool caught{}; bool result{};
        SetLastError(kIncoming);
        try { if (builder) result = BuilderEntry(f.holder); else PumpEntry(); }
        catch (int value) { caught = value == kNativeCpp; }
        const DWORD outgoing = GetLastError();
        RS2_CHECK(caught == throws && !result && outgoing == kOutgoing && f.argumentErrors == 0);
        RS2_CHECK((builder ? f.builderCalls : f.pumpCalls) == (cross ? 1 : 2));
        RS2_CHECK(f.Revoked(Reason::Reentry)==!cross);
        if (cross) RS2_CHECK((builder ? f.pumpCalls : f.builderCalls)==1);
        RS2_CHECK(f.runtime.builderDepth == 0 && f.runtime.pumpDepth == 0 && f.queries == 0 && f.reads == 0);
        RS2_CHECK(f.runtime.timingDepth==0 && f.runtime.pendingDuration.valid && f.runtime.pendingDuration.topLevel);
        if (throws) RS2_CHECK(f.Revoked(Reason::NativeUnwind));
    }
    { Fixture f; if (!f.live) return;
      f.runtime.builderDepth = (std::numeric_limits<std::uint32_t>::max)();
      SetLastError(kIncoming); const bool result = BuilderEntry(f.holder); const DWORD outgoing = GetLastError();
      RS2_CHECK(result && outgoing == kOutgoing && f.builderCalls == 1 && f.Revoked(Reason::CounterOverflow));
      RS2_CHECK(f.runtime.builderDepth == (std::numeric_limits<std::uint32_t>::max)() && f.queries == 0 && f.reads == 0); }
}
void ForeignForwardsOnly() {
    Fixture f; if (!f.live) return;
    f.Ready();
    InterlockedExchange(&f.runtime.task.phase, static_cast<LONG>(TaskPhase::Armed));
    const auto before = f.runtime.counters;
    DWORD pumpError{}, builderError{}; bool result{};
    std::thread foreign([&] {
        SetLastError(kIncoming); PumpEntry(); pumpError = GetLastError();
        SetLastError(kIncoming); result = BuilderEntry(f.holder); builderError = GetLastError();
    });
    foreign.join();
    RS2_CHECK(result && pumpError == kOutgoing && builderError == kOutgoing && f.argumentErrors == 0);
    RS2_CHECK(f.pumpCalls == 1 && f.builderCalls == 1 && f.Revoked(Reason::ForeignThread));
    RS2_CHECK(f.queries == 0 && f.reads == 0 && f.runtime.pumpDepth == 0 && f.runtime.builderDepth == 0);
    RS2_CHECK(std::memcmp(&before, &f.runtime.counters, sizeof(before)) == 0);
}
void ActualNormalCapture() {
    { Fixture f; if (!f.live) return;
      PumpEngine(PumpOracle);
      f.runtime.config.ancestry.callbackReturn = g_pumpReturns[0];
      f.runtime.config.ancestry.worldReturns[0] = f.runtime.config.ancestry.worldReturns[1] = g_pumpReturns[1];
      f.runtime.config.ancestry.engineReturn = g_pumpReturns[2];
      f.Ready(); f.ClearProbes();
      SetLastError(kIncoming); PumpEngine(PumpEntry); const DWORD outgoing = GetLastError();
      RS2_CHECK(outgoing == kOutgoing && f.pumpCalls == 1 && f.argumentErrors == 0);
      RS2_CHECK(f.runtime.counters.normalPumpClassifications == 1 && f.runtime.counters.managementCalls == 1);
      RS2_CHECK(f.queries > 0 && !f.Revoked(Reason::UnknownAncestry) && !f.Revoked(Reason::TruncatedStack));
      RS2_CHECK(f.runtime.pumpDepth == 0 && f.runtime.counters.fullSelected == 0); }
    { Fixture f; if (!f.live) return;
      RS2_CHECK(BuilderEngine(BuilderOracle, f.holder));
      auto& ancestry = f.runtime.config.ancestry;
      ancestry.builderAdapterReturn = g_builderReturns[0]; ancestry.taskDispatchReturn = g_builderReturns[1];
      ancestry.taskPumpReturn = g_builderReturns[2];
      ancestry.leechUpdateReturns[0] = ancestry.leechUpdateReturns[1] = g_builderReturns[3];
      ancestry.leechTickReturns[0] = ancestry.leechTickReturns[1] = g_builderReturns[4];
      ancestry.subsystemReturn = g_builderReturns[5];
      ancestry.worldReturns[0] = ancestry.worldReturns[1] = g_builderReturns[6]; ancestry.engineReturn = g_builderReturns[7];
      f.Ready(); InterlockedExchange(&f.runtime.task.phase, static_cast<LONG>(TaskPhase::Armed));
      f.outcome = Outcome::False; f.ClearProbes();
      SetLastError(kIncoming); const bool result = BuilderEngine(BuilderEntry, f.holder); const DWORD outgoing = GetLastError();
      RS2_CHECK(!result && outgoing == kOutgoing && f.builderCalls == 1 && f.argumentErrors == 0);
      RS2_CHECK(f.runtime.counters.normalBuilderClassifications == 1 && f.runtime.counters.normalAttempts == 1);
      RS2_CHECK(f.queries > 0 && !f.Revoked(Reason::UnknownAncestry) && !f.Revoked(Reason::TruncatedStack));
      RS2_CHECK(f.runtime.builderDepth == 0 && f.runtime.counters.fullSelected == 0); }
}
void OnePublicationLagAndFinalFailures() {
    for (const bool builder : {false, true}) {
        Fixture f; if (!f.live) continue;
        const std::size_t kind = builder ? 2U : 0U;
        // No Init means genuine forwarding without native source reads. This
        // still traverses the actual End publication/accounting/LastError path.
        for (std::uint64_t invocation = 1; invocation <= 3; ++invocation) {
            auto expected = f.runtime.counters.durations[kind];
            const auto pending=f.runtime.pendingDuration;
            if (pending.valid) RS2_CHECK(AccountDuration(expected,pending.ticks,f.runtime.producer.frequency));
            const auto sequence = ReadStatusWord(f.status.ownerSequence);
            SetLastError(kIncoming);
            const bool result = builder ? BuilderEntry(f.holder) : (PumpEntry(), true);
            const auto outgoing = GetLastError();
            StatusHeader header{}; StatusPayload published{};
            RS2_CHECK(result && outgoing == kOutgoing && f.argumentErrors == 0);
            RS2_CHECK(ReadLocalStatus(f.status, &header, &published));
            RS2_CHECK(published.durations[kind].calls == invocation - 1);
            RS2_CHECK(std::memcmp(&published.durations[kind], &expected, sizeof(expected)) == 0);
            RS2_CHECK(f.runtime.counters.durations[kind].calls == invocation-1);
            RS2_CHECK(f.runtime.pendingDuration.valid && f.runtime.pendingDuration.topLevel);
            RS2_CHECK(published.timingAccountedThroughQpc==(pending.valid ? static_cast<std::uint64_t>(pending.entryQpc) : 0));
            RS2_CHECK(ReadStatusWord(f.status.ownerSequence) == sequence + 2);
            // Another read is not an accessor that flushes private timing state.
            StatusHeader againHeader{}; StatusPayload again{};
            RS2_CHECK(ReadLocalStatus(f.status, &againHeader, &again));
            RS2_CHECK(std::memcmp(&published, &again, sizeof(again)) == 0);
            RS2_CHECK(f.runtime.pumpDepth == 0 && f.runtime.builderDepth == 0 && f.queries == 0 && f.reads == 0);
        }
        RS2_CHECK((builder ? f.builderCalls : f.pumpCalls) == 3);
    }
    for (const bool builder : {false, true}) {
        Fixture f; if (!f.live) continue;
        const std::size_t kind = builder ? 2U : 0U;
        f.breakFinalClock = true;
        const auto sequence = ReadStatusWord(f.status.ownerSequence);
        SetLastError(kIncoming);
        const bool result = builder ? BuilderEntry(f.holder) : (PumpEntry(), true);
        const auto outgoing = GetLastError();
        RS2_CHECK(result && outgoing == kOutgoing && f.argumentErrors == 0 && f.Revoked(Reason::ClockFailed));
        RS2_CHECK(ReadStatusWord(f.status.ownerSequence) == sequence);
        RS2_CHECK(ReadStatusWord(f.status.owner.durations[kind].calls) == 0 && f.runtime.counters.durations[kind].calls == 0);
        RS2_CHECK((builder ? f.builderCalls : f.pumpCalls) == 1 && f.runtime.pumpDepth == 0 && f.runtime.builderDepth == 0);
    }
    for (const bool builder : {false, true}) {
        Fixture f; if (!f.live) continue;
        const std::size_t kind = builder ? 2U : 0U;
        f.runtime.counters.durations[kind].calls = (std::numeric_limits<std::uint64_t>::max)();
        const auto prior = f.runtime.counters.durations[kind];
        const auto sequence = ReadStatusWord(f.status.ownerSequence);
        SetLastError(kIncoming);
        const bool result = builder ? BuilderEntry(f.holder) : (PumpEntry(), true);
        const auto outgoing = GetLastError();
        // Staging overflow fails AFTER the only full publication. Its sticky
        // fault must nevertheless be externally visible without another call.
        RS2_CHECK(result && outgoing == kOutgoing && f.argumentErrors == 0 && f.Revoked(Reason::CounterOverflow));
        RS2_CHECK(ReadStatusWord(f.status.ownerSequence) == sequence + 2);
        RS2_CHECK(std::memcmp(&f.runtime.counters.durations[kind], &prior, sizeof(prior)) == 0);
        RS2_CHECK(ReadStatusWord(f.status.owner.durations[kind].calls) == prior.calls);
        StatusHeader header{}; StatusPayload published{};
        RS2_CHECK(!ReadLocalStatus(f.status, &header, &published));
        RS2_CHECK((builder ? f.builderCalls : f.pumpCalls) == 1 && f.runtime.pumpDepth == 0 && f.runtime.builderDepth == 0);
    }
}
void AdaptiveManagementCadence() {
    const auto ready=[](Fixture& f,Mode mode) {
        PumpEngine(PumpOracle);
        auto& ancestry=f.runtime.config.ancestry;
        ancestry.callbackReturn=g_pumpReturns[0];
        ancestry.worldReturns[0]=ancestry.worldReturns[1]=g_pumpReturns[1];
        ancestry.engineReturn=g_pumpReturns[2];
        f.Ready(); f.runtime.config.mode=mode; f.runtime.producer.mode=mode;
        f.runtime.sourceReady=true; f.runtime.producer.epochReady=true;
        InterlockedExchange(&f.runtime.task.phase,static_cast<LONG>(TaskPhase::Armed));
        f.ClearProbes();
    };
    const auto elapsedQuarters=[](Fixture& f,unsigned quarters) {
        LARGE_INTEGER now{}; RS2_CHECK(QueryPerformanceCounter(&now));
        f.runtime.lastManagement=now.QuadPart-f.runtime.producer.frequency*quarters/4;
        f.runtime.haveManagement=true;
    };
    const auto pump=[](Fixture& f) {
        SetLastError(kIncoming); PumpEngine(PumpEntry); const auto outgoing=GetLastError();
        RS2_CHECK(outgoing==kOutgoing && f.argumentErrors==0 && f.runtime.pumpDepth==0);
    };
    for(const auto mode:{Mode::Observe,Mode::Repair}) {
        Fixture f; if(!f.live) continue; ready(f,mode);
        // Real wrapper/caller classification, without sleeping or native data.
        // 750ms is past the fast floor but safely inside the stable-idle floor.
        elapsedQuarters(f,3); pump(f);
        RS2_CHECK(f.pumpCalls==1 && f.queries==0 && f.reads==0 && f.runtime.counters.managementCalls==0);
        elapsedQuarters(f,9); pump(f);
        RS2_CHECK(f.pumpCalls==2 && f.queries>0 && f.runtime.counters.managementCalls==1);
        RS2_CHECK(!f.Revoked(Reason::UnknownAncestry) && !f.Revoked(Reason::TruncatedStack));
    }
    // Each change must leave the slow lane immediately; the prior skipped
    // call cannot delay pending observation, reacquisition or fault retirement.
    for(unsigned transition=0;transition<5;++transition) {
        Fixture f; if(!f.live) continue; ready(f,Mode::Repair);
        elapsedQuarters(f,3); pump(f);
        RS2_CHECK(f.queries==0 && f.runtime.counters.managementCalls==0);
        if(transition==0) f.runtime.producer.pending.active=true;
        else if(transition==1) f.runtime.sourceReady=false;
        else if(transition==2) f.runtime.producer.epochReady=false;
        else if(transition==3) InterlockedExchange(&f.runtime.task.phase,static_cast<LONG>(TaskPhase::Retired));
        else {
            // Fake identity is never dereferenced: MemoryOps rejects all native
            // reads. Reaching Inert proves cleanup was not left in the idle lane.
            f.runtime.task.haveIdentity=true;
            RevokeStatus(f.status,Reason::RecordLoss);
        }
        pump(f);
        RS2_CHECK(f.pumpCalls==2);
        if(transition==4) RS2_CHECK(ReadTaskPhase(f.runtime.task)==TaskPhase::Inert);
        else RS2_CHECK(f.queries>0 && f.runtime.counters.managementCalls==1);
    }
    { Fixture f; if(!f.live) return; ready(f,Mode::Repair);
      f.runtime.producer.pending.active=true; elapsedQuarters(f,0); pump(f);
      RS2_CHECK(f.pumpCalls==1 && f.queries==0 && f.runtime.counters.managementCalls==0); }
}
void NestedIntervalsAccountOnceWithLag() {
    for (const bool builder : {false, true}) {
        Fixture f; if (!f.live) continue;
        f.nested = true;
        const std::size_t kind = builder ? 2U : 0U;
        const auto sequence = ReadStatusWord(f.status.ownerSequence);
        SetLastError(kIncoming);
        const bool result = builder ? BuilderEntry(f.holder) : (PumpEntry(), true);
        const auto outgoing = GetLastError();
        RS2_CHECK(result && outgoing == kOutgoing && f.argumentErrors == 0 && f.Revoked(Reason::Reentry));
        RS2_CHECK((builder ? f.builderCalls : f.pumpCalls) == 2);
        RS2_CHECK(f.runtime.counters.durations[kind].calls == 1 && f.runtime.pendingDuration.valid);
        RS2_CHECK(ReadStatusWord(f.status.owner.durations[kind].calls) == 1);
        RS2_CHECK(ReadStatusWord(f.status.ownerSequence) == sequence + 4);
        auto two = f.runtime.counters.durations[kind];
        RS2_CHECK(AccountDuration(two,f.runtime.pendingDuration.ticks,f.runtime.producer.frequency));
        SetLastError(kIncoming);
        const bool later = builder ? BuilderEntry(f.holder) : (PumpEntry(), true);
        RS2_CHECK(later && GetLastError() == kOutgoing && f.argumentErrors == 0);
        RS2_CHECK((builder ? f.builderCalls : f.pumpCalls) == 3 && f.runtime.counters.durations[kind].calls == 2);
        RS2_CHECK(ReadStatusWord(f.status.owner.durations[kind].calls) == 2);
        RS2_CHECK(ReadStatusWord(f.status.owner.durations[kind].elapsedTicks) == two.elapsedTicks);
        RS2_CHECK(ReadStatusWord(f.status.ownerSequence) == sequence + 6);
        RS2_CHECK(f.runtime.pumpDepth == 0 && f.runtime.builderDepth == 0 && f.queries == 0 && f.reads == 0);
    }
}
void CompletedRootCutoff() {
    for (const bool builder : {false,true}) {
        Fixture f; if (!f.live) continue;
        const auto invoke=[&] {
            SetLastError(kIncoming);
            const bool result=builder ? BuilderEntry(f.holder) : (PumpEntry(),true);
            RS2_CHECK(result && GetLastError()==kOutgoing && f.argumentErrors==0);
            RS2_CHECK(f.runtime.timingDepth==0 && f.runtime.pumpDepth==0 && f.runtime.builderDepth==0);
        };
        invoke();
        const auto first=static_cast<std::uint64_t>(f.runtime.pendingDuration.entryQpc);
        RS2_CHECK(first>0 && f.runtime.pendingDuration.valid && f.runtime.counters.timingAccountedThroughQpc==0);
        RS2_CHECK(ReadStatusWord(f.status.owner.timingAccountedThroughQpc)==0);
        f.nested=true; f.crossNested=true;
        invoke();
        // A child completes/publishes while its parent's native interval is
        // unfinished. Neither its commit nor publication may move the cutoff.
        RS2_CHECK(f.nestedPrivateCutoff==first && f.nestedPublishedCutoff==first);
        const auto parent=static_cast<std::uint64_t>(f.runtime.pendingDuration.entryQpc);
        RS2_CHECK(parent>=first && f.runtime.pendingDuration.valid && f.runtime.pendingDuration.topLevel);
        RS2_CHECK(f.runtime.counters.timingAccountedThroughQpc==first && ReadStatusWord(f.status.owner.timingAccountedThroughQpc)==first);
        RS2_CHECK(f.pumpCalls==(builder ? 1 : 2) && f.builderCalls==(builder ? 2 : 1));
        RS2_CHECK(!f.runtime.timingGap && !StatusRevoked(f.status));
        f.nested=false;
        invoke();
        RS2_CHECK(ReadStatusWord(f.status.owner.timingAccountedThroughQpc)==parent);
    }
    { Fixture f; if (!f.live) return;
      SetLastError(kIncoming); PumpEntry();
      SetLastError(kIncoming); PumpEntry();
      const auto cutoff=f.runtime.counters.timingAccountedThroughQpc;
      const auto calls=f.runtime.counters.durations[0].calls;
      const auto retained=f.runtime.pendingDuration;
      f.runtime.haveClock=true; f.runtime.lastClock=INT64_MAX;
      SetLastError(kIncoming); PumpEntry();
      RS2_CHECK(GetLastError()==kOutgoing && f.runtime.timingGap && f.Revoked(Reason::ClockFailed));
      f.runtime.lastClock=0; // Later good clocks must not recover a lost interval.
      SetLastError(kIncoming); PumpEntry();
      RS2_CHECK(GetLastError()==kOutgoing && f.runtime.timingGap && f.pumpCalls==4);
      RS2_CHECK(f.runtime.pendingDuration.valid && f.runtime.pendingDuration.entryQpc==retained.entryQpc);
      RS2_CHECK(f.runtime.counters.timingAccountedThroughQpc==cutoff && f.runtime.counters.durations[0].calls==calls); }
}
void PendingAccountingFailuresAndLifecycle() {
    // A final wrapper can have no successor. Only a real owner lifecycle
    // publication may consume it; status reads themselves never do so.
    for (const bool shutdown : {false,true}) {
        Fixture f; if (!f.live) continue;
        SetLastError(kIncoming); PumpEntry();
        const auto final=f.runtime.pendingDuration;
        RS2_CHECK(final.valid && f.runtime.counters.durations[0].calls==0);
        if (shutdown) {
            const auto sink=RuntimeLifecycleSink(f.runtime);
            sink.shutdownEntered(sink.context,kIdle);
        } else f.Ready();
        RS2_CHECK(!f.runtime.timingGap && !f.runtime.pendingDuration.valid);
        RS2_CHECK(f.runtime.counters.durations[0].calls==1 &&
            f.runtime.counters.timingAccountedThroughQpc==static_cast<std::uint64_t>(final.entryQpc));
        std::int64_t now{}; RS2_CHECK(RuntimeClock(f.runtime,&now));
        PublishRuntimeStatus(f.runtime,now,false);
        RS2_CHECK(f.runtime.counters.durations[0].calls==1); // Never account twice.
    }
    // Deliberately broken private counter state simulates consume failure after
    // a sample was staged. Preserve A, discard later B and prohibit every retry.
    { Fixture f; if (!f.live) return;
      SetLastError(kIncoming); PumpEntry();
      const auto pending=f.runtime.pendingDuration;
      f.runtime.counters.durations[0].calls=UINT64_MAX;
      SetLastError(kIncoming); PumpEntry();
      RS2_CHECK(GetLastError()==kOutgoing && f.pumpCalls==2 && f.runtime.timingGap);
      RS2_CHECK(f.Revoked(Reason::CounterOverflow) && f.runtime.pendingDuration.valid &&
          f.runtime.pendingDuration.entryQpc==pending.entryQpc);
      f.runtime.counters.durations[0]={}; // Even a now-consumable A stays frozen.
      SetLastError(kIncoming); PumpEntry();
      const auto sink=RuntimeLifecycleSink(f.runtime); sink.shutdownEntered(sink.context,kIdle);
      RS2_CHECK(f.pumpCalls==3 && f.runtime.pendingDuration.valid && f.runtime.timingGap);
      RS2_CHECK(f.runtime.counters.durations[0].calls==0 && f.runtime.counters.timingAccountedThroughQpc==0);
      RS2_CHECK(f.runtime.pendingDuration.entryQpc==pending.entryQpc); }
    // A single slot cannot retain two completed calls. Conflict is an immediate
    // permanent gap, not a replacement of the previous unaccounted sample.
    { Fixture f; if (!f.live) return;
      SetLastError(kIncoming); PumpEntry();
      const auto pending=f.runtime.pendingDuration;
      RS2_CHECK(!StageRuntimeDuration(f.runtime,DurationClass::PumpForward,1,pending.entryQpc,true));
      RS2_CHECK(f.runtime.timingGap && f.Revoked(Reason::Reentry) && f.runtime.pendingDuration.valid);
      RS2_CHECK(f.runtime.pendingDuration.ticks==pending.ticks && f.runtime.pendingDuration.entryQpc==pending.entryQpc);
      RS2_CHECK(!ConsumeRuntimeDuration(f.runtime) && f.runtime.counters.durations[0].calls==0); }
    // Overflow at staging must be visible even if no further call arrives.
    for (const bool badFrequency : {false,true}) {
        Fixture f; if (!f.live) continue;
        std::int64_t now{}; RS2_CHECK(RuntimeClock(f.runtime,&now));
        if (badFrequency) f.runtime.producer.frequency=0;
        else f.runtime.counters.durations[0].elapsedTicks=UINT64_MAX;
        RS2_CHECK(!StageRuntimeDuration(f.runtime,DurationClass::PumpForward,1,now,true));
        RS2_CHECK(f.runtime.timingGap && f.Revoked(Reason::CounterOverflow) && !f.runtime.pendingDuration.valid);
        RS2_CHECK(f.runtime.counters.timingAccountedThroughQpc==0);
    }
    // Foreign shutdown can set sticky stopping only, never drain owner storage.
    { Fixture f; if (!f.live) return;
      SetLastError(kIncoming); PumpEntry();
      const auto before=f.runtime.pendingDuration;
      const auto cutoff=f.runtime.counters.timingAccountedThroughQpc;
      std::thread foreign([&] {
          RS2_CHECK(!ConsumeRuntimeDuration(f.runtime));
          RS2_CHECK(!StageRuntimeDuration(f.runtime,DurationClass::PumpForward,1,before.entryQpc,true));
          const auto sink=RuntimeLifecycleSink(f.runtime); sink.shutdownEntered(sink.context,kIdle);
      }); foreign.join();
      RS2_CHECK(f.runtime.pendingDuration.valid && f.runtime.pendingDuration.entryQpc==before.entryQpc);
      RS2_CHECK(!f.runtime.timingGap && f.runtime.counters.timingAccountedThroughQpc==cutoff &&
          f.runtime.counters.durations[0].calls==0 && f.Revoked(Reason::ForeignThread)); }
}
} // namespace

void ReportingForwardTests() {
    TransparentAndInactive();
    GenuineUnwindAndNestedDepth();
    ForeignForwardsOnly();
    ActualNormalCapture();
    OnePublicationLagAndFinalFailures();
    AdaptiveManagementCadence();
    NestedIntervalsAccountOnceWithLag();
    CompletedRootCutoff();
    PendingAccountingFailuresAndLifecycle();
}
