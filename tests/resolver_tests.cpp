#include "bootstrap/genuine_resolver.h"
#include "bootstrap/forwarder.h"
#include "test_framework.h"
#include <array>
#include <atomic>
#include <cstring>
#include <cstdlib>
#include <cwchar>

namespace rs2fix::testcases {
namespace {
constexpr DWORD kApiError = 2468;
HMODULE Module(std::uintptr_t value) noexcept { return reinterpret_cast<HMODULE>(value); }
struct CallCapture {
    UINT32 mask{}, flags{};
    FLOAT speed{};
    BYTE* instance{};
    const void* listener{};
    const void* emitter{};
    void* settings{};
    unsigned initializes{}, calculates{};
    bool throwCalculate{};
};
thread_local CallCapture* g_capture{};
void WINAPI InitializeStub(UINT32 mask, FLOAT speed, BYTE* instance) {
    if (g_capture != nullptr) {
        ++g_capture->initializes; g_capture->mask = mask;
        g_capture->speed = speed; g_capture->instance = instance;
    }
    if (instance != nullptr) for (unsigned i = 0; i < kX3AudioHandleBytes; ++i) instance[i] = static_cast<BYTE>(i + 1);
}
void WINAPI CalculateStub(const BYTE* instance, const void* listener,
    const void* emitter, UINT32 flags, void* settings) {
    if (g_capture != nullptr) {
        ++g_capture->calculates; g_capture->instance = const_cast<BYTE*>(instance);
        g_capture->listener = listener; g_capture->emitter = emitter;
        g_capture->flags = flags; g_capture->settings = settings;
        if (g_capture->throwCalculate) throw 73;
    }
    if (settings != nullptr) *static_cast<DWORD*>(settings) = 0xAABBCCDD;
}
X3AudioDispatch Dispatch() noexcept {
    return {Module(2), InitializeStub, CalculateStub, GenuineResolverStatus::Ok, 0};
}
struct ResolverFake {
    GenuineResolverStatus failure{GenuineResolverStatus::Ok};
    bool expectedIdentityFailure{};
    bool failAsyncBegin{};
    bool rejectComplete{};
    bool failAllocation{};
    bool injectNormalOnComplete{};
    bool injectNormalOnAllocate{};
    bool injectNormalOnFailure{};
    bool yieldLoad{};
    unsigned recoverAfterAttempts{};
    GenuineResolverState* state{};
    alignas(8) X3AudioDispatch injectedWinner{Dispatch()};
    std::atomic<unsigned> attempts{}, loads{}, frees{}, allocations{}, freedRecords{}, completions{};
    std::array<std::atomic<void*>, 64> records{};
};
ResolverFake& F(void* context) noexcept { return *static_cast<ResolverFake*>(context); }
bool Failing(const ResolverFake& fake, GenuineResolverStatus status) noexcept {
    return fake.failure == status &&
        (fake.recoverAfterAttempts == 0 || fake.attempts.load() <= fake.recoverAfterAttempts);
}
void InjectNormal(ResolverFake& fake) noexcept {
    DWORD error = 0; BOOL pending = TRUE; void* old = nullptr;
    const auto& production = ProductionGenuineResolverOps();
    production.beginOnce(nullptr, &fake.state->normalOnce, INIT_ONCE_ASYNC, &pending, &old, &error);
    if (production.completeOnce(nullptr, &fake.state->normalOnce, INIT_ONCE_ASYNC,
            &fake.injectedWinner, &error)) ++fake.loads;
}
bool Build(void* context, wchar_t* output, std::size_t capacity, DWORD* error) noexcept {
    auto& fake = F(context); ++fake.attempts;
    if (Failing(fake, GenuineResolverStatus::SystemPathFailed) ||
        Failing(fake, GenuineResolverStatus::PathCapacityFailed)) {
        *error = fake.failure == GenuineResolverStatus::PathCapacityFailed ? ERROR_INSUFFICIENT_BUFFER : kApiError;
        if (fake.injectNormalOnFailure) InjectNormal(fake);
        return false;
    }
    wcscpy_s(output, capacity, L"expected"); *error = 0; return true;
}
HMODULE Load(void* context, const wchar_t*, DWORD* error) noexcept {
    auto& fake = F(context);
    if (Failing(fake, GenuineResolverStatus::LoadFailed)) { *error = kApiError; return nullptr; }
    ++fake.loads;
    if (fake.yieldLoad) Sleep(1);
    *error = 0;
    return fake.failure == GenuineResolverStatus::SelfModule ? Module(1) : Module(2);
}
bool Path(void* context, HMODULE, wchar_t* output, std::size_t capacity, DWORD* error) noexcept {
    if (Failing(F(context), GenuineResolverStatus::CandidatePathFailed)) { *error = kApiError; return false; }
    wcscpy_s(output, capacity, L"actual"); *error = 0; return true;
}
bool Identity(void* context, const wchar_t* path, FileIdentity* identity, DWORD* error) noexcept {
    auto& fake = F(context); const bool expected = path[0] == L'e';
    if (Failing(fake, GenuineResolverStatus::FileIdentityFailed) && expected == fake.expectedIdentityFailure) {
        *error = kApiError; return false;
    }
    *identity = {1, 2, !expected && fake.failure == GenuineResolverStatus::WrongFile ? 4u : 3u, true};
    *error = 0; return true;
}
FARPROC Export(void* context, HMODULE, const char* name, DWORD* error) noexcept {
    const bool initialize = std::strcmp(name, "X3DAudioInitialize") == 0;
    if (Failing(F(context), initialize ? GenuineResolverStatus::InitializeExportMissing :
            GenuineResolverStatus::CalculateExportMissing)) { *error = kApiError; return nullptr; }
    *error = 0;
    return initialize ? reinterpret_cast<FARPROC>(InitializeStub) : reinterpret_cast<FARPROC>(CalculateStub);
}
bool Query(void* context, FARPROC function, const void** base, DWORD* error) noexcept {
    auto& fake = F(context);
    const bool initialize = function == reinterpret_cast<FARPROC>(InitializeStub);
    if (Failing(fake, initialize ? GenuineResolverStatus::InitializeAddressQueryFailed :
            GenuineResolverStatus::CalculateAddressQueryFailed)) { *error = kApiError; return false; }
    *base = Failing(fake, initialize ? GenuineResolverStatus::InitializeWrongAllocationBase :
        GenuineResolverStatus::CalculateWrongAllocationBase) ? Module(1) : Module(2);
    *error = 0; return true;
}
bool Free(void* context, HMODULE) noexcept { ++F(context).frees; return true; }
void* Allocate(void* context) noexcept {
    auto& fake = F(context);
    if (fake.injectNormalOnAllocate) { InjectNormal(fake); return nullptr; }
    if (fake.failAllocation) return nullptr;
    const unsigned slot = fake.allocations.fetch_add(1);
    if (slot >= fake.records.size()) return nullptr;
    void* record = VirtualAlloc(nullptr, sizeof(X3AudioDispatch), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    fake.records[slot].store(record);
    return record;
}
bool FreeRecord(void* context, void* record) noexcept {
    auto& fake = F(context);
    for (auto& slot : fake.records) {
        void* expected = record;
        if (slot.compare_exchange_strong(expected, nullptr)) {
            ++fake.freedRecords;
            return VirtualFree(record, 0, MEM_RELEASE) != FALSE;
        }
    }
    return false;
}
bool Begin(void* context, INIT_ONCE* once, DWORD flags, BOOL* pending,
    void** value, DWORD* error) noexcept {
    if (F(context).failAsyncBegin && flags == INIT_ONCE_ASYNC) { *error = kApiError; return false; }
    return ProductionGenuineResolverOps().beginOnce(nullptr, once, flags, pending, value, error);
}
bool Complete(void* context, INIT_ONCE* once, DWORD flags, void* value, DWORD* error) noexcept {
    auto& fake = F(context);
    if (fake.injectNormalOnComplete && value != &fake.state->fallback) {
        InjectNormal(fake); *error = kApiError; return false;
    }
    if (fake.rejectComplete) { *error = kApiError; return false; }
    const bool result = ProductionGenuineResolverOps().completeOnce(nullptr, once, flags, value, error);
    if (result) ++fake.completions;
    return result;
}
GenuineResolverOps Ops(ResolverFake& fake) noexcept {
    return {&fake, Build, Load, Path, Identity, Export, Query, Free, Allocate, FreeRecord, Begin, Complete};
}
void Cleanup(ResolverFake& fake) {
    for (auto& slot : fake.records) {
        void* record = slot.exchange(nullptr);
        if (record != nullptr) RS2_CHECK(VirtualFree(record, 0, MEM_RELEASE));
    }
}
void TestPrivate() {
    for (GenuineResolverStatus status : {GenuineResolverStatus::SystemPathFailed,
        GenuineResolverStatus::PathCapacityFailed, GenuineResolverStatus::LoadFailed,
        GenuineResolverStatus::SelfModule, GenuineResolverStatus::CandidatePathFailed,
        GenuineResolverStatus::FileIdentityFailed, GenuineResolverStatus::WrongFile,
        GenuineResolverStatus::InitializeExportMissing, GenuineResolverStatus::CalculateExportMissing,
        GenuineResolverStatus::InitializeAddressQueryFailed, GenuineResolverStatus::CalculateAddressQueryFailed,
        GenuineResolverStatus::InitializeWrongAllocationBase, GenuineResolverStatus::CalculateWrongAllocationBase}) {
        ResolverFake fake{}; fake.failure = status;
        auto result = ResolveGenuineX3AudioPrivate(Module(1), Ops(fake));
        RS2_CHECK(result.dispatch.status == status && !result.ownsModule);
        RS2_CHECK(result.dispatch.module == nullptr && result.dispatch.initialize == nullptr && result.dispatch.calculate == nullptr);
        const bool resourceFailure = status == GenuineResolverStatus::SystemPathFailed ||
            status == GenuineResolverStatus::PathCapacityFailed || status == GenuineResolverStatus::LoadFailed ||
            status == GenuineResolverStatus::CandidatePathFailed || status == GenuineResolverStatus::FileIdentityFailed;
        RS2_CHECK(result.failureClass == (resourceFailure ? GenuineFailureClass::ResourceApi : GenuineFailureClass::Validation));
        const bool dataFailure = status == GenuineResolverStatus::SelfModule ||
            status == GenuineResolverStatus::WrongFile || status == GenuineResolverStatus::InitializeWrongAllocationBase ||
            status == GenuineResolverStatus::CalculateWrongAllocationBase;
        RS2_CHECK(result.dispatch.win32Error == (status == GenuineResolverStatus::PathCapacityFailed
            ? ERROR_INSUFFICIENT_BUFFER : dataFailure ? ERROR_INVALID_DATA : kApiError));
        RS2_CHECK(fake.frees == (status <= GenuineResolverStatus::SelfModule ? 0u : 1u));
    }
    ResolverFake fake{}; fake.failure = GenuineResolverStatus::FileIdentityFailed; fake.expectedIdentityFailure = true;
    RS2_CHECK(ResolveGenuineX3AudioPrivate(Module(1), Ops(fake)).dispatch.status == GenuineResolverStatus::FileIdentityFailed);
    RS2_CHECK(fake.frees == 1);
    ResolverFake success{};
    auto result = ResolveGenuineX3AudioPrivate(Module(1), Ops(success));
    RS2_CHECK(result.ownsModule && IsCompleteDispatch(result.dispatch));
    RS2_CHECK(result.failureClass == GenuineFailureClass::None && success.loads == 1 && success.frees == 0);
    const FileIdentity identity{1, 2, 3, true};
    const auto init = reinterpret_cast<FARPROC>(InitializeStub);
    const auto calc = reinterpret_cast<FARPROC>(CalculateStub);
    RS2_CHECK(ValidateGenuineEvidence(Module(1), Module(2), identity, identity,
        init, calc, true, true, Module(2), Module(2)) == GenuineResolverStatus::Ok);
    RS2_CHECK(ValidateGenuineEvidence(Module(1), Module(2), identity, {},
        init, calc, true, true, Module(2), Module(2)) == GenuineResolverStatus::FileIdentityFailed);
    RS2_CHECK(ValidateGenuineEvidence(Module(1), Module(2), {}, identity,
        init, calc, true, true, Module(2), Module(2)) == GenuineResolverStatus::FileIdentityFailed);
}

void TestPublication() {
    for (unsigned scenario = 0; scenario < 7; ++scenario) {
        GenuineResolverState state{}; ResolverFake fake{}; fake.state = &state;
        fake.rejectComplete = scenario == 1;
        fake.failAllocation = scenario == 2 || scenario == 4;
        fake.failAsyncBegin = scenario == 3;
        fake.injectNormalOnComplete = scenario == 5;
        fake.injectNormalOnAllocate = scenario == 6;
        if (scenario == 4) state.fallbackState = static_cast<LONG>(FallbackState::Writing);
        const auto ops = Ops(fake);
        auto first = AcquireGenuineX3Audio(&state, Module(1), ops);
        RS2_CHECK(first.valid && IsCompleteDispatch(first.dispatch));
        RS2_CHECK(first.releaseModuleOnClose == (scenario == 4));
        RS2_CHECK(reinterpret_cast<std::uintptr_t>(&state.fallback) % kDispatchAlignment == 0);
        ReleaseGenuineX3AudioLease(&first, ops);
        RS2_CHECK(!first.valid && first.dispatch.module == nullptr);
        const unsigned beforeLoads = fake.loads;
        if (scenario != 4) {
            auto next = AcquireGenuineX3Audio(&state, Module(1), ops);
            RS2_CHECK(next.valid && !next.releaseModuleOnClose && fake.loads == beforeLoads);
            ReleaseGenuineX3AudioLease(&next, ops);
            RS2_CHECK(fake.loads - fake.frees <= 2);
        } else {
            RS2_CHECK(fake.frees == 1 && state.fallback.module == nullptr);
            ReleaseGenuineX3AudioLease(&first, ops);
            RS2_CHECK(fake.frees == 1);
        }
        if (scenario == 1) {
            RS2_CHECK(state.fallbackState == static_cast<LONG>(FallbackState::Ready));
            RS2_CHECK(fake.freedRecords == 1 && fake.completions == 0);
        }
        if (scenario == 5) RS2_CHECK(fake.freedRecords == 1 && fake.frees == 1);
        if (scenario == 6) RS2_CHECK(fake.frees == 1 && state.fallbackState == 0);
        Cleanup(fake);
    }
    // Readers ignore Empty/Writing records even if their payload appears complete.
    GenuineResolverState state{}; state.fallback = Dispatch();
    X3AudioDispatch output{};
    RS2_CHECK(!TryGetReadyFallback(&state, &output));
    state.fallbackState = static_cast<LONG>(FallbackState::Writing);
    RS2_CHECK(!TryGetReadyFallback(&state, &output));
    InterlockedExchange(&state.fallbackState, static_cast<LONG>(FallbackState::Ready));
    ResolverFake ready{}; ready.state = &state;
    auto lease = AcquireGenuineX3Audio(&state, Module(1), Ops(ready));
    RS2_CHECK(lease.valid && ready.attempts == 0 && ready.loads == 0);
    // A private loser releases its reference when a Ready fallback already exists.
    GenuineResolverResult privateResult{Dispatch(), GenuineFailureClass::None, true};
    auto loser = PublishPrivateSuccess(&state, static_cast<GenuineResolverResult&&>(privateResult), false, TRUE, Ops(ready));
    RS2_CHECK(loser.valid && !loser.releaseModuleOnClose && ready.frees == 1);
}

void TestRetriesAndCalls() {
    for (GenuineResolverStatus status : {GenuineResolverStatus::LoadFailed, GenuineResolverStatus::WrongFile}) {
        GenuineResolverState state{}; ResolverFake fake{}; fake.failure = status; fake.state = &state;
        auto lease = AcquireGenuineX3Audio(&state, Module(1), Ops(fake));
        RS2_CHECK(!lease.valid && lease.dispatch.status == status);
        RS2_CHECK(fake.attempts == (status == GenuineResolverStatus::LoadFailed ? 2u : 1u));
        fake.failure = GenuineResolverStatus::Ok;
        auto retry = AcquireGenuineX3Audio(&state, Module(1), Ops(fake));
        RS2_CHECK(retry.valid); Cleanup(fake);
    }
    GenuineResolverState recoveredState{}; ResolverFake recovered{}; recovered.state = &recoveredState;
    recovered.failure = GenuineResolverStatus::LoadFailed; recovered.recoverAfterAttempts = 1;
    RS2_CHECK(AcquireGenuineX3Audio(&recoveredState, Module(1), Ops(recovered)).valid);
    RS2_CHECK(recovered.attempts == 2); Cleanup(recovered);
    GenuineResolverState appearedState{}; ResolverFake appeared{}; appeared.state = &appearedState;
    appeared.failure = GenuineResolverStatus::SystemPathFailed; appeared.injectNormalOnFailure = true;
    RS2_CHECK(AcquireGenuineX3Audio(&appearedState, Module(1), Ops(appeared)).valid);
    RS2_CHECK(appeared.attempts == 1);

    GenuineResolverState state{}; ResolverFake fake{}; fake.state = &state;
    CallCapture capture{}; g_capture = &capture;
    BYTE instance[kX3AudioHandleBytes]{}; DWORD settings = 0; const BYTE listener = 8, emitter = 9;
    auto lease = AcquireGenuineX3Audio(&state, Module(1), Ops(fake));
    RS2_CHECK(lease.valid);
    lease.dispatch.initialize(0xDEADBEEF, 343.125f, instance);
    ReleaseGenuineX3AudioLease(&lease, Ops(fake));
    RS2_CHECK(capture.initializes == 1 && capture.mask == 0xDEADBEEF && capture.speed == 343.125f);
    for (unsigned i = 0; i < kX3AudioHandleBytes; ++i) RS2_CHECK(instance[i] == i + 1);
    RS2_CHECK(TryForwardCalculate(&state, Module(1), Ops(fake), instance, &listener, &emitter, 0x11223344, &settings));
    RS2_CHECK(capture.calculates == 1 && capture.instance == instance && capture.listener == &listener &&
        capture.emitter == &emitter && capture.flags == 0x11223344 && capture.settings == &settings);
    RS2_CHECK(settings == 0xAABBCCDD);
    capture.throwCalculate = true;
    bool caught = false;
    try { TryForwardCalculate(&state, Module(1), Ops(fake), instance, &listener, &emitter, 0, &settings); }
    catch (int value) { caught = value == 73; }
    RS2_CHECK(caught);
    g_capture = nullptr; Cleanup(fake);
}

struct ThreadInput { GenuineResolverState* state; GenuineResolverOps ops; HANDLE start; std::atomic<unsigned>* failures; };
DWORD WINAPI AcquireThread(void* argument) {
    auto& input = *static_cast<ThreadInput*>(argument);
    if (WaitForSingleObject(input.start, 2000) != WAIT_OBJECT_0) { ++*input.failures; return 1; }
    for (unsigned i = 0; i < 20; ++i) {
        auto lease = AcquireGenuineX3Audio(input.state, Module(1), input.ops);
        if (!lease.valid || !IsCompleteDispatch(lease.dispatch)) ++*input.failures;
        ReleaseGenuineX3AudioLease(&lease, input.ops);
    }
    return 0;
}
void TestConcurrency() {
    GenuineResolverState state{}; ResolverFake fake{}; fake.state = &state; fake.yieldLoad = true;
    HANDLE start = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    RS2_CHECK(start != nullptr); if (start == nullptr) return;
    std::atomic<unsigned> failures{};
    ThreadInput input{&state, Ops(fake), start, &failures};
    std::array<HANDLE, 32> threads{};
    DWORD count = 0;
    for (auto& thread : threads) {
        thread = CreateThread(nullptr, 0, AcquireThread, &input, 0, nullptr);
        if (thread == nullptr) break;
        ++count;
    }
    RS2_CHECK(count == threads.size());
    const ULONGLONG begin = GetTickCount64();
    RS2_CHECK(SetEvent(start));
    if (count != 0) {
        const DWORD wait = WaitForMultipleObjects(count, threads.data(), TRUE, 2000);
        RS2_CHECK(wait == WAIT_OBJECT_0);
        // A failed own-code concurrency test must not return with stack state still in use.
        if (wait != WAIT_OBJECT_0) std::abort();
    }
    RS2_CHECK(GetTickCount64() - begin <= 2000);
    RS2_CHECK(failures == 0 && fake.completions == 1 && fake.loads - fake.frees <= 2);
    RS2_CHECK(state.fallbackState == 0 || state.fallbackState == static_cast<LONG>(FallbackState::Ready));
    for (HANDLE thread : threads) if (thread != nullptr) RS2_CHECK(CloseHandle(thread));
    RS2_CHECK(CloseHandle(start)); Cleanup(fake);
}
} // namespace
void RunResolverTests() { TestPrivate(); TestPublication(); TestRetriesAndCalls(); TestConcurrency(); }
} // namespace rs2fix::testcases
