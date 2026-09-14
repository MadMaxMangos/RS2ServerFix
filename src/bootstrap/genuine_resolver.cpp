#include "bootstrap/genuine_resolver.h"
#include "shared/thread_error_mode.h"
#include <new>

namespace rs2fix {
namespace {
bool BuildPath(void*, wchar_t* path, std::size_t capacity, DWORD* error) noexcept {
#ifdef RS2_TEST_SYSTEM_X3AUDIO_LEAF
    if (path == nullptr || capacity == 0 || capacity > MAXDWORD) {
        *error = ERROR_INVALID_PARAMETER; return false;
    }
    path[0] = L'\0';
    const UINT length = GetSystemDirectoryW(path, static_cast<UINT>(capacity));
    if (length == 0) { *error = GetLastError(); path[0] = L'\0'; return false; }
    if (length >= capacity) { *error = ERROR_INSUFFICIENT_BUFFER; path[0] = L'\0'; return false; }
    constexpr wchar_t leaf[] = RS2_TEST_SYSTEM_X3AUDIO_LEAF;
    return AppendPathLeaf(path, capacity, leaf, _countof(leaf), path, capacity, error);
#else
    return BuildSystemX3AudioPath(path, capacity, error);
#endif
}
HMODULE Load(void*, const wchar_t* path, DWORD* error) noexcept {
    return LoadLibraryWithThreadErrorMode(path, LOAD_LIBRARY_SEARCH_SYSTEM32,
        error, ProductionThreadErrorModeOps());
}
bool ModulePath(void*, HMODULE module, wchar_t* path, std::size_t capacity,
    DWORD* error) noexcept { return GetBoundedModulePath(module, path, capacity, error); }
bool Identity(void*, const wchar_t* path, FileIdentity* identity, DWORD* error) noexcept {
    return QueryFileIdentity(path, identity, error);
}
FARPROC Export(void*, HMODULE module, const char* name, DWORD* error) noexcept {
    FARPROC function = GetProcAddress(module, name);
    *error = function == nullptr ? GetLastError() : ERROR_SUCCESS;
    return function;
}
bool Address(void*, FARPROC function, const void** base, DWORD* error) noexcept {
    MEMORY_BASIC_INFORMATION memory{};
    if (VirtualQuery(reinterpret_cast<const void*>(function), &memory, sizeof(memory)) != sizeof(memory)) {
        *error = GetLastError(); *base = nullptr; return false;
    }
    *base = memory.AllocationBase; *error = ERROR_SUCCESS; return true;
}
bool ReleaseModule(void*, HMODULE module) noexcept { return FreeLibrary(module) != FALSE; }
void* Allocate(void*) noexcept {
    return VirtualAlloc(nullptr, sizeof(X3AudioDispatch), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}
bool FreeRecord(void*, void* record) noexcept { return VirtualFree(record, 0, MEM_RELEASE) != FALSE; }
bool Begin(void*, INIT_ONCE* once, DWORD flags, BOOL* pending, void** context,
    DWORD* error) noexcept {
    if (InitOnceBeginInitialize(once, flags, pending, context)) { *error = ERROR_SUCCESS; return true; }
    *error = GetLastError(); return false;
}
bool Complete(void*, INIT_ONCE* once, DWORD flags, void* context, DWORD* error) noexcept {
    if (InitOnceComplete(once, flags, context)) { *error = ERROR_SUCCESS; return true; }
    *error = GetLastError(); return false;
}
constexpr GenuineResolverOps kProduction{nullptr, BuildPath, Load, ModulePath, Identity,
    Export, Address, ReleaseModule, Allocate, FreeRecord, Begin, Complete};
GenuineResolverResult Failure(GenuineResolverStatus status, DWORD error) noexcept {
    GenuineResolverResult result{};
    result.dispatch.status = status;
    result.dispatch.win32Error = error;
    result.failureClass = ClassifyGenuineFailure(status);
    return result;
}
GenuineDispatchLease Persistent(const X3AudioDispatch& dispatch) noexcept {
    return {dispatch, IsCompleteDispatch(dispatch), false};
}
bool Published(GenuineResolverState* state, const GenuineResolverOps& ops,
    X3AudioDispatch* dispatch) noexcept {
    DWORD ignored = ERROR_SUCCESS;
    return TryGetNormal(state, ops, dispatch, &ignored) || TryGetReadyFallback(state, dispatch);
}
bool HasPrivateOps(const GenuineResolverOps& ops) noexcept {
    return ops.buildSystemPath && ops.loadSystemLibrary && ops.getModulePath &&
        ops.queryFileIdentity && ops.getExport && ops.queryAllocationBase && ops.freeLibrary;
}
} // namespace

const GenuineResolverOps& ProductionGenuineResolverOps() noexcept { return kProduction; }
GenuineFailureClass ClassifyGenuineFailure(GenuineResolverStatus status) noexcept {
    switch (status) {
    case GenuineResolverStatus::Ok: return GenuineFailureClass::None;
    case GenuineResolverStatus::SystemPathFailed:
    case GenuineResolverStatus::PathCapacityFailed:
    case GenuineResolverStatus::LoadFailed:
    case GenuineResolverStatus::CandidatePathFailed:
    case GenuineResolverStatus::FileIdentityFailed: return GenuineFailureClass::ResourceApi;
    default: return GenuineFailureClass::Validation;
    }
}

GenuineResolverStatus ValidateGenuineEvidence(HMODULE bootstrap, HMODULE candidate,
    const FileIdentity& expected, const FileIdentity& actual,
    FARPROC initialize, FARPROC calculate, bool initializeQueried, bool calculateQueried,
    const void* initializeBase, const void* calculateBase) noexcept {
    if (candidate == nullptr) return GenuineResolverStatus::LoadFailed;
    if (candidate == bootstrap) return GenuineResolverStatus::SelfModule;
    if (!expected.valid || !actual.valid) return GenuineResolverStatus::FileIdentityFailed;
    if (!SameFileIdentity(expected, actual)) return GenuineResolverStatus::WrongFile;
    if (initialize == nullptr) return GenuineResolverStatus::InitializeExportMissing;
    if (calculate == nullptr) return GenuineResolverStatus::CalculateExportMissing;
    if (!initializeQueried) return GenuineResolverStatus::InitializeAddressQueryFailed;
    if (!calculateQueried) return GenuineResolverStatus::CalculateAddressQueryFailed;
    if (initializeBase != candidate) return GenuineResolverStatus::InitializeWrongAllocationBase;
    if (calculateBase != candidate) return GenuineResolverStatus::CalculateWrongAllocationBase;
    return GenuineResolverStatus::Ok;
}

GenuineResolverResult ResolveGenuineX3AudioPrivate(HMODULE bootstrap,
    const GenuineResolverOps& ops) noexcept {
    if (bootstrap == nullptr || !HasPrivateOps(ops))
        return Failure(GenuineResolverStatus::SystemPathFailed, ERROR_INVALID_PARAMETER);
    wchar_t expectedPath[kBootstrapPathCapacity]{};
    wchar_t candidatePath[kBootstrapPathCapacity]{};
    DWORD error = ERROR_SUCCESS;
    if (!ops.buildSystemPath(ops.context, expectedPath, _countof(expectedPath), &error))
        return Failure(error == ERROR_INSUFFICIENT_BUFFER ? GenuineResolverStatus::PathCapacityFailed
            : GenuineResolverStatus::SystemPathFailed, error);
    HMODULE candidate = ops.loadSystemLibrary(ops.context, expectedPath, &error);
    if (candidate == nullptr) return Failure(GenuineResolverStatus::LoadFailed, error);
    // Never release a handle that resolved to our bootstrap, even on rejection.
    if (candidate == bootstrap) return Failure(GenuineResolverStatus::SelfModule, ERROR_INVALID_DATA);
    const auto reject = [&](GenuineResolverStatus status, DWORD failure) noexcept {
        ops.freeLibrary(ops.context, candidate);
        return Failure(status, failure);
    };
    if (!ops.getModulePath(ops.context, candidate, candidatePath, _countof(candidatePath), &error))
        return reject(GenuineResolverStatus::CandidatePathFailed, error);
    FileIdentity expected{}, actual{};
    if (!ops.queryFileIdentity(ops.context, expectedPath, &expected, &error) ||
        !ops.queryFileIdentity(ops.context, candidatePath, &actual, &error))
        return reject(GenuineResolverStatus::FileIdentityFailed, error);
    if (!expected.valid || !actual.valid)
        return reject(GenuineResolverStatus::FileIdentityFailed, ERROR_INVALID_DATA);
    if (!SameFileIdentity(expected, actual))
        return reject(GenuineResolverStatus::WrongFile, ERROR_INVALID_DATA);
    FARPROC initialize = ops.getExport(ops.context, candidate, "X3DAudioInitialize", &error);
    if (initialize == nullptr) return reject(GenuineResolverStatus::InitializeExportMissing, error);
    FARPROC calculate = ops.getExport(ops.context, candidate, "X3DAudioCalculate", &error);
    if (calculate == nullptr) return reject(GenuineResolverStatus::CalculateExportMissing, error);
    const void* initializeBase = nullptr;
    if (!ops.queryAllocationBase(ops.context, initialize, &initializeBase, &error))
        return reject(GenuineResolverStatus::InitializeAddressQueryFailed, error);
    if (initializeBase != candidate)
        return reject(GenuineResolverStatus::InitializeWrongAllocationBase, ERROR_INVALID_DATA);
    const void* calculateBase = nullptr;
    if (!ops.queryAllocationBase(ops.context, calculate, &calculateBase, &error))
        return reject(GenuineResolverStatus::CalculateAddressQueryFailed, error);
    if (calculateBase != candidate)
        return reject(GenuineResolverStatus::CalculateWrongAllocationBase, ERROR_INVALID_DATA);
    GenuineResolverResult result{};
    result.dispatch = {candidate, reinterpret_cast<X3DAudioInitializeFn>(initialize),
        reinterpret_cast<X3DAudioCalculateFn>(calculate), GenuineResolverStatus::Ok, ERROR_SUCCESS};
    result.failureClass = GenuineFailureClass::None;
    result.ownsModule = true;
    return result;
}

bool TryGetNormal(GenuineResolverState* state, const GenuineResolverOps& ops,
    X3AudioDispatch* dispatch, DWORD* error) noexcept {
    if (state == nullptr || dispatch == nullptr || ops.beginOnce == nullptr) return false;
    BOOL pending = TRUE;
    void* context = nullptr;
    DWORD localError = ERROR_SUCCESS;
    const bool success = ops.beginOnce(ops.context, &state->normalOnce,
        INIT_ONCE_CHECK_ONLY, &pending, &context, &localError);
    if (error != nullptr) *error = localError;
    if (!success || pending || context == nullptr ||
        reinterpret_cast<std::uintptr_t>(context) % kDispatchAlignment != 0) return false;
    const auto* record = static_cast<const X3AudioDispatch*>(context);
    if (!IsCompleteDispatch(*record)) return false;
    *dispatch = *record;
    return true;
}
bool TryGetReadyFallback(GenuineResolverState* state, X3AudioDispatch* dispatch) noexcept {
    if (state == nullptr || dispatch == nullptr ||
        InterlockedCompareExchange(&state->fallbackState, 0, 0) !=
            static_cast<LONG>(FallbackState::Ready)) return false;
    if (!IsCompleteDispatch(state->fallback)) return false;
    *dispatch = state->fallback;
    return true;
}

GenuineDispatchLease PublishPrivateSuccess(GenuineResolverState* state,
    GenuineResolverResult&& privateResult, bool beginSucceeded, BOOL pending,
    const GenuineResolverOps& ops) noexcept {
    if (state == nullptr || !privateResult.ownsModule ||
        !IsCompleteDispatch(privateResult.dispatch)) return {};
    X3AudioDispatch winner{};
    if (Published(state, ops, &winner)) {
        ops.freeLibrary(ops.context, privateResult.dispatch.module);
        privateResult.ownsModule = false;
        return Persistent(winner);
    }
    if (beginSucceeded && pending && ops.allocateDispatch && ops.freeDispatch && ops.completeOnce) {
        void* allocation = ops.allocateDispatch(ops.context);
        if (allocation != nullptr) {
            if (reinterpret_cast<std::uintptr_t>(allocation) % kDispatchAlignment == 0) {
                auto* record = ::new (allocation) X3AudioDispatch(privateResult.dispatch);
                DWORD ignored = ERROR_SUCCESS;
                if (ops.completeOnce(ops.context, &state->normalOnce, INIT_ONCE_ASYNC, record, &ignored)) {
                    privateResult.ownsModule = false;
                    return Persistent(*record);
                }
                // Observe the normal winner immediately after a rejected completion.
                if (TryGetNormal(state, ops, &winner, &ignored)) {
                    ops.freeDispatch(ops.context, allocation);
                    ops.freeLibrary(ops.context, privateResult.dispatch.module);
                    privateResult.ownsModule = false;
                    return Persistent(winner);
                }
            }
            ops.freeDispatch(ops.context, allocation);
        }
    }
    if (Published(state, ops, &winner)) {
        ops.freeLibrary(ops.context, privateResult.dispatch.module);
        privateResult.ownsModule = false;
        return Persistent(winner);
    }
    if (InterlockedCompareExchange(&state->fallbackState,
            static_cast<LONG>(FallbackState::Writing), static_cast<LONG>(FallbackState::Empty)) ==
        static_cast<LONG>(FallbackState::Empty)) {
        state->fallback = privateResult.dispatch;
        InterlockedExchange(&state->fallbackState, static_cast<LONG>(FallbackState::Ready));
        privateResult.ownsModule = false;
        DWORD ignored = ERROR_SUCCESS;
        if (ops.completeOnce) ops.completeOnce(ops.context, &state->normalOnce,
            INIT_ONCE_ASYNC, &state->fallback, &ignored);
        return Persistent(state->fallback);
    }
    // A single acquire read. Never inspect a record still being written or wait for it.
    if (TryGetReadyFallback(state, &winner)) {
        ops.freeLibrary(ops.context, privateResult.dispatch.module);
        privateResult.ownsModule = false;
        return Persistent(winner);
    }
    privateResult.ownsModule = false;
    return {privateResult.dispatch, true, true};
}

GenuineDispatchLease AcquireGenuineX3Audio(GenuineResolverState* state, HMODULE bootstrap,
    const GenuineResolverOps& ops, AcquireMode mode) noexcept {
    GenuineDispatchLease failed{};
    if (state == nullptr || bootstrap == nullptr || mode != AcquireMode::ExportRetryOnce) {
        failed.dispatch.win32Error = ERROR_INVALID_PARAMETER;
        return failed;
    }
    X3AudioDispatch published{};
    if (Published(state, ops, &published)) return Persistent(published);
    BOOL pending = TRUE;
    void* context = nullptr;
    DWORD error = ERROR_SUCCESS;
    const bool begun = ops.beginOnce != nullptr && ops.beginOnce(ops.context,
        &state->normalOnce, INIT_ONCE_ASYNC, &pending, &context, &error);
    if (begun && !pending && context != nullptr &&
        reinterpret_cast<std::uintptr_t>(context) % kDispatchAlignment == 0 &&
        IsCompleteDispatch(*static_cast<const X3AudioDispatch*>(context)))
        return Persistent(*static_cast<const X3AudioDispatch*>(context));
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        if (attempt != 0 && Published(state, ops, &published)) return Persistent(published);
        GenuineResolverResult result = ResolveGenuineX3AudioPrivate(bootstrap, ops);
        if (result.ownsModule && IsCompleteDispatch(result.dispatch))
            return PublishPrivateSuccess(state, static_cast<GenuineResolverResult&&>(result), begun, pending, ops);
        failed.dispatch = result.dispatch;
        if (Published(state, ops, &published)) return Persistent(published);
        if (result.failureClass != GenuineFailureClass::ResourceApi) break;
    }
    return failed;
}
void ReleaseGenuineX3AudioLease(GenuineDispatchLease* lease, const GenuineResolverOps& ops) noexcept {
    if (lease == nullptr) return;
    if (lease->valid && lease->releaseModuleOnClose && lease->dispatch.module != nullptr && ops.freeLibrary)
        ops.freeLibrary(ops.context, lease->dispatch.module);
    *lease = {};
}
} // namespace rs2fix
