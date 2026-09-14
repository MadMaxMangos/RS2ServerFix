#include "bootstrap/companion_loader.h"
#include "shared/thread_error_mode.h"
#include <iterator>

namespace rs2fix {
namespace {
bool BuildPath(void*, HMODULE module, wchar_t* path, std::size_t capacity, DWORD* error) noexcept {
    return BuildCompanionPath(module, path, capacity, error);
}
HMODULE Load(void*, const wchar_t* path, DWORD* error) noexcept {
    return LoadLibraryWithThreadErrorMode(path, LOAD_LIBRARY_SEARCH_SYSTEM32,
        error, ProductionThreadErrorModeOps());
}
bool ModulePath(void*, HMODULE module, wchar_t* path, std::size_t capacity, DWORD* error) noexcept {
    return GetBoundedModulePath(module, path, capacity, error);
}
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
DWORD Invoke(void*, InitializeV3Fn initialize, const BootstrapContextV3* context) noexcept {
    return initialize(context);
}
constexpr CompanionLoaderOps kProduction{nullptr, BuildPath, Load, ModulePath,
    Identity, Export, Address, ReleaseModule, Invoke};
CompanionLoadResult Failure(CompanionLoadStatus status, DWORD error) noexcept {
    CompanionLoadResult result{}; result.status = status; result.win32Error = error; return result;
}
} // namespace
const CompanionLoaderOps& ProductionCompanionLoaderOps() noexcept { return kProduction; }

CompanionLoadStatus ValidateCompanionEvidence(HMODULE bootstrap, HMODULE genuine,
    HMODULE candidate, FARPROC initializer, const FileIdentity& expected,
    const FileIdentity& actual, bool queried, const void* allocationBase) noexcept {
    if (candidate == nullptr) return CompanionLoadStatus::LoadFailed;
    if (candidate == bootstrap) return CompanionLoadStatus::SelfModule;
    if (candidate == genuine) return CompanionLoadStatus::GenuineModule;
    if (!expected.valid || !actual.valid) return CompanionLoadStatus::FileIdentityFailed;
    if (!SameFileIdentity(expected, actual)) return CompanionLoadStatus::WrongFile;
    if (initializer == nullptr) return CompanionLoadStatus::ExportMissing;
    if (!queried) return CompanionLoadStatus::QueryAddressFailed;
    if (allocationBase != candidate) return CompanionLoadStatus::WrongAddressBase;
    return CompanionLoadStatus::Ok;
}

bool BuildCompanionPath(HMODULE bootstrap, wchar_t* output,
    std::size_t capacity, DWORD* error) noexcept {
    if (output != nullptr && capacity != 0) output[0] = L'\0';
    if (bootstrap == nullptr || output == nullptr || capacity == 0) {
        if (error != nullptr) *error = ERROR_INVALID_PARAMETER;
        return false;
    }
    if (!GetBoundedModulePath(bootstrap, output, capacity, error)) return false;
    std::size_t length = 0;
    while (length < capacity && output[length] != L'\0') ++length;
    std::size_t separator = length;
    while (separator != 0 && output[separator - 1] != L'\\' &&
        output[separator - 1] != L'/') --separator;
    if (length == 0 || length == capacity || separator == 0 || separator == length) {
        output[0] = L'\0';
        if (error != nullptr) *error = ERROR_INVALID_NAME;
        return false;
    }
    // Keep the separator, including a drive root, and append in place.
    output[separator] = L'\0';
    constexpr wchar_t leaf[] = L"RS2ServerFix.dll";
    return AppendPathLeaf(output, capacity, leaf, std::size(leaf), output, capacity, error);
}

CompanionLoadResult LoadAndInitializeCompanion(HMODULE bootstrap,
    const BootstrapContextV3& context, const CompanionLoaderOps& ops) noexcept {
    if (bootstrap == nullptr || context.bootstrapModule != bootstrap ||
        context.genuineX3AudioModule == nullptr ||
        context.genuineX3AudioModule == bootstrap || context.hostModule == nullptr ||
        context.size != sizeof(BootstrapContextV3) || context.abiVersion != kBootstrapAbiVersion ||
        context.genuineExportsMask != kRequiredGenuineExports || context.reserved != 0 ||
        context.triggerKind != kTriggerExeCrtInitialize || context.staticLoad != 1 ||
        context.triggerReturnAddress == 0 || context.startupThreadId == 0 ||
        context.currentThreadId != context.startupThreadId ||
        !ops.buildCompanionPath || !ops.loadLibrary || !ops.getModulePath ||
        !ops.queryFileIdentity || !ops.getExport || !ops.queryAllocationBase ||
        !ops.freeLibrary || !ops.invoke)
        return Failure(CompanionLoadStatus::PathFailed, ERROR_INVALID_PARAMETER);
    wchar_t expectedPath[kBootstrapPathCapacity]{};
    wchar_t candidatePath[kBootstrapPathCapacity]{};
    DWORD error = ERROR_SUCCESS;
    if (!ops.buildCompanionPath(ops.context, bootstrap, expectedPath, std::size(expectedPath), &error))
        return Failure(CompanionLoadStatus::PathFailed, error);
    HMODULE candidate = ops.loadLibrary(ops.context, expectedPath, &error);
    if (candidate == nullptr) return Failure(CompanionLoadStatus::LoadFailed, error);
    // A rejected self handle must never unload the bootstrap itself.
    if (candidate == bootstrap) return Failure(CompanionLoadStatus::SelfModule, ERROR_INVALID_DATA);
    const auto reject = [&](CompanionLoadStatus status, DWORD failure) noexcept {
        ops.freeLibrary(ops.context, candidate);
        return Failure(status, failure);
    };
    if (candidate == context.genuineX3AudioModule)
        return reject(CompanionLoadStatus::GenuineModule, ERROR_INVALID_DATA);
    if (!ops.getModulePath(ops.context, candidate, candidatePath, std::size(candidatePath), &error))
        return reject(CompanionLoadStatus::CandidatePathFailed, error);
    FileIdentity expected{}, actual{};
    if (!ops.queryFileIdentity(ops.context, expectedPath, &expected, &error) ||
        !ops.queryFileIdentity(ops.context, candidatePath, &actual, &error))
        return reject(CompanionLoadStatus::FileIdentityFailed, error);
    if (!expected.valid || !actual.valid)
        return reject(CompanionLoadStatus::FileIdentityFailed, ERROR_INVALID_DATA);
    if (!SameFileIdentity(expected, actual))
        return reject(CompanionLoadStatus::WrongFile, ERROR_INVALID_DATA);
    FARPROC initializer = ops.getExport(ops.context, candidate, "RS2ServerFix_InitializeV3", &error);
    if (initializer == nullptr) return reject(CompanionLoadStatus::ExportMissing, error);
    const void* allocationBase = nullptr;
    if (!ops.queryAllocationBase(ops.context, initializer, &allocationBase, &error))
        return reject(CompanionLoadStatus::QueryAddressFailed, error);
    if (allocationBase != candidate)
        return reject(CompanionLoadStatus::WrongAddressBase, ERROR_INVALID_DATA);
    CompanionLoadResult result{};
    // Invocation transfers the load reference to process lifetime, even on failure:
    // the initializer may have published data or started its report-only thread.
    result.module = candidate;
    result.initializeResult = ops.invoke(ops.context,
        reinterpret_cast<InitializeV3Fn>(initializer), &context);
    result.status = result.initializeResult == kInitOk || result.initializeResult == kInitAlreadyInitialized
        ? CompanionLoadStatus::Ok : CompanionLoadStatus::InitializeFailed;
    return result;
}
CompanionLoadResult LoadAndInitializeCompanion(HMODULE bootstrap,
    const BootstrapContextV3& context) noexcept {
    return LoadAndInitializeCompanion(bootstrap, context, ProductionCompanionLoaderOps());
}
} // namespace rs2fix
