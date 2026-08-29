#include "bootstrap/companion_loader.h"

#include <Windows.h>

namespace rs2fix {
namespace {

struct CompanionLoaderWorkspace {
    wchar_t expectedPath[kPathCapacity];
    wchar_t candidatePath[kPathCapacity];
};

DWORD CompanionValidationError(
    const CompanionLoadStatus status) noexcept {
    switch (status) {
    case CompanionLoadStatus::Ok:
        return ERROR_SUCCESS;
    case CompanionLoadStatus::LoadFailed:
        return ERROR_MOD_NOT_FOUND;
    case CompanionLoadStatus::ExportMissing:
        return ERROR_PROC_NOT_FOUND;
    case CompanionLoadStatus::PathFailed:
    case CompanionLoadStatus::CandidatePathFailed:
        return ERROR_INVALID_NAME;
    case CompanionLoadStatus::SelfModule:
    case CompanionLoadStatus::GenuineModule:
    case CompanionLoadStatus::FileIdentityFailed:
    case CompanionLoadStatus::WrongFile:
    case CompanionLoadStatus::QueryAddressFailed:
    case CompanionLoadStatus::WrongAddressBase:
    case CompanionLoadStatus::InitializeFailed:
        return ERROR_INVALID_DATA;
    }
    return ERROR_INVALID_DATA;
}

} // namespace

CompanionLoadStatus ValidateCompanionEvidence(
    HMODULE bootstrap,
    HMODULE genuine,
    HMODULE candidate,
    FARPROC initializer,
    const FileIdentity& expected,
    const FileIdentity& actual,
    const bool virtualQuerySucceeded,
    const void* allocationBase) noexcept {
    if (candidate == nullptr) {
        return CompanionLoadStatus::LoadFailed;
    }
    if (candidate == bootstrap) {
        return CompanionLoadStatus::SelfModule;
    }
    if (candidate == genuine) {
        return CompanionLoadStatus::GenuineModule;
    }
    if (!expected.valid || !actual.valid) {
        return CompanionLoadStatus::FileIdentityFailed;
    }
    if (!SameFileIdentity(expected, actual)) {
        return CompanionLoadStatus::WrongFile;
    }
    if (initializer == nullptr) {
        return CompanionLoadStatus::ExportMissing;
    }
    if (!virtualQuerySucceeded) {
        return CompanionLoadStatus::QueryAddressFailed;
    }
    if (allocationBase != candidate) {
        return CompanionLoadStatus::WrongAddressBase;
    }
    return CompanionLoadStatus::Ok;
}

bool BuildCompanionPath(
    HMODULE bootstrap,
    wchar_t* output,
    const std::size_t capacity,
    DWORD* error) noexcept {
    if (output != nullptr && capacity != 0) {
        output[0] = L'\0';
    }
    if (bootstrap == nullptr || output == nullptr || capacity == 0) {
        if (error != nullptr) {
            *error = ERROR_INVALID_PARAMETER;
        }
        return false;
    }

    DWORD localError = ERROR_SUCCESS;
    if (!GetBoundedModulePath(
            bootstrap, output, capacity, &localError)) {
        if (error != nullptr) {
            *error = localError;
        }
        return false;
    }

    const std::size_t length = wcsnlen_s(output, capacity);
    std::size_t separator = length;
    while (separator != 0) {
        --separator;
        if (output[separator] == L'\\' || output[separator] == L'/') {
            break;
        }
    }
    if (length == 0 || length >= capacity ||
        (output[separator] != L'\\' && output[separator] != L'/') ||
        separator + 1 >= length) {
        output[0] = L'\0';
        if (error != nullptr) {
            *error = ERROR_INVALID_NAME;
        }
        return false;
    }
    output[separator] = L'\0';
    if (!AppendPathLeaf(
            output,
            L"RS2ServerFix.dll",
            output,
            capacity,
            &localError)) {
        if (error != nullptr) {
            *error = localError;
        }
        return false;
    }

    if (error != nullptr) {
        *error = ERROR_SUCCESS;
    }
    return true;
}

CompanionLoadResult LoadAndInitializeCompanion(
    HMODULE bootstrap,
    const BootstrapContextV1& context) noexcept {
    CompanionLoadResult result{};
    if (bootstrap == nullptr || context.bootstrapModule != bootstrap) {
        result.status = CompanionLoadStatus::PathFailed;
        result.win32Error = ERROR_INVALID_PARAMETER;
        return result;
    }

    auto* workspace = static_cast<CompanionLoaderWorkspace*>(VirtualAlloc(
        nullptr,
        sizeof(CompanionLoaderWorkspace),
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE));
    if (workspace == nullptr) {
        result.status = CompanionLoadStatus::PathFailed;
        result.win32Error = ERROR_NOT_ENOUGH_MEMORY;
        return result;
    }

    DWORD localError = ERROR_SUCCESS;
    if (!BuildCompanionPath(
            bootstrap,
            workspace->expectedPath,
            kPathCapacity,
            &localError)) {
        result.status = CompanionLoadStatus::PathFailed;
        result.win32Error = localError;
        VirtualFree(workspace, 0, MEM_RELEASE);
        return result;
    }

    HMODULE candidate = LoadLibraryExW(
        workspace->expectedPath,
        nullptr,
        LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (candidate == nullptr) {
        result.status = CompanionLoadStatus::LoadFailed;
        result.win32Error = GetLastError();
        VirtualFree(workspace, 0, MEM_RELEASE);
        return result;
    }

    FileIdentity expectedIdentity{};
    FileIdentity candidateIdentity{};
    FARPROC initializer = nullptr;
    MEMORY_BASIC_INFORMATION memory{};
    bool queried = false;

    if (!GetBoundedModulePath(
            candidate,
            workspace->candidatePath,
            kPathCapacity,
            &localError)) {
        result.status = CompanionLoadStatus::CandidatePathFailed;
        result.win32Error = localError;
        FreeLibrary(candidate);
        VirtualFree(workspace, 0, MEM_RELEASE);
        return result;
    }
    if (!QueryFileIdentity(
            workspace->expectedPath,
            &expectedIdentity,
            &localError) ||
        !QueryFileIdentity(
            workspace->candidatePath,
            &candidateIdentity,
            &localError)) {
        result.status = CompanionLoadStatus::FileIdentityFailed;
        result.win32Error = localError;
        FreeLibrary(candidate);
        VirtualFree(workspace, 0, MEM_RELEASE);
        return result;
    }

    SetLastError(ERROR_SUCCESS);
    initializer = GetProcAddress(
        candidate, "RS2ServerFix_InitializeV1");
    localError = initializer == nullptr ? GetLastError() : ERROR_SUCCESS;
    if (initializer != nullptr) {
        queried = VirtualQuery(
            reinterpret_cast<const void*>(initializer),
            &memory,
            sizeof(memory)) == sizeof(memory);
        if (!queried) {
            localError = GetLastError();
        }
    }

    const CompanionLoadStatus validation = ValidateCompanionEvidence(
        bootstrap,
        context.genuineFaultrepModule,
        candidate,
        initializer,
        expectedIdentity,
        candidateIdentity,
        queried,
        memory.AllocationBase);
    if (validation != CompanionLoadStatus::Ok) {
        result.status = validation;
        result.win32Error = localError != ERROR_SUCCESS
            ? localError
            : CompanionValidationError(validation);
        FreeLibrary(candidate);
        VirtualFree(workspace, 0, MEM_RELEASE);
        return result;
    }

    if (initializer == nullptr) {
        result.status = CompanionLoadStatus::ExportMissing;
        result.win32Error = ERROR_PROC_NOT_FOUND;
        FreeLibrary(candidate);
        VirtualFree(workspace, 0, MEM_RELEASE);
        return result;
    }
    const auto initialize = reinterpret_cast<InitializeV1Fn>(initializer);
    VirtualFree(workspace, 0, MEM_RELEASE);
    result.initializeResult = initialize(&context);
    result.module = candidate;
    result.status =
        result.initializeResult == kInitOk ||
        result.initializeResult == kInitAlreadyInitialized
            ? CompanionLoadStatus::Ok
            : CompanionLoadStatus::InitializeFailed;
    result.win32Error = ERROR_SUCCESS;
    return result;
}

} // namespace rs2fix
