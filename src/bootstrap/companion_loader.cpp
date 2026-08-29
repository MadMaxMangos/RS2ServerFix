#include "bootstrap/companion_loader.h"

#include <Windows.h>

namespace rs2fix {
namespace {

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

    wchar_t bootstrapPath[kPathCapacity]{};
    wchar_t directory[kPathCapacity]{};
    wchar_t leaf[260]{};
    DWORD localError = ERROR_SUCCESS;
    if (!GetBoundedModulePath(
            bootstrap, bootstrapPath, kPathCapacity, &localError) ||
        !ExtractDirectoryAndLeaf(
            bootstrapPath,
            directory,
            kPathCapacity,
            leaf,
            260,
            &localError) ||
        !AppendPathLeaf(
            directory,
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

    wchar_t expectedPath[kPathCapacity]{};
    DWORD localError = ERROR_SUCCESS;
    if (!BuildCompanionPath(
            bootstrap, expectedPath, kPathCapacity, &localError)) {
        result.status = CompanionLoadStatus::PathFailed;
        result.win32Error = localError;
        return result;
    }

    HMODULE candidate = LoadLibraryExW(
        expectedPath, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (candidate == nullptr) {
        result.status = CompanionLoadStatus::LoadFailed;
        result.win32Error = GetLastError();
        return result;
    }

    wchar_t candidatePath[kPathCapacity]{};
    FileIdentity expectedIdentity{};
    FileIdentity candidateIdentity{};
    FARPROC initializer = nullptr;
    MEMORY_BASIC_INFORMATION memory{};
    bool queried = false;

    if (!GetBoundedModulePath(
            candidate, candidatePath, kPathCapacity, &localError)) {
        result.status = CompanionLoadStatus::CandidatePathFailed;
        result.win32Error = localError;
        FreeLibrary(candidate);
        return result;
    }
    if (!QueryFileIdentity(
            expectedPath, &expectedIdentity, &localError) ||
        !QueryFileIdentity(
            candidatePath, &candidateIdentity, &localError)) {
        result.status = CompanionLoadStatus::FileIdentityFailed;
        result.win32Error = localError;
        FreeLibrary(candidate);
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
        return result;
    }

    const auto initialize = reinterpret_cast<InitializeV1Fn>(initializer);
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
