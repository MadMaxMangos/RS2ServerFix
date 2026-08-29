#include "bootstrap/companion_loader.h"

namespace rs2fix {

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

} // namespace rs2fix
