#include "bootstrap/genuine_resolver.h"

#include <Windows.h>

namespace rs2fix {
namespace {

DWORD ValidationError(const GenuineResolverStatus status) noexcept {
    switch (status) {
    case GenuineResolverStatus::Ok:
        return ERROR_SUCCESS;
    case GenuineResolverStatus::LoadFailed:
        return ERROR_MOD_NOT_FOUND;
    case GenuineResolverStatus::ExportMissing:
        return ERROR_PROC_NOT_FOUND;
    case GenuineResolverStatus::SystemPathFailed:
    case GenuineResolverStatus::CandidatePathFailed:
        return ERROR_INVALID_NAME;
    case GenuineResolverStatus::FileIdentityFailed:
    case GenuineResolverStatus::WrongFile:
    case GenuineResolverStatus::SelfModule:
    case GenuineResolverStatus::QueryAddressFailed:
    case GenuineResolverStatus::SelfAddress:
        return ERROR_INVALID_DATA;
    }
    return ERROR_INVALID_DATA;
}

} // namespace

GenuineResolverStatus ValidateGenuineEvidence(
    HMODULE bootstrap,
    HMODULE candidate,
    FARPROC function,
    const FileIdentity& expected,
    const FileIdentity& actual,
    const bool virtualQuerySucceeded,
    const void* allocationBase) noexcept {
    if (candidate == nullptr) {
        return GenuineResolverStatus::LoadFailed;
    }
    if (candidate == bootstrap) {
        return GenuineResolverStatus::SelfModule;
    }
    if (!expected.valid || !actual.valid) {
        return GenuineResolverStatus::FileIdentityFailed;
    }
    if (!SameFileIdentity(expected, actual)) {
        return GenuineResolverStatus::WrongFile;
    }
    if (function == nullptr) {
        return GenuineResolverStatus::ExportMissing;
    }
    if (!virtualQuerySucceeded) {
        return GenuineResolverStatus::QueryAddressFailed;
    }
    if (allocationBase == bootstrap) {
        return GenuineResolverStatus::SelfAddress;
    }
    return GenuineResolverStatus::Ok;
}

GenuineResolverResult ResolveGenuineReportFault(
    HMODULE bootstrap) noexcept {
    GenuineResolverResult result{};
    wchar_t expectedPath[kPathCapacity]{};
    DWORD localError = ERROR_SUCCESS;
    if (!BuildSystemFaultrepPath(
            expectedPath, kPathCapacity, &localError)) {
        result.status = GenuineResolverStatus::SystemPathFailed;
        result.win32Error = localError;
        return result;
    }

    HMODULE candidate = LoadLibraryExW(
        expectedPath, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (candidate == nullptr) {
        result.status = GenuineResolverStatus::LoadFailed;
        result.win32Error = GetLastError();
        return result;
    }

    wchar_t candidatePath[kPathCapacity]{};
    FileIdentity expectedIdentity{};
    FileIdentity candidateIdentity{};
    FARPROC function = nullptr;
    MEMORY_BASIC_INFORMATION memory{};
    bool queried = false;

    if (!GetBoundedModulePath(
            candidate, candidatePath, kPathCapacity, &localError)) {
        result.status = GenuineResolverStatus::CandidatePathFailed;
        result.win32Error = localError;
        FreeLibrary(candidate);
        return result;
    }
    if (!QueryFileIdentity(
            expectedPath, &expectedIdentity, &localError) ||
        !QueryFileIdentity(
            candidatePath, &candidateIdentity, &localError)) {
        result.status = GenuineResolverStatus::FileIdentityFailed;
        result.win32Error = localError;
        FreeLibrary(candidate);
        return result;
    }

    SetLastError(ERROR_SUCCESS);
    function = GetProcAddress(candidate, "ReportFault");
    localError = function == nullptr ? GetLastError() : ERROR_SUCCESS;
    if (function != nullptr) {
        queried = VirtualQuery(
            reinterpret_cast<const void*>(function),
            &memory,
            sizeof(memory)) == sizeof(memory);
        if (!queried) {
            localError = GetLastError();
        }
    }

    const GenuineResolverStatus status = ValidateGenuineEvidence(
        bootstrap,
        candidate,
        function,
        expectedIdentity,
        candidateIdentity,
        queried,
        memory.AllocationBase);
    if (status != GenuineResolverStatus::Ok) {
        result.status = status;
        result.win32Error = localError != ERROR_SUCCESS
            ? localError
            : ValidationError(status);
        FreeLibrary(candidate);
        return result;
    }

    result.module = candidate;
    result.function = reinterpret_cast<ReportFaultFn>(function);
    result.status = GenuineResolverStatus::Ok;
    result.win32Error = ERROR_SUCCESS;
    return result;
}

} // namespace rs2fix
