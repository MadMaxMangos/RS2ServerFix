#pragma once

#include "shared/bootstrap_abi.h"

#include <ErrorRep.h>

#include <cstdint>

namespace rs2fix {

using ReportFaultFn =
    EFaultRepRetVal(APIENTRY*)(LPEXCEPTION_POINTERS, DWORD);

enum class GenuineResolverStatus : std::uint32_t {
    Ok = 0,
    SystemPathFailed,
    LoadFailed,
    SelfModule,
    CandidatePathFailed,
    FileIdentityFailed,
    WrongFile,
    ExportMissing,
    QueryAddressFailed,
    SelfAddress,
};

struct GenuineResolverResult {
    HMODULE module{};
    ReportFaultFn function{};
    GenuineResolverStatus status{GenuineResolverStatus::LoadFailed};
    DWORD win32Error{};
};

enum class CompanionLoadStatus : std::uint32_t {
    Ok,
    PathFailed,
    LoadFailed,
    SelfModule,
    GenuineModule,
    CandidatePathFailed,
    FileIdentityFailed,
    WrongFile,
    ExportMissing,
    QueryAddressFailed,
    WrongAddressBase,
    InitializeFailed,
};

struct CompanionLoadResult {
    HMODULE module{};
    CompanionLoadStatus status{CompanionLoadStatus::LoadFailed};
    DWORD win32Error{};
    DWORD initializeResult{kInitInvalidContext};
};

} // namespace rs2fix
