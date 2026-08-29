#pragma once

#include "bootstrap/bootstrap_types.h"
#include "shared/path_identity.h"

namespace rs2fix {

GenuineResolverStatus ValidateGenuineEvidence(
    HMODULE bootstrap,
    HMODULE candidate,
    FARPROC function,
    const FileIdentity& expected,
    const FileIdentity& actual,
    bool virtualQuerySucceeded,
    const void* allocationBase) noexcept;

GenuineResolverResult ResolveGenuineReportFault(
    HMODULE bootstrap) noexcept;

} // namespace rs2fix
