#pragma once

#include "bootstrap/bootstrap_types.h"

namespace rs2fix {

EFaultRepRetVal ForwardOrFail(
    ReportFaultFn function,
    LPEXCEPTION_POINTERS exceptionPointers,
    DWORD options) noexcept;

} // namespace rs2fix
