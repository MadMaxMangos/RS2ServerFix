#include "bootstrap/forwarder.h"

namespace rs2fix {

EFaultRepRetVal ForwardOrFail(
    const ReportFaultFn function,
    LPEXCEPTION_POINTERS exceptionPointers,
    const DWORD options) noexcept {
    if (function == nullptr) {
        return frrvErrNoDW;
    }
    return function(exceptionPointers, options);
}

} // namespace rs2fix
