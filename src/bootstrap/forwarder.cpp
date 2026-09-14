#include "bootstrap/forwarder.h"

namespace rs2fix {
bool TryForwardCalculate(GenuineResolverState* state, HMODULE bootstrap,
    const GenuineResolverOps& ops, const BYTE* instance, const void* listener,
    const void* emitter, UINT32 flags, void* settings) {
    GenuineDispatchLease lease = AcquireGenuineX3Audio(state, bootstrap, ops);
    if (!lease.valid) return false;
    lease.dispatch.calculate(instance, listener, emitter, flags, settings);
    ReleaseGenuineX3AudioLease(&lease, ops);
    return true;
}
[[noreturn]] void FailFastX3Audio() noexcept {
    RaiseFailFastException(nullptr, nullptr, FAIL_FAST_GENERATE_EXCEPTION_ADDRESS);
    TerminateProcess(GetCurrentProcess(), 0xC0000602UL);
    __assume(0);
}
} // namespace rs2fix
