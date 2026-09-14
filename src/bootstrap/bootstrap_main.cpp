#include "bootstrap/companion_loader.h"
#include "bootstrap/forwarder.h"
#include "shared/selected_profile.h"

#include <intrin.h>

namespace {
rs2fix::GenuineResolverState g_genuine{};
HMODULE g_bootstrap{};
HMODULE g_host{};
DWORD g_startupThread{};
DWORD g_staticLoad{};
volatile LONG g_optionalAttempted{};

struct LeaseOwner {
    rs2fix::GenuineDispatchLease lease;
    ~LeaseOwner() noexcept {
        rs2fix::ReleaseGenuineX3AudioLease(&lease, rs2fix::ProductionGenuineResolverOps());
    }
};
} // namespace

extern "C" __declspec(noinline) void WINAPI X3DAudioInitialize(
    UINT32 mask, FLOAT speed, BYTE* handle) {
    // Capture here, not in a helper: this is the actual imported API return PC.
    const auto returnAddress = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    LeaseOwner owner{rs2fix::AcquireGenuineX3Audio(&g_genuine, g_bootstrap,
        rs2fix::ProductionGenuineResolverOps())};
    if (!owner.lease.valid) rs2fix::FailFastX3Audio();
    owner.lease.dispatch.initialize(mask, speed, handle);

    rs2fix::BootstrapContextV3 context{};
    context.size = sizeof(context);
    context.abiVersion = rs2fix::kBootstrapAbiVersion;
    context.hostModule = g_host;
    context.bootstrapModule = g_bootstrap;
    context.genuineX3AudioModule = owner.lease.dispatch.module;
    context.genuineExportsMask = rs2fix::kRequiredGenuineExports;
    context.triggerReturnAddress = returnAddress;
    context.startupThreadId = g_startupThread;
    context.currentThreadId = GetCurrentThreadId();
    context.staticLoad = g_staticLoad;
    context.triggerKind = rs2fix::kTriggerExeCrtInitialize;
    if (rs2fix::CheckStartupOpportunity(context, rs2fix::kSelectedStartupProfile,
            rs2fix::ProductionMemoryOps()) == rs2fix::StartupGateResult::Ready &&
        InterlockedCompareExchange(&g_optionalAttempted, 1, 0) == 0) {
        // Synchronous, one attempt, and still holding the same genuine lease.
        (void)rs2fix::LoadAndInitializeCompanion(g_bootstrap, context);
    }
}

extern "C" void WINAPI X3DAudioCalculate(const BYTE* handle, const void* listener,
    const void* emitter, UINT32 flags, void* settings) {
    if (!rs2fix::TryForwardCalculate(&g_genuine, g_bootstrap,
            rs2fix::ProductionGenuineResolverOps(), handle, listener, emitter, flags, settings))
        rs2fix::FailFastX3Audio();
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) noexcept {
    if (reason == DLL_PROCESS_ATTACH) {
        g_bootstrap = instance;
        g_host = GetModuleHandleW(nullptr);
        g_startupThread = GetCurrentThreadId();
        g_staticLoad = reserved != nullptr ? 1u : 0u;
    }
    return TRUE;
}
