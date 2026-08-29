#include "bootstrap/companion_loader.h"
#include "bootstrap/forwarder.h"
#include "bootstrap/genuine_resolver.h"
#include "shared/bootstrap_abi.h"

#include <Windows.h>

namespace {

PVOID volatile g_reportFault{};
HMODULE g_bootstrap{};

DWORD WINAPI BootstrapWorker(void* parameter) noexcept {
    const HMODULE bootstrap = static_cast<HMODULE>(parameter);
    const rs2fix::GenuineResolverResult genuine =
        rs2fix::ResolveGenuineReportFault(bootstrap);

    if (genuine.status == rs2fix::GenuineResolverStatus::Ok &&
        genuine.function != nullptr) {
        InterlockedCompareExchangePointer(
            &g_reportFault,
            reinterpret_cast<PVOID>(genuine.function),
            nullptr);
    }

    rs2fix::BootstrapContextV1 context{};
    context.size = sizeof(context);
    context.abiVersion = rs2fix::kBootstrapAbiVersion;
    context.hostModule = GetModuleHandleW(nullptr);
    context.bootstrapModule = bootstrap;
    context.genuineFaultrepModule = genuine.module;
    context.genuineReportFault =
        reinterpret_cast<FARPROC>(genuine.function);
    context.resolverStatus =
        static_cast<std::uint32_t>(genuine.status);
    context.resolverError = genuine.win32Error;

    rs2fix::LoadAndInitializeCompanion(bootstrap, context);
    return 0;
}

} // namespace

extern "C" EFaultRepRetVal APIENTRY ReportFault(
    _In_ LPEXCEPTION_POINTERS pointers,
    _In_ const DWORD options) {
    const auto function = reinterpret_cast<rs2fix::ReportFaultFn>(
        InterlockedCompareExchangePointer(
            &g_reportFault, nullptr, nullptr));
    return rs2fix::ForwardOrFail(function, pointers, options);
}

BOOL WINAPI DllMain(
    HINSTANCE instance,
    const DWORD reason,
    LPVOID) noexcept {
    if (reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    g_bootstrap = instance;
    const HANDLE worker = CreateThread(
        nullptr,
        0,
        BootstrapWorker,
        g_bootstrap,
        0,
        nullptr);
    if (worker != nullptr) {
        CloseHandle(worker);
    }
    return TRUE;
}
