#include "companion/companion_init.h"
#include "companion/build_identity.h"
#include "companion/console_status.h"
#include "companion/host_hash.h"
#include "companion/recon_fix.h"
#include "shared/path_identity.h"
#include "shared/selected_profile.h"
#include "shared/selected_recon_profile.h"

#include <cwchar>
#include <new>

namespace rs2fix {
namespace {
struct Workspace {
    wchar_t hostPath[kPathCapacity];
    wchar_t hostDirectory[kPathCapacity];
    wchar_t modulePath[kPathCapacity];
    wchar_t moduleDirectory[kPathCapacity];
    wchar_t expectedPath[kPathCapacity];
    wchar_t fallbackDirectory[kPathCapacity];
    wchar_t hostLeaf[260];
    wchar_t moduleLeaf[260];
    MarkerWriteResult markerWrite;
};
constexpr ReconMode kCompiledMode =
#ifdef RS2_RECON_ACTIVE
    ReconMode::Active;
#else
    ReconMode::Passive;
#endif

DWORD Finish(LONG volatile* state, DWORD result) noexcept {
    // Failed qualification or reporting still consumes the single attempt.
    InterlockedExchange(state, 2);
    return result;
}
HMODULE ModuleAt(const void* address) noexcept {
    MEMORY_BASIC_INFORMATION memory{};
    if (VirtualQuery(address, &memory, sizeof(memory)) != sizeof(memory) ||
        memory.State != MEM_COMMIT || memory.Type != MEM_IMAGE) return nullptr;
    return static_cast<HMODULE>(memory.AllocationBase);
}
bool SiblingModule(HMODULE module, const wchar_t* expectedLeaf, Workspace* work,
                   DWORD* error) noexcept {
    if (!GetBoundedModulePath(module, work->modulePath, kPathCapacity, error) ||
        !ExtractDirectoryAndLeaf(work->modulePath, kPathCapacity,
            work->moduleDirectory, kPathCapacity, work->moduleLeaf, 260, error) ||
        _wcsicmp(work->moduleDirectory, work->hostDirectory) != 0 ||
        _wcsicmp(work->moduleLeaf, expectedLeaf) != 0 ||
        !AppendPathLeaf(work->hostDirectory, kPathCapacity, expectedLeaf, 260,
            work->expectedPath, kPathCapacity, error)) return false;
    FileIdentity expected{}, actual{};
    return QueryFileIdentity(work->expectedPath, &expected, error) &&
        QueryFileIdentity(work->modulePath, &actual, error) &&
        SameFileIdentity(expected, actual);
}
bool GenuineModule(HMODULE module, Workspace* work, DWORD* error) noexcept {
    if (!BuildSystemX3AudioPath(work->expectedPath, kPathCapacity, error) ||
        !GetBoundedModulePath(module, work->modulePath, kPathCapacity, error)) return false;
    FileIdentity expected{}, actual{};
    if (!QueryFileIdentity(work->expectedPath, &expected, error) ||
        !QueryFileIdentity(work->modulePath, &actual, error) ||
        !SameFileIdentity(expected, actual)) return false;
    const auto initialize = GetProcAddress(module, "X3DAudioInitialize");
    const auto calculate = GetProcAddress(module, "X3DAudioCalculate");
    return initialize && calculate &&
        ModuleAt(reinterpret_cast<const void*>(initialize)) == module &&
        ModuleAt(reinterpret_cast<const void*>(calculate)) == module;
}
HANDLE ReadyFatalConsole(void*, DWORD* error) noexcept {
    const auto& ops = ProductionConsoleStatusOps();
    const HANDLE output = ops.getStdOutput(ops.context, error);
    DWORD mode{};
    // Do not wait for startup to expose stdout, and do not risk blocking on a
    // redirected pipe while startup must fail fast. An existing console only.
    if (!output || output == INVALID_HANDLE_VALUE ||
        GetFileType(output) != FILE_TYPE_CHAR || !GetConsoleMode(output, &mode))
        return INVALID_HANDLE_VALUE;
    return output;
}
} // namespace

DWORD ValidateBootstrapContextV3(const BootstrapContextV3* context) noexcept {
    if (!context || context->size != sizeof(BootstrapContextV3) ||
        context->abiVersion != kBootstrapAbiVersion || context->reserved != 0 ||
        !context->hostModule || !context->bootstrapModule || !context->genuineX3AudioModule ||
        context->hostModule != GetModuleHandleW(nullptr) ||
        context->hostModule == context->bootstrapModule ||
        context->bootstrapModule == context->genuineX3AudioModule ||
        context->hostModule == context->genuineX3AudioModule ||
        context->genuineExportsMask != kRequiredGenuineExports ||
        context->staticLoad != 1 || context->triggerKind != kTriggerExeCrtInitialize ||
        !context->startupThreadId || context->currentThreadId != context->startupThreadId ||
        context->currentThreadId != GetCurrentThreadId())
        return kInitInvalidContext;
    return kInitOk;
}

InitializationClaim ClaimInitialization(LONG volatile* state) noexcept {
    if (!state) return InitializationClaim::Running;
    const LONG previous = InterlockedCompareExchange(state, 1, 0);
    return previous == 0 ? InitializationClaim::Claimed :
        previous == 1 ? InitializationClaim::Running : InitializationClaim::Finished;
}

bool TryReportFatalInitialization(const wchar_t* primaryDirectory,
    const wchar_t* fallbackDirectory, const MarkerData& data,
    MarkerWriteResult* writeResult, const MarkerFileOps& markerOps,
    const ConsoleStatusOps& readyConsoleOps) noexcept {
    if (data.recon.outcome != ReconOutcome::Fatal || !writeResult) return false;
    MarkerData terminal = data;
    terminal.complete = true;
    terminal.initializeResult = kInitFixDisabled;
    const bool written = WriteMarkerWithFallback(primaryDirectory, fallbackDirectory,
        terminal, writeResult, markerOps);
    ConsoleReportContext report{};
    if (FormatConsoleStatus(terminal, *writeResult, &report) &&
        readyConsoleOps.getStdOutput && readyConsoleOps.write) {
        DWORD error{};
        const HANDLE output = readyConsoleOps.getStdOutput(readyConsoleOps.context, &error);
        if (output && output != INVALID_HANDLE_VALUE) {
            DWORD bytesWritten{};
            // One bounded owned ASCII line, one attempt, no retry or observer.
            (void)readyConsoleOps.write(readyConsoleOps.context, output,
                report.line, report.bytes, &bytesWritten, &error);
        }
    }
    return written && writeResult->written && writeResult->cleanupError == ERROR_SUCCESS &&
        writeResult->finalError == ERROR_SUCCESS;
}

DWORD RunCompanionInitialization(const BootstrapContextV3& context,
                                LONG volatile* state) noexcept {
    const DWORD validation = ValidateBootstrapContextV3(&context);
    if (validation != kInitOk || !state)
        return validation == kInitOk ? kInitInvalidContext : validation;
    if (ClaimInitialization(state) != InitializationClaim::Claimed)
        return kInitAlreadyInitialized;
    if (CheckStartupOpportunity(context, kSelectedStartupProfile,
            ProductionMemoryOps()) != StartupGateResult::Ready)
        return Finish(state, kInitInvalidContext);

    void* storage = VirtualAlloc(nullptr, sizeof(Workspace),
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    auto* work = storage ? ::new (storage) Workspace{} : nullptr;
    if (!work) return Finish(state, kInitHostIdentityFailed);
    DWORD error{};
    if (!GetBoundedModulePath(context.hostModule, work->hostPath, kPathCapacity, &error) ||
        !ExtractDirectoryAndLeaf(work->hostPath, kPathCapacity, work->hostDirectory,
            kPathCapacity, work->hostLeaf, 260, &error)) {
        VirtualFree(work, 0, MEM_RELEASE);
        return Finish(state, kInitHostIdentityFailed);
    }
    const HMODULE companion = ModuleAt(reinterpret_cast<const void*>(&RunCompanionInitialization));
    MarkerData marker{};
    GetSystemTime(&marker.utc);
    marker.processId = GetCurrentProcessId();
    marker.triggerKind = context.triggerKind;
    marker.mode = kCompiledMode;
    std::wmemcpy(marker.executableLeaf, work->hostLeaf, std::wcslen(work->hostLeaf) + 1);
    marker.bootstrapBesideExecutable = SiblingModule(
        context.bootstrapModule, L"X3DAudio1_7.dll", work, &error);
    marker.companionBesideExecutable = companion &&
        companion != context.hostModule && companion != context.bootstrapModule &&
        companion != context.genuineX3AudioModule &&
        SiblingModule(companion, L"RS2ServerFix.dll", work, &error);
    marker.genuineSystem32 = GenuineModule(context.genuineX3AudioModule, work, &error);
    marker.genuineExportsMask = marker.genuineSystem32 ? kRequiredGenuineExports : 0;

    HostHashLease lease;
    if (!marker.bootstrapBesideExecutable || !marker.companionBesideExecutable ||
        !marker.genuineSystem32) {
        marker.recon = {ReconOutcome::Disabled, FixReason::InvalidContext, error, false};
    } else {
        const HostHashResult host = AcquireHostHash(work->hostPath, &lease);
        marker.digest = host.hash.digest;
        marker.digestValid = host.hash.digestValid;
        marker.executableSize = host.hash.fileSize;
        marker.buildIdentity = ClassifyBuild(host.hash.digest, host.hash.digestValid);
        if (host.reason != FixReason::None || !host.hash.digestValid || !lease.valid()) {
            marker.recon = {ReconOutcome::Disabled, host.reason, host.hash.error, false};
        } else {
            marker.recon = RunReconFix(context, kSelectedStartupProfile, kSelectedReconProfile,
                kCompiledMode, host.hash.digest, ProductionReconOps(&lease));
        }
    }
    marker.initializeResult =
        marker.recon.reason == FixReason::None &&
        (marker.recon.outcome == ReconOutcome::Passive || marker.recon.outcome == ReconOutcome::Active)
        ? kInitOk : kInitFixDisabled;
    marker.complete = true; // a complete terminal diagnostic, not automatic acceptance
    const DWORD tempLength = GetTempPathW(static_cast<DWORD>(kPathCapacity),
        work->fallbackDirectory);
    if (!tempLength || tempLength >= kPathCapacity) work->fallbackDirectory[0] = L'\0';
    if (marker.recon.outcome == ReconOutcome::Fatal) {
        ConsoleStatusOps console = ProductionConsoleStatusOps();
        console.getStdOutput = ReadyFatalConsole;
        (void)TryReportFatalInitialization(work->hostDirectory,
            work->fallbackDirectory, marker, &work->markerWrite,
            ProductionMarkerFileOps(), console);
        // Reporting is best effort: even allocation or I/O failure cannot allow
        // host continuation. Unreal's full-dump handler may not be installed yet.
        FailFastRecon();
    }
    const bool written = WriteMarkerWithFallback(work->hostDirectory,
        work->fallbackDirectory, marker, &work->markerWrite);
    ConsoleReportContext report{};
    if (FormatConsoleStatus(marker, work->markerWrite, &report))
        (void)StartReporter(report);
    const DWORD result = written && work->markerWrite.written &&
        work->markerWrite.cleanupError == ERROR_SUCCESS && work->markerWrite.finalError == ERROR_SUCCESS
        ? marker.initializeResult : kInitMarkerWriteFailed;
    VirtualFree(work, 0, MEM_RELEASE);
    return Finish(state, result);
}
} // namespace rs2fix
