#include "companion/companion_init.h"

#include "bootstrap/bootstrap_types.h"
#include "companion/build_identity.h"
#include "companion/marker.h"
#include "companion/sha256.h"
#include "shared/path_identity.h"

#include <Windows.h>

#include <cwchar>

namespace rs2fix {
namespace {

DWORD FinishInitialization(
    LONG volatile* state,
    const DWORD result) noexcept {
    InterlockedExchange(state, 2);
    return result;
}

bool GetModuleDirectory(
    HMODULE module,
    wchar_t* directory,
    wchar_t* leaf,
    DWORD* error) noexcept {
    wchar_t path[kPathCapacity]{};
    return GetBoundedModulePath(
               module, path, kPathCapacity, error) &&
           ExtractDirectoryAndLeaf(
               path,
               directory,
               kPathCapacity,
               leaf,
               260,
               error);
}

HMODULE ModuleFromInitializerAddress() noexcept {
    MEMORY_BASIC_INFORMATION memory{};
    const SIZE_T queried = VirtualQuery(
        reinterpret_cast<const void*>(&RunCompanionInitialization),
        &memory,
        sizeof(memory));
    if (queried != sizeof(memory)) {
        return nullptr;
    }
    return static_cast<HMODULE>(memory.AllocationBase);
}

} // namespace

DWORD ValidateBootstrapContextV1(
    const BootstrapContextV1* context) noexcept {
    if (context == nullptr ||
        context->size != sizeof(BootstrapContextV1) ||
        context->abiVersion != kBootstrapAbiVersion ||
        context->hostModule == nullptr ||
        context->bootstrapModule == nullptr ||
        context->resolverStatus > static_cast<std::uint32_t>(
            GenuineResolverStatus::SelfAddress)) {
        return kInitInvalidContext;
    }

    const bool resolverSucceeded =
        context->resolverStatus == static_cast<std::uint32_t>(
            GenuineResolverStatus::Ok);
    const bool hasGenuineModule =
        context->genuineFaultrepModule != nullptr;
    const bool hasGenuineFunction =
        context->genuineReportFault != nullptr;
    if (resolverSucceeded != hasGenuineModule ||
        resolverSucceeded != hasGenuineFunction) {
        return kInitInvalidContext;
    }

    if (context->hostModule != GetModuleHandleW(nullptr)) {
        return kInitHostIdentityFailed;
    }
    return kInitOk;
}

InitializationClaim ClaimInitialization(
    LONG volatile* state) noexcept {
    if (state == nullptr) {
        return InitializationClaim::Running;
    }
    const LONG previous = InterlockedCompareExchange(state, 1, 0);
    if (previous == 0) {
        return InitializationClaim::Claimed;
    }
    if (previous == 1) {
        return InitializationClaim::Running;
    }
    return InitializationClaim::Finished;
}

DWORD RunCompanionInitialization(
    const BootstrapContextV1& context,
    LONG volatile* state) noexcept {
    const DWORD validation = ValidateBootstrapContextV1(&context);
    if (validation != kInitOk || state == nullptr) {
        return validation == kInitOk ? kInitInvalidContext : validation;
    }

    if (ClaimInitialization(state) != InitializationClaim::Claimed) {
        return kInitAlreadyInitialized;
    }

    OutputDebugStringW(L"[RS2ServerFix] companion-start\n");

    wchar_t executablePath[kPathCapacity]{};
    wchar_t executableDirectory[kPathCapacity]{};
    wchar_t executableLeaf[260]{};
    DWORD error = ERROR_SUCCESS;
    if (!GetBoundedModulePath(
            context.hostModule,
            executablePath,
            kPathCapacity,
            &error) ||
        !ExtractDirectoryAndLeaf(
            executablePath,
            executableDirectory,
            kPathCapacity,
            executableLeaf,
            260,
            &error)) {
        OutputDebugStringW(L"[RS2ServerFix] host-path-failed\n");
        return FinishInitialization(state, kInitHostIdentityFailed);
    }

    const FileHashResult hash = HashFileSha256(
        executablePath, GetTickCount64() + 10000);
    const BuildIdentity identity =
        ClassifyBuild(hash.digest, hash.digestValid);

    wchar_t bootstrapDirectory[kPathCapacity]{};
    wchar_t bootstrapLeaf[260]{};
    const bool bootstrapPathValid = GetModuleDirectory(
        context.bootstrapModule,
        bootstrapDirectory,
        bootstrapLeaf,
        &error);

    const HMODULE companionModule = ModuleFromInitializerAddress();
    wchar_t companionDirectory[kPathCapacity]{};
    wchar_t companionLeaf[260]{};
    const bool companionPathValid = companionModule != nullptr &&
        GetModuleDirectory(
            companionModule,
            companionDirectory,
            companionLeaf,
            &error);

    const DWORD provisionalResult = hash.digestValid
        ? kInitOk
        : kInitHostIdentityFailed;
    MarkerData marker{};
    marker.processId = GetCurrentProcessId();
    marker.executableSize = hash.fileSize;
    marker.digest = hash.digest;
    marker.digestValid = hash.digestValid;
    marker.buildIdentity = identity;
    marker.resolverStatus = static_cast<GenuineResolverStatus>(
        context.resolverStatus);
    marker.resolverError = context.resolverError;
    marker.initializeResult = provisionalResult;
    marker.bootstrapBesideExecutable = bootstrapPathValid &&
        _wcsicmp(bootstrapDirectory, executableDirectory) == 0;
    marker.companionBesideExecutable = companionPathValid &&
        _wcsicmp(companionDirectory, executableDirectory) == 0;
    marker.complete = hash.digestValid &&
        marker.resolverStatus == GenuineResolverStatus::Ok &&
        marker.bootstrapBesideExecutable &&
        marker.companionBesideExecutable;
    std::wmemcpy(
        marker.executableLeaf,
        executableLeaf,
        std::wcslen(executableLeaf) + 1);

    wchar_t fallbackDirectory[kPathCapacity]{};
    const DWORD fallbackLength = GetTempPathW(
        static_cast<DWORD>(kPathCapacity), fallbackDirectory);
    if (fallbackLength == 0 || fallbackLength >= kPathCapacity) {
        OutputDebugStringW(L"[RS2ServerFix] temp-path-failed\n");
        return FinishInitialization(state, kInitMarkerWriteFailed);
    }

    const MarkerWriteResult write = WriteMarkerWithFallback(
        executableDirectory, fallbackDirectory, marker);
    if (!write.written) {
        OutputDebugStringW(L"[RS2ServerFix] marker-failed\n");
        return FinishInitialization(state, kInitMarkerWriteFailed);
    }

    OutputDebugStringW(L"[RS2ServerFix] companion-complete\n");
    return FinishInitialization(state, provisionalResult);
}

} // namespace rs2fix
