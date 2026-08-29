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

struct InitializationWorkspace {
    wchar_t executablePath[kPathCapacity];
    wchar_t executableDirectory[kPathCapacity];
    wchar_t bootstrapDirectory[kPathCapacity];
    wchar_t companionDirectory[kPathCapacity];
    wchar_t fallbackDirectory[kPathCapacity];
    wchar_t executableLeaf[260];
    wchar_t scratchLeaf[260];
    MarkerWriteResult markerWrite;
};

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
    if (directory == nullptr || leaf == nullptr) {
        if (error != nullptr) {
            *error = ERROR_INVALID_PARAMETER;
        }
        return false;
    }
    if (!GetBoundedModulePath(
            module, directory, kPathCapacity, error)) {
        return false;
    }

    const std::size_t length = wcsnlen_s(directory, kPathCapacity);
    std::size_t separator = length;
    while (separator != 0) {
        --separator;
        if (directory[separator] == L'\\' ||
            directory[separator] == L'/') {
            break;
        }
    }
    if (length == 0 || length >= kPathCapacity ||
        (directory[separator] != L'\\' &&
         directory[separator] != L'/') ||
        separator + 1 >= length) {
        directory[0] = L'\0';
        leaf[0] = L'\0';
        if (error != nullptr) {
            *error = ERROR_INVALID_NAME;
        }
        return false;
    }
    const std::size_t leafLength = length - separator - 1;
    if (leafLength >= 260) {
        directory[0] = L'\0';
        leaf[0] = L'\0';
        if (error != nullptr) {
            *error = ERROR_INSUFFICIENT_BUFFER;
        }
        return false;
    }
    std::wmemcpy(leaf, directory + separator + 1, leafLength);
    leaf[leafLength] = L'\0';
    directory[separator] = L'\0';
    if (error != nullptr) {
        *error = ERROR_SUCCESS;
    }
    return true;
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

    auto* workspace = static_cast<InitializationWorkspace*>(VirtualAlloc(
        nullptr,
        sizeof(InitializationWorkspace),
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE));
    if (workspace == nullptr) {
        OutputDebugStringW(L"[RS2ServerFix] workspace-allocation-failed\n");
        return FinishInitialization(state, kInitHostIdentityFailed);
    }

    DWORD error = ERROR_SUCCESS;
    if (!GetBoundedModulePath(
            context.hostModule,
            workspace->executablePath,
            kPathCapacity,
            &error) ||
        !ExtractDirectoryAndLeaf(
            workspace->executablePath,
            workspace->executableDirectory,
            kPathCapacity,
            workspace->executableLeaf,
            260,
            &error)) {
        OutputDebugStringW(L"[RS2ServerFix] host-path-failed\n");
        VirtualFree(workspace, 0, MEM_RELEASE);
        return FinishInitialization(state, kInitHostIdentityFailed);
    }

    const FileHashResult hash = HashFileSha256(
        workspace->executablePath, GetTickCount64() + 10000);
    const BuildIdentity identity =
        ClassifyBuild(hash.digest, hash.digestValid);

    const bool bootstrapPathValid = GetModuleDirectory(
        context.bootstrapModule,
        workspace->bootstrapDirectory,
        workspace->scratchLeaf,
        &error);

    const HMODULE companionModule = ModuleFromInitializerAddress();
    const bool companionPathValid = companionModule != nullptr &&
        GetModuleDirectory(
            companionModule,
            workspace->companionDirectory,
            workspace->scratchLeaf,
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
        _wcsicmp(
            workspace->bootstrapDirectory,
            workspace->executableDirectory) == 0;
    marker.companionBesideExecutable = companionPathValid &&
        _wcsicmp(
            workspace->companionDirectory,
            workspace->executableDirectory) == 0;
    marker.complete = hash.digestValid &&
        marker.resolverStatus == GenuineResolverStatus::Ok &&
        marker.bootstrapBesideExecutable &&
        marker.companionBesideExecutable;
    std::wmemcpy(
        marker.executableLeaf,
        workspace->executableLeaf,
        std::wcslen(workspace->executableLeaf) + 1);

    const DWORD fallbackLength = GetTempPathW(
        static_cast<DWORD>(kPathCapacity),
        workspace->fallbackDirectory);
    if (fallbackLength == 0 || fallbackLength >= kPathCapacity) {
        OutputDebugStringW(L"[RS2ServerFix] temp-path-failed\n");
        VirtualFree(workspace, 0, MEM_RELEASE);
        return FinishInitialization(state, kInitMarkerWriteFailed);
    }

    const bool markerWritten = WriteMarkerWithFallback(
        workspace->executableDirectory,
        workspace->fallbackDirectory,
        marker,
        &workspace->markerWrite);
    if (!markerWritten || !workspace->markerWrite.written) {
        OutputDebugStringW(L"[RS2ServerFix] marker-failed\n");
        VirtualFree(workspace, 0, MEM_RELEASE);
        return FinishInitialization(state, kInitMarkerWriteFailed);
    }

    OutputDebugStringW(L"[RS2ServerFix] companion-complete\n");
    VirtualFree(workspace, 0, MEM_RELEASE);
    return FinishInitialization(state, provisionalResult);
}

} // namespace rs2fix
