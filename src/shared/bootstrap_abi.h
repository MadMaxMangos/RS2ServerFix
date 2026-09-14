#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>

namespace rs2fix {

inline constexpr std::uint32_t kBootstrapAbiVersion = 3;
inline constexpr std::uint32_t kGenuineInitializePresent = 1u;
inline constexpr std::uint32_t kGenuineCalculatePresent = 2u;
inline constexpr std::uint32_t kRequiredGenuineExports = 3u;
inline constexpr std::uint32_t kTriggerExeCrtInitialize = 1u;

struct BootstrapContextV3 {
    std::uint32_t size;
    std::uint32_t abiVersion;
    HMODULE hostModule;
    HMODULE bootstrapModule;
    HMODULE genuineX3AudioModule;
    std::uint32_t genuineExportsMask;
    std::uint32_t reserved;
    std::uintptr_t triggerReturnAddress;
    DWORD startupThreadId;
    DWORD currentThreadId;
    DWORD staticLoad;
    DWORD triggerKind;
};

static_assert(sizeof(void*) == 8);
static_assert(sizeof(BootstrapContextV3) == 64);
static_assert(offsetof(BootstrapContextV3, hostModule) == 8);
static_assert(offsetof(BootstrapContextV3, genuineExportsMask) == 32);
static_assert(offsetof(BootstrapContextV3, triggerReturnAddress) == 40);
static_assert(offsetof(BootstrapContextV3, startupThreadId) == 48);
static_assert(offsetof(BootstrapContextV3, triggerKind) == 60);
using InitializeV3Fn = DWORD(WINAPI*)(const BootstrapContextV3*);

inline constexpr DWORD kInitOk = 0;
inline constexpr DWORD kInitAlreadyInitialized = 1;
inline constexpr DWORD kInitInvalidContext = 2;
inline constexpr DWORD kInitHostIdentityFailed = 3;
inline constexpr DWORD kInitMarkerWriteFailed = 4;
inline constexpr DWORD kInitFixDisabled = 5;

} // namespace rs2fix
