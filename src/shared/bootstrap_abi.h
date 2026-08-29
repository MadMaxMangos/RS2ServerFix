#pragma once

#include <Windows.h>

#include <cstdint>

namespace rs2fix {

inline constexpr std::uint32_t kBootstrapAbiVersion = 1;

struct BootstrapContextV1 {
    std::uint32_t size;
    std::uint32_t abiVersion;
    HMODULE hostModule;
    HMODULE bootstrapModule;
    HMODULE genuineFaultrepModule;
    FARPROC genuineReportFault;
    std::uint32_t resolverStatus;
    DWORD resolverError;
};

static_assert(sizeof(BootstrapContextV1) == 48);

using InitializeV1Fn = DWORD(WINAPI*)(const BootstrapContextV1*);

inline constexpr DWORD kInitOk = 0;
inline constexpr DWORD kInitAlreadyInitialized = 1;
inline constexpr DWORD kInitInvalidContext = 2;
inline constexpr DWORD kInitHostIdentityFailed = 3;
inline constexpr DWORD kInitMarkerWriteFailed = 4;

} // namespace rs2fix
