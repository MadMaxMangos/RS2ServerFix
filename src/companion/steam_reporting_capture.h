#pragma once
#include "companion/steam_reporting_ancestry.h"
#include "shared/startup_profile.h"

namespace rs2fix::reporting {
inline constexpr std::size_t kCapturePrefixLimit = 8;
inline constexpr std::size_t kCaptureFragmentLimit = 16;
struct CaptureExtent { std::uint32_t begin; std::uint32_t end; };
struct CaptureScope {
    CaptureExtent fragments[kCaptureFragmentLimit];
    std::size_t fragmentCount;
};
struct CaptureProfile {
    std::uintptr_t companionBase;
    std::uint32_t companionSize;
    std::uintptr_t hostBase;
    std::uint32_t hostSize;
    CaptureScope prefix[kCapturePrefixLimit];
    std::size_t prefixCount;
};
// Cold qualification only. The first scope is CaptureHostCallers itself; callers
// lists its exact noinline callers in nearest-first order. No DbgHelp, new import,
// native hook or raw stack scan. Scope records come from this module's .pdata.
bool PrepareCaptureProfile(HMODULE companion, std::uintptr_t hostBase,
    std::uint32_t hostSize, const void* const* callers, std::size_t callerCount,
    CaptureProfile* output) noexcept;
// Every own-prefix frame must match before any host frame is consumed. Foreign
// frames after that prefix become sentinels in-place, never silently removed.
// Raw addresses are invocation-local and never enter records/current status.
__declspec(noinline) bool CaptureHostCallers(const CaptureProfile&,
    std::uint32_t (&hostFrames)[kCaptureFrames], std::size_t* count,
    bool* truncated) noexcept;
} // namespace rs2fix::reporting
