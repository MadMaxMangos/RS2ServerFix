#pragma once

#include "companion/steam_reporting_types.h"
#include <cstddef>
#include <cstdint>

namespace rs2fix::reporting {
inline constexpr std::uint32_t kUnqualifiedHostFrame = 0xFFFFFFFFU;

struct AncestryProfile {
    std::uint32_t builderAdapterReturn;
    std::uint32_t taskDispatchReturn;
    std::uint32_t taskPumpReturn;
    std::uint32_t leechUpdateReturns[2];
    std::uint32_t leechTickReturns[2];
    std::uint32_t subsystemReturn;
    std::uint32_t worldReturns[2];
    std::uint32_t engineReturn;
    std::uint32_t spinReturns[2];
    std::uint32_t shutdownReturn;
    std::uint32_t exitReturns[2];
    std::uint32_t callbackReturn;
};
const AncestryProfile& ProductionAncestryProfile() noexcept;

// Pure classification of at most kCaptureFrames caller-owned scalar RVAs.
// The capture layer must first validate/remove ONLY its exact compiled DLL
// prefix. It retains every subsequent frame in order, using the sentinel for
// an out-of-host/unknown frame. These functions never scan for a later match,
// skip an intervening frame, capture a stack, or read native source state.
//
// A complete relevant prefix determines the nearest context. Any still-outer
// frames are ignored, never used as a fallback or to upgrade an inner spin.
// The capture layer owns truncation detection; explicit truncation or count>32
// returns Truncated, even when the visible prefix would otherwise match.
CallerClass ClassifyBuilderFrames(const std::uint32_t* frames, std::size_t count,
    bool truncated) noexcept;
CallerClass ClassifyPumpFrames(const std::uint32_t* frames, std::size_t count,
    bool truncated) noexcept;
// Explicit immutable profiles permit actual compiled fixture addresses. They
// do not change the consecutive/nearest-parent rule or add a scanning fallback.
CallerClass ClassifyBuilderFrames(const AncestryProfile&, const std::uint32_t*,
    std::size_t count, bool truncated) noexcept;
CallerClass ClassifyPumpFrames(const AncestryProfile&, const std::uint32_t*,
    std::size_t count, bool truncated) noexcept;
} // namespace rs2fix::reporting
