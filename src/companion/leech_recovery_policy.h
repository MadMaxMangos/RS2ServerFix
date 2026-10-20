#pragma once
#include "companion/steam_reporting_types.h"

namespace rs2fix::reporting {
enum class RecoveryCallbackClass : std::uint32_t { Unknown, NormalLeechSuccess, Truncated };
// Only the independently verified two-frame DLL prefix may have been removed.
// No scan/skip/nearest-outer fallback; still-outer frames after 585650 are irrelevant.
RecoveryCallbackClass ClassifyRecoveryCreateFrames(const std::uint32_t*, std::size_t count,
    bool truncated) noexcept;
// This predicate is for the CURRENT owner service capture, never a cached
// capture's authority. hostFrameCount excludes the existing three DLL frames.
bool RecoveryPumpHeadroomAvailable(CallerClass currentClass, std::size_t hostFrameCount,
    bool truncated) noexcept;

enum class PrimaryCallbackTimingPhase : std::uint32_t { NotEntered, InProgress, CompleteValid, CompleteInvalid };
enum class PrimaryCallbackTimingSegment : std::uint32_t { None, Own, Native, Filter };
// Initialize once with {} BEFORE guard installation. Only the active attributed
// owner may claim or mutate it. No reset API: duplicate/stale/terminal callbacks
// and repeated publication must leave the completed measurement unchanged.
struct PrimaryCallbackTiming {
    PrimaryCallbackTimingPhase phase;
    PrimaryCallbackTimingSegment segment;
    PrimaryCallbackTimingSegment filterParent;
    std::uint64_t ticks, lastQpc, segmentStartQpc;
    bool invalid;
};
// Endpoints come ONLY from the caller's pure, non-latching diagnostic QPC read.
// Missing/zero/regressing/overflowing endpoints invalidate this measurement,
// never RuntimeClock, V3 duration state, admission or recovery fault policy.
// Claim returns whether this invocation claimed the one-shot measurement,
// including a claimed-but-invalid clock. Other bool results are diagnostics.
bool ClaimPrimaryCallbackTiming(PrimaryCallbackTiming&, bool clockValid, std::uint64_t qpc) noexcept;
bool EnterPrimaryCallbackNative(PrimaryCallbackTiming&, bool clockValid, std::uint64_t qpc) noexcept;
bool LeavePrimaryCallbackNative(PrimaryCallbackTiming&, bool clockValid, std::uint64_t qpc) noexcept;
// Search-filter work suspends an enclosing Own OR Native interval and restores
// it at EndFilter. This counts disjoint DLL filter work once, including when the
// original native call resumes. Nested/unprovable overlap invalidates the sample.
bool BeginPrimaryCallbackFilter(PrimaryCallbackTiming&, bool clockValid, std::uint64_t qpc) noexcept;
bool EndPrimaryCallbackFilter(PrimaryCallbackTiming&, bool clockValid, std::uint64_t qpc) noexcept;
// Actual unwind entry into the DLL termination handler ends excluded Native
// time and starts Own handler work. SEARCH alone never calls Finalize/Unwind.
bool BeginPrimaryCallbackUnwind(PrimaryCallbackTiming&, bool clockValid, std::uint64_t qpc) noexcept;
// Called once on ordinary return (including guard refusal) or from the actual
// DLL termination handler after BeginUnwind. Incomplete Native/filter scopes
// invalidate. Invalid completion stores ticks=0; true permits a measured zero.
bool FinalizePrimaryCallbackTiming(PrimaryCallbackTiming&, bool clockValid, std::uint64_t qpc) noexcept;
void InvalidatePrimaryCallbackTiming(PrimaryCallbackTiming&) noexcept;
static_assert(std::is_trivial_v<PrimaryCallbackTiming> && std::is_standard_layout_v<PrimaryCallbackTiming>);
} // namespace rs2fix::reporting
