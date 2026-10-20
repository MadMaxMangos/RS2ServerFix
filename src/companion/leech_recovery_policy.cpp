#include "companion/leech_recovery_policy.h"

namespace rs2fix::reporting {
namespace {
constexpr std::uint32_t kDirectReturns[] = {
    0xBF746E, 0xBD2CAC, 0xBE853A, 0xB9880D, 0xBE8044, 0xBD1AD9,
    0xBE874A, 0xBC32FD, 0xBE7E44, 0xBD1999, 0xBE874A, 0xBC32FD,
    0xBE7E44, 0xBD1999, 0xBE874A, 0xC02D42, 0xA4B370, 0xA341A7
};
static_assert(sizeof(kDirectReturns) / sizeof(kDirectReturns[0]) == 18 && kCaptureFrames == 32);
bool Active(const PrimaryCallbackTiming& timing) noexcept {
    return timing.phase == PrimaryCallbackTimingPhase::InProgress;
}
bool Endpoint(PrimaryCallbackTiming& timing, bool valid, std::uint64_t qpc) noexcept {
    if (!valid || !qpc || qpc > INT64_MAX || (timing.lastQpc && qpc < timing.lastQpc)) {
        timing.invalid = true;
        return false;
    }
    timing.lastQpc = qpc;
    return true;
}
void CloseOwn(PrimaryCallbackTiming& timing, std::uint64_t qpc) noexcept {
    if (timing.invalid) return;
    if (!timing.segmentStartQpc || qpc < timing.segmentStartQpc || timing.ticks > INT64_MAX) { timing.invalid = true; return; }
    const auto elapsed = qpc - timing.segmentStartQpc;
    if (elapsed > static_cast<std::uint64_t>(INT64_MAX) - timing.ticks) { timing.invalid = true; return; }
    timing.ticks += elapsed;
}
bool BeginOwn(PrimaryCallbackTiming& timing, bool valid, std::uint64_t qpc) noexcept {
    const bool endpoint = Endpoint(timing, valid, qpc);
    timing.segment = PrimaryCallbackTimingSegment::Own;
    timing.segmentStartQpc = endpoint ? qpc : 0;
    return !timing.invalid;
}
}

RecoveryCallbackClass ClassifyRecoveryCreateFrames(const std::uint32_t* frames, std::size_t count,
    bool truncated) noexcept {
    if (truncated || count > kCaptureFrames) return RecoveryCallbackClass::Truncated;
    if (!frames || count < 20) return RecoveryCallbackClass::Unknown;
    for (std::size_t i = 0; i < 18; ++i)
        if (frames[i] != kDirectReturns[i]) return RecoveryCallbackClass::Unknown;
    if ((frames[18] != 0x5F48E6 && frames[18] != 0x5F4953) || frames[19] != 0x585650)
        return RecoveryCallbackClass::Unknown;
    return RecoveryCallbackClass::NormalLeechSuccess;
}
bool RecoveryPumpHeadroomAvailable(CallerClass currentClass, std::size_t hostFrameCount, bool truncated) noexcept {
    if (truncated || currentClass != CallerClass::NormalPump || hostFrameCount < 3 || hostFrameCount > kCaptureFrames)
        return false;
    // 2 compiled DLL prefix + 20 fixed host returns + one margin <=31.
    // Subtract only after the checked lower bound, and never add an untrusted count.
    return hostFrameCount - 3 <= 8;
}

bool ClaimPrimaryCallbackTiming(PrimaryCallbackTiming& timing, bool valid, std::uint64_t qpc) noexcept {
    if (timing.phase != PrimaryCallbackTimingPhase::NotEntered) return false;
    timing.phase = PrimaryCallbackTimingPhase::InProgress;
    // Initialization is caller-owned and precedes guard install. Never turn an
    // unexpectedly populated NotEntered object into a seemingly fresh sample.
    if (timing.ticks || timing.lastQpc || timing.segmentStartQpc || timing.invalid ||
        timing.segment != PrimaryCallbackTimingSegment::None || timing.filterParent != PrimaryCallbackTimingSegment::None)
        timing.invalid = true;
    BeginOwn(timing, valid, qpc);
    return true;
}
bool EnterPrimaryCallbackNative(PrimaryCallbackTiming& timing, bool valid, std::uint64_t qpc) noexcept {
    if (!Active(timing)) return false;
    if (timing.segment != PrimaryCallbackTimingSegment::Own || timing.filterParent != PrimaryCallbackTimingSegment::None) {
        timing.invalid = true; return false;
    }
    Endpoint(timing, valid, qpc);
    CloseOwn(timing, qpc);
    timing.segment = PrimaryCallbackTimingSegment::Native;
    timing.segmentStartQpc = 0;
    return !timing.invalid;
}
bool LeavePrimaryCallbackNative(PrimaryCallbackTiming& timing, bool valid, std::uint64_t qpc) noexcept {
    if (!Active(timing)) return false;
    if (timing.segment != PrimaryCallbackTimingSegment::Native || timing.filterParent != PrimaryCallbackTimingSegment::None) {
        timing.invalid = true; return false;
    }
    return BeginOwn(timing, valid, qpc);
}
bool BeginPrimaryCallbackFilter(PrimaryCallbackTiming& timing, bool valid, std::uint64_t qpc) noexcept {
    if (!Active(timing)) return false;
    if ((timing.segment != PrimaryCallbackTimingSegment::Own && timing.segment != PrimaryCallbackTimingSegment::Native) ||
        timing.filterParent != PrimaryCallbackTimingSegment::None) { timing.invalid = true; return false; }
    const bool endpoint = Endpoint(timing, valid, qpc);
    if (timing.segment == PrimaryCallbackTimingSegment::Own) CloseOwn(timing, qpc);
    timing.filterParent = timing.segment;
    timing.segment = PrimaryCallbackTimingSegment::Filter;
    timing.segmentStartQpc = endpoint ? qpc : 0;
    return !timing.invalid;
}
bool EndPrimaryCallbackFilter(PrimaryCallbackTiming& timing, bool valid, std::uint64_t qpc) noexcept {
    if (!Active(timing)) return false;
    if (timing.segment != PrimaryCallbackTimingSegment::Filter ||
        (timing.filterParent != PrimaryCallbackTimingSegment::Own && timing.filterParent != PrimaryCallbackTimingSegment::Native)) {
        timing.invalid = true; return false;
    }
    const bool endpoint = Endpoint(timing, valid, qpc);
    CloseOwn(timing, qpc);
    timing.segment = timing.filterParent;
    timing.filterParent = PrimaryCallbackTimingSegment::None;
    timing.segmentStartQpc = timing.segment == PrimaryCallbackTimingSegment::Own && endpoint ? qpc : 0;
    return !timing.invalid;
}
bool BeginPrimaryCallbackUnwind(PrimaryCallbackTiming& timing, bool valid, std::uint64_t qpc) noexcept {
    if (!Active(timing)) return false;
    if ((timing.segment != PrimaryCallbackTimingSegment::Own && timing.segment != PrimaryCallbackTimingSegment::Native) ||
        timing.filterParent != PrimaryCallbackTimingSegment::None) { timing.invalid = true; return false; }
    Endpoint(timing, valid, qpc);
    // SEARCH already closed the last DLL-own interval. The gap up to this
    // termination handler is native exception dispatch/unwind, not DLL time.
    return BeginOwn(timing, valid, qpc);
}
bool FinalizePrimaryCallbackTiming(PrimaryCallbackTiming& timing, bool valid, std::uint64_t qpc) noexcept {
    if (!Active(timing)) return false;
    Endpoint(timing, valid, qpc);
    if (timing.segment != PrimaryCallbackTimingSegment::Own || timing.filterParent != PrimaryCallbackTimingSegment::None)
        timing.invalid = true;
    else CloseOwn(timing, qpc);
    timing.phase = timing.invalid ? PrimaryCallbackTimingPhase::CompleteInvalid : PrimaryCallbackTimingPhase::CompleteValid;
    timing.segment = timing.filterParent = PrimaryCallbackTimingSegment::None;
    timing.segmentStartQpc = 0;
    if (timing.invalid) timing.ticks = 0;
    return !timing.invalid;
}
void InvalidatePrimaryCallbackTiming(PrimaryCallbackTiming& timing) noexcept {
    if (Active(timing)) timing.invalid = true;
}
} // namespace rs2fix::reporting
