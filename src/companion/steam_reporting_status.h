#pragma once
#include "shared/steam_reporting_status.h"
#include "companion/steam_reporting_types.h"

namespace rs2fix::reporting {
static_assert(kReasonCount <= kStatusReasonSlots);
static_assert(kDurationClassCount == kStatusDurationClasses);
// Control words/readers are interlocked. Only the sole-owner payload uses aligned
// Windows/MSVC AMD64 release stores inside the interlocked sequence; this is not
// a portable C++ seqlock permission. Worker/foreign callers use sticky latches only.
bool InitializeStatus(StatusWire&, const StatusHeader&, const StatusPayload&) noexcept;
bool PublishStatus(StatusWire&, const StatusPayload&) noexcept;
void RevokeStatus(StatusWire&, Reason) noexcept;
void LoseStatus(StatusWire&, Reason) noexcept;
void StopStatus(StatusWire&, std::uint64_t qpc) noexcept;
bool StatusRevoked(const StatusWire&) noexcept;
// Coherent non-revoked copy only, NOT a readiness/identity/freshness verdict.
// The referenced storage must be the live writable StatusWire, not const data.
bool ReadLocalStatus(const StatusWire&, StatusHeader*, StatusPayload*) noexcept;
std::uint64_t ReadStatusWord(const std::uint64_t&) noexcept;
void StoreStatusWord(std::uint64_t&, std::uint64_t) noexcept;
bool IncrementCounter(std::uint64_t&, std::uint64_t amount = 1) noexcept;
bool AccountDuration(DurationCounters&, std::uint64_t elapsed, std::uint64_t frequency) noexcept;
} // namespace rs2fix::reporting
