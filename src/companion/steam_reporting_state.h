#pragma once
#include "companion/steam_reporting_types.h"

namespace rs2fix::reporting {
struct ProducerSample {
    std::int64_t qpc;
    NativeCounts outer;
    std::uint32_t gameBots;
    float timer;
    bool requested;
    bool dirty;
};
struct PendingRequest {
    std::uint64_t sequence;
    std::uint64_t sourceEpoch;
    std::uint64_t bindingEpoch;
    std::int64_t stagedQpc;
    std::int64_t previousSetQpc;
    std::uint32_t bots;
    std::uint32_t maximum;
    float previousTimer;
    bool active;
    bool previousSet;
};
struct FreshTuple {
    NativeCounts counts;
    std::uint64_t witness;
    std::uint64_t request;
    std::uint64_t sourceEpoch;
    std::uint64_t bindingEpoch;
    std::int64_t lowerBoundQpc;
    bool valid;
};
// Owner-only POD. The tracker proves only the producer transition; callers must
// independently qualify native identities, thread/ancestry, prepared objects and
// final atomic admission. These functions never dereference or mutate the game.
struct ProducerState {
    Mode mode;
    Reason fault;
    std::int64_t frequency;
    std::int64_t lastQpc;
    std::int64_t lastRequestQpc;
    std::uint64_t sourceEpoch;
    std::uint64_t bindingEpoch;
    std::uint64_t requestSequence;
    std::uint64_t witnessSequence;
    bool haveClock;
    bool haveRequest;
    bool epochReady;
    PendingRequest pending;
    FreshTuple fresh;
};
static_assert(std::is_trivial_v<ProducerState> && std::is_standard_layout_v<ProducerState>);

Reason InitializeProducer(ProducerState&, Mode, std::int64_t frequency) noexcept;
// Invalidate only DLL claims. The process-global request floor is never reset
// by travel, binding changes or a missed read-back.
void InvalidateProducer(ProducerState&) noexcept;
Reason SetProducerEpoch(ProducerState&, std::uint64_t source, std::uint64_t binding) noexcept;
Reason CanStageRequest(ProducerState&, std::int64_t now) noexcept;
// Call AFTER the admitted B/A0 native store pair, using its pre-store timestamp.
// Failed read-back keeps Pending without a witness seed; it must still expire
// or be observed consumed before a subsequent staging pair is allowed.
Reason RecordStagedRequest(ProducerState&, std::int64_t stagedQpc, std::uint32_t bots, std::uint32_t maximum,
    const ProducerSample& readBack, bool readBackValid) noexcept;
Reason ObserveProducer(ProducerState&, const ProducerSample&) noexcept;
Reason ReadFreshTuple(ProducerState&, std::int64_t now, const NativeCounts& currentOuter,
    std::uint32_t gameBots, FreshTuple* output) noexcept;
} // namespace rs2fix::reporting
