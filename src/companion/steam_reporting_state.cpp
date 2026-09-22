#include "companion/steam_reporting_state.h"
#include <cmath>
#include <limits>

namespace rs2fix::reporting {
namespace {
Reason Fault(ProducerState& state, Reason reason) noexcept {
    if (state.fault == Reason::None) state.fault = reason;
    state.pending = {}; state.fresh = {};
    return state.fault;
}
Reason Clock(ProducerState& state, std::int64_t now) noexcept {
    if (state.fault != Reason::None) return state.fault;
    if (state.frequency <= 0 || now < 0 || (state.haveClock && now < state.lastQpc))
        return Fault(state, Reason::ClockFailed);
    state.lastQpc = now; state.haveClock = true;
    return Reason::None;
}
bool Timer(float value) noexcept { return std::isfinite(value) && value >= 0; }
void ExpirePending(ProducerState& state, std::int64_t now) noexcept {
    if (state.pending.active && now - state.pending.stagedQpc >=
        state.frequency * kFreshnessSeconds) state.pending = {};
}
bool Supported(const NativeCounts& counts, std::uint32_t bots) noexcept {
    return counts.maximum <= 255 && bots <= counts.maximum && counts.bots <= counts.maximum;
}
} // namespace

Reason InitializeProducer(ProducerState& state, Mode mode, std::int64_t frequency) noexcept {
    state = {};
    state.mode = mode;
    if (frequency <= 0 || frequency > (std::numeric_limits<std::int64_t>::max)() / kFreshnessSeconds)
        return Fault(state, Reason::ClockFailed);
    state.frequency = frequency;
    if (mode != Mode::Observe && mode != Mode::Repair) return Fault(state, Reason::ConfigDisabled);
    return Reason::None;
}
void InvalidateProducer(ProducerState& state) noexcept {
    state.pending = {}; state.fresh = {};
    state.epochReady = false;
    // Epoch counters are retained to reject reuse. A new live identity must be
    // assigned a strictly newer token by the owner, never reconstructed from B.
}
Reason SetProducerEpoch(ProducerState& state, std::uint64_t source, std::uint64_t binding) noexcept {
    if (state.fault != Reason::None) return state.fault;
    if (!source || !binding) { InvalidateProducer(state); return Reason::SourceUnavailable; }
    if (source < state.sourceEpoch || binding < state.bindingEpoch)
        return Fault(state, Reason::LifecycleCrossing);
    if (source != state.sourceEpoch || binding != state.bindingEpoch) InvalidateProducer(state);
    state.sourceEpoch = source; state.bindingEpoch = binding;
    state.epochReady = true;
    return Reason::None;
}
Reason CanStageRequest(ProducerState& state, std::int64_t now) noexcept {
    const auto clock = Clock(state, now);
    if (clock != Reason::None) return clock;
    if (state.mode != Mode::Repair) return Reason::ConfigDisabled;
    if (!state.epochReady || !state.sourceEpoch || !state.bindingEpoch) return Reason::SourceUnavailable;
    ExpirePending(state, now);
    if (state.pending.active) return Reason::Pending;
    if (state.haveRequest && now - state.lastRequestQpc < state.frequency * kRequestFloorSeconds)
        return Reason::RequestFloor;
    if (state.requestSequence == (std::numeric_limits<std::uint64_t>::max)())
        return Fault(state, Reason::CounterOverflow);
    return Reason::None;
}
Reason RecordStagedRequest(ProducerState& state, std::int64_t stagedQpc, std::uint32_t bots, std::uint32_t maximum,
    const ProducerSample& readBack, bool readBackValid) noexcept {
    const auto admission = CanStageRequest(state, stagedQpc);
    if (admission != Reason::None) return admission;
    if (maximum > 255 || bots > maximum) return Fault(state, Reason::UnsupportedCounts);
    state.haveRequest = true; state.lastRequestQpc = stagedQpc;
    state.pending = {};
    auto& pending = state.pending;
    pending.active = true; pending.sequence = ++state.requestSequence;
    pending.sourceEpoch = state.sourceEpoch; pending.bindingEpoch = state.bindingEpoch;
    pending.stagedQpc = stagedQpc; pending.bots = bots; pending.maximum = maximum;
    const auto clock = Clock(state, readBack.qpc);
    if (clock != Reason::None) return clock;
    ExpirePending(state, readBack.qpc);
    if (!pending.active) return Reason::FreshnessExpired;
    if (!readBackValid || !readBack.requested || !Timer(readBack.timer))
        return Reason::ProducerAmbiguous;
    pending.previousSet = true;
    pending.previousSetQpc = readBack.qpc; pending.previousTimer = readBack.timer;
    return Reason::None;
}
Reason ObserveProducer(ProducerState& state, const ProducerSample& sample) noexcept {
    const auto clock = Clock(state, sample.qpc);
    if (clock != Reason::None) return clock;
    const bool hadPending = state.pending.active;
    ExpirePending(state, sample.qpc);
    if (!state.pending.active) return hadPending ? Reason::FreshnessExpired : Reason::None;
    auto& pending = state.pending;
    if (pending.sourceEpoch != state.sourceEpoch || pending.bindingEpoch != state.bindingEpoch) {
        InvalidateProducer(state); return Reason::SourceLifetime;
    }
    if (!Timer(sample.timer)) { InvalidateProducer(state); return Reason::ProducerAmbiguous; }
    if (sample.requested) {
        pending.previousSet = true; pending.previousSetQpc = sample.qpc;
        pending.previousTimer = sample.timer;
        return Reason::Pending;
    }
    // A0 is now clear. Retire the claim even when the other consumption
    // predicates fail; a later ordinary timer reset must not revive it.
    const auto previous = pending;
    state.pending = {}; state.fresh = {};
    if (!previous.previousSet || sample.dirty || sample.timer >= previous.previousTimer ||
        !Supported(sample.outer, sample.gameBots) || previous.maximum != sample.outer.maximum ||
        previous.bots != sample.outer.bots ||
        previous.bots != sample.gameBots) return Reason::ProducerAmbiguous;
    if (state.witnessSequence == (std::numeric_limits<std::uint64_t>::max)())
        return Fault(state, Reason::CounterOverflow);
    state.fresh = {sample.outer, ++state.witnessSequence, previous.sequence,
        state.sourceEpoch, state.bindingEpoch, previous.previousSetQpc, true};
    return Reason::None;
}
Reason ReadFreshTuple(ProducerState& state, std::int64_t now, const NativeCounts& currentOuter,
    std::uint32_t gameBots, FreshTuple* output) noexcept {
    if (output) *output = {};
    const auto clock = Clock(state, now);
    if (clock != Reason::None) return clock;
    if (!output || state.mode != Mode::Repair || !state.fresh.valid)
        return Reason::FreshnessExpired;
    const auto& fresh = state.fresh;
    if (fresh.sourceEpoch != state.sourceEpoch || fresh.bindingEpoch != state.bindingEpoch) {
        InvalidateProducer(state); return Reason::SourceLifetime;
    }
    if (now - fresh.lowerBoundQpc > state.frequency * kFreshnessSeconds) {
        state.fresh = {}; return Reason::FreshnessExpired;
    }
    if (!Supported(currentOuter, gameBots) || !EqualCounts(currentOuter, fresh.counts) ||
        gameBots != fresh.counts.bots) return Reason::PreparedMismatch;
    *output = fresh;
    return Reason::None;
}
} // namespace rs2fix::reporting
