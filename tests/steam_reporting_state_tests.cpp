#include "test_framework.h"
#include "companion/steam_reporting_state.h"
#include <limits>

using namespace rs2fix::reporting;
namespace {
ProducerState Ready(Mode mode = Mode::Repair) {
    ProducerState state{};
    RS2_CHECK(InitializeProducer(state, mode, 1000) == Reason::None);
    RS2_CHECK(SetProducerEpoch(state, 1, 1) == Reason::None);
    return state;
}
ProducerSample Sample(std::int64_t now, bool requested, float timer) {
    return {now, {65, 24, 64}, 24, timer, requested, false};
}
void Stage(ProducerState& state) {
    RS2_CHECK(RecordStagedRequest(state, 0, 24, 64, Sample(0, true, 1.0f), true) == Reason::None);
}
} // namespace
void ReportingStateTests() {
    auto state = Ready();
    Stage(state);
    RS2_CHECK(CanStageRequest(state, 20000) == Reason::Pending);
    RS2_CHECK(ObserveProducer(state, Sample(44000, true, 25.0f)) == Reason::Pending);
    RS2_CHECK(state.pending.stagedQpc == 0 && state.pending.previousSetQpc == 44000);
    RS2_CHECK(CanStageRequest(state, 44999) == Reason::Pending);
    RS2_CHECK(CanStageRequest(state, 45000) == Reason::None && !state.pending.active);

    state = Ready(); Stage(state);
    RS2_CHECK(ObserveProducer(state, Sample(19000, true, 19.5f)) == Reason::Pending);
    RS2_CHECK(ObserveProducer(state, Sample(19500, false, 0.25f)) == Reason::None);
    RS2_CHECK(!state.pending.active && state.fresh.valid && state.fresh.lowerBoundQpc == 19000);
    FreshTuple fresh{};
    auto exactAge = state, expiredAge = state;
    RS2_CHECK(ReadFreshTuple(exactAge, 64000, {65,24,64}, 24, &fresh) == Reason::None);
    RS2_CHECK(ReadFreshTuple(expiredAge, 64001, {65,24,64}, 24, &fresh) == Reason::FreshnessExpired);
    RS2_CHECK(!fresh.valid);
    // A later ordinary sample/reset cannot renew the timestamp.
    RS2_CHECK(ObserveProducer(state, Sample(30000, false, 0.0f)) == Reason::None);
    RS2_CHECK(state.fresh.lowerBoundQpc == 19000 && state.witnessSequence == 1);
    RS2_CHECK(ReadFreshTuple(state, 31000, {64,24,64}, 24, &fresh) == Reason::PreparedMismatch);
    RS2_CHECK(ReadFreshTuple(state, 32000, {65,24,64}, 25, &fresh) == Reason::PreparedMismatch);

    for (unsigned failure = 0; failure < 5; ++failure) {
        state = Ready(); Stage(state);
        auto sample = Sample(1000, false, 0.0f);
        if (failure == 0) sample.dirty = true;
        if (failure == 1) sample.timer = 1.0f;
        if (failure == 2) sample.outer.bots = 23;
        if (failure == 3) sample.gameBots = 25;
        if (failure == 4) sample.outer.maximum = 63;
        RS2_CHECK(ObserveProducer(state, sample) == Reason::ProducerAmbiguous);
        RS2_CHECK(!state.pending.active && !state.fresh.valid);
        RS2_CHECK(CanStageRequest(state, 19999) == Reason::RequestFloor);
        RS2_CHECK(CanStageRequest(state, 20000) == Reason::None);
    }
    state = Ready(); Stage(state);
    RS2_CHECK(SetProducerEpoch(state, 2, 2) == Reason::None);
    RS2_CHECK(!state.pending.active && !state.fresh.valid);
    RS2_CHECK(CanStageRequest(state, 1000) == Reason::RequestFloor);
    InvalidateProducer(state);
    RS2_CHECK(CanStageRequest(state, 20000) == Reason::SourceUnavailable);
    RS2_CHECK(SetProducerEpoch(state, 2, 2) == Reason::None);
    RS2_CHECK(CanStageRequest(state, 20000) == Reason::None);
    RS2_CHECK(SetProducerEpoch(state, 1, 2) == Reason::LifecycleCrossing);
    RS2_CHECK(CanStageRequest(state, 40000) == Reason::LifecycleCrossing);

    state = Ready();
    RS2_CHECK(RecordStagedRequest(state, 0, 24, 64, Sample(0, false, 0), false) == Reason::ProducerAmbiguous);
    RS2_CHECK(state.pending.active && !state.pending.previousSet);
    RS2_CHECK(ObserveProducer(state, Sample(1000, false, 0)) == Reason::ProducerAmbiguous);
    RS2_CHECK(!state.fresh.valid);
    state = Ready();
    RS2_CHECK(RecordStagedRequest(state, 0, 24, 64, Sample(0, false, 0), false) == Reason::ProducerAmbiguous);
    RS2_CHECK(ObserveProducer(state, Sample(1000, true, 2)) == Reason::Pending);
    RS2_CHECK(ObserveProducer(state, Sample(2000, false, 0)) == Reason::None);
    RS2_CHECK(state.fresh.lowerBoundQpc == 1000);

    state = Ready(Mode::Observe);
    RS2_CHECK(CanStageRequest(state, 0) == Reason::ConfigDisabled);
    RS2_CHECK(RecordStagedRequest(state, 0, 24, 64, Sample(0,true,1), true) == Reason::ConfigDisabled);
    RS2_CHECK(!state.pending.active && !state.haveRequest);
    state = Ready(); Stage(state);
    RS2_CHECK(ObserveProducer(state, Sample(1, true, (std::numeric_limits<float>::quiet_NaN)())) == Reason::ProducerAmbiguous);
    RS2_CHECK(!state.pending.active && !state.fresh.valid);
    state = Ready();
    RS2_CHECK(CanStageRequest(state, 10) == Reason::None);
    RS2_CHECK(CanStageRequest(state, 9) == Reason::ClockFailed);
    RS2_CHECK(CanStageRequest(state, 20) == Reason::ClockFailed);
    RS2_CHECK(InitializeProducer(state, Mode::Repair, (std::numeric_limits<std::int64_t>::max)()) == Reason::ClockFailed);
    state = Ready(); state.requestSequence = (std::numeric_limits<std::uint64_t>::max)();
    RS2_CHECK(CanStageRequest(state, 0) == Reason::CounterOverflow);
}
