#include "companion/leech_recovery_policy.h"
#include "test_framework.h"
#include <array>
#include <cstring>
#include <limits>

namespace rs2fix::testcases {
namespace {
using namespace reporting;
constexpr std::array<std::uint32_t, 20> kDirect{
    0xBF746E, 0xBD2CAC, 0xBE853A, 0xB9880D, 0xBE8044, 0xBD1AD9,
    0xBE874A, 0xBC32FD, 0xBE7E44, 0xBD1999, 0xBE874A, 0xBC32FD,
    0xBE7E44, 0xBD1999, 0xBE874A, 0xC02D42, 0xA4B370, 0xA341A7,
    0x5F48E6, 0x585650
};
void ExactCreateAncestry() {
    auto direct = kDirect;
    RS2_CHECK(ClassifyRecoveryCreateFrames(direct.data(), direct.size(), false) == RecoveryCallbackClass::NormalLeechSuccess);
    direct[18] = 0x5F4953;
    RS2_CHECK(ClassifyRecoveryCreateFrames(direct.data(), direct.size(), false) == RecoveryCallbackClass::NormalLeechSuccess);
    for (std::size_t i = 0; i < kDirect.size(); ++i) {
        direct = kDirect; direct[i] = 0xFFFFFFFF;
        RS2_CHECK(ClassifyRecoveryCreateFrames(direct.data(), direct.size(), false) == RecoveryCallbackClass::Unknown);
    }
    for (const auto crossing : {0xA4B43EU, 0xBA5A58U, 0xA48BD4U, 0xADE7DU, 0xADE9DU, 0xA48F4DU, 0xA49F93U}) {
        direct = kDirect; direct[16] = crossing;
        RS2_CHECK(ClassifyRecoveryCreateFrames(direct.data(), direct.size(), false) == RecoveryCallbackClass::Unknown);
    }
    RS2_CHECK(ClassifyRecoveryCreateFrames(kDirect.data(), 19, false) == RecoveryCallbackClass::Unknown);
    RS2_CHECK(ClassifyRecoveryCreateFrames(nullptr, 20, false) == RecoveryCallbackClass::Unknown);
    RS2_CHECK(ClassifyRecoveryCreateFrames(kDirect.data(), 20, true) == RecoveryCallbackClass::Truncated);
    // Removing one repeated continuation must not collapse into a valid route.
    std::array<std::uint32_t, 32> frames{};
    for (std::size_t i = 0; i < 10; ++i) frames[i] = kDirect[i];
    for (std::size_t i = 10; i < 19; ++i) frames[i] = kDirect[i + 1];
    RS2_CHECK(ClassifyRecoveryCreateFrames(frames.data(), 19, false) == RecoveryCallbackClass::Unknown);
    // An interposed DLL/foreign frame is not removed or bypassed by scanning.
    frames[0] = 0xFFFFFFFF;
    for (std::size_t i = 0; i < kDirect.size(); ++i) frames[i + 1] = kDirect[i];
    RS2_CHECK(ClassifyRecoveryCreateFrames(frames.data(), 21, false) == RecoveryCallbackClass::Unknown);
    // Complete inner authority ignores only still-outer frames after engine.
    for (std::size_t i = 0; i < kDirect.size(); ++i) frames[i] = kDirect[i];
    frames[20] = 0xFFFFFFFF; frames[21] = 0xA48F4D;
    RS2_CHECK(ClassifyRecoveryCreateFrames(frames.data(), 22, false) == RecoveryCallbackClass::NormalLeechSuccess);
    frames[17] = 0xA48F4D; // Nearest spin cannot borrow the outer normal engine.
    frames[22] = 0xA341A7; frames[23] = 0x5F48E6; frames[24] = 0x585650;
    RS2_CHECK(ClassifyRecoveryCreateFrames(frames.data(), 25, false) == RecoveryCallbackClass::Unknown);
    RS2_CHECK(ClassifyRecoveryCreateFrames(frames.data(), 33, false) == RecoveryCallbackClass::Truncated);
}
void SameServiceHeadroom() {
    RS2_CHECK(RecoveryPumpHeadroomAvailable(CallerClass::NormalPump, 3, false));
    RS2_CHECK(RecoveryPumpHeadroomAvailable(CallerClass::NormalPump, 11, false)); // outer8, 22+8+1=31
    RS2_CHECK(!RecoveryPumpHeadroomAvailable(CallerClass::NormalPump, 12, false)); // outer9
    RS2_CHECK(!RecoveryPumpHeadroomAvailable(CallerClass::NormalPump, 2, false));
    RS2_CHECK(!RecoveryPumpHeadroomAvailable(CallerClass::NormalPump, SIZE_MAX, false));
    RS2_CHECK(!RecoveryPumpHeadroomAvailable(CallerClass::NormalPump, 11, true));
    for (const auto caller : {CallerClass::Unknown, CallerClass::NormalBuilder, CallerClass::KnownSpin,
        CallerClass::ShutdownDrain, CallerClass::Truncated})
        RS2_CHECK(!RecoveryPumpHeadroomAvailable(caller, 3, false));
}
void NormalAndRefusedMeasurement() {
    PrimaryCallbackTiming timing{};
    RS2_CHECK(ClaimPrimaryCallbackTiming(timing, true, 100));
    RS2_CHECK(EnterPrimaryCallbackNative(timing, true, 105));
    RS2_CHECK(LeavePrimaryCallbackNative(timing, true, 200));
    RS2_CHECK(FinalizePrimaryCallbackTiming(timing, true, 205));
    RS2_CHECK(timing.phase == PrimaryCallbackTimingPhase::CompleteValid && timing.ticks == 10);
    const auto complete = timing;
    RS2_CHECK(!ClaimPrimaryCallbackTiming(timing, true, 300));
    RS2_CHECK(!EnterPrimaryCallbackNative(timing, true, 300));
    RS2_CHECK(!LeavePrimaryCallbackNative(timing, true, 301));
    RS2_CHECK(!BeginPrimaryCallbackFilter(timing, true, 300));
    RS2_CHECK(!EndPrimaryCallbackFilter(timing, true, 301));
    RS2_CHECK(!BeginPrimaryCallbackUnwind(timing, true, 300));
    RS2_CHECK(!FinalizePrimaryCallbackTiming(timing, false, 0));
    InvalidatePrimaryCallbackTiming(timing);
    RS2_CHECK(std::memcmp(&timing, &complete, sizeof(timing)) == 0);
    PrimaryCallbackTiming refused{};
    RS2_CHECK(ClaimPrimaryCallbackTiming(refused, true, 100));
    RS2_CHECK(FinalizePrimaryCallbackTiming(refused, true, 103));
    RS2_CHECK(refused.phase == PrimaryCallbackTimingPhase::CompleteValid && refused.ticks == 3);
    PrimaryCallbackTiming zero{};
    RS2_CHECK(ClaimPrimaryCallbackTiming(zero, true, 100));
    RS2_CHECK(FinalizePrimaryCallbackTiming(zero, true, 100));
    RS2_CHECK(zero.phase == PrimaryCallbackTimingPhase::CompleteValid && !zero.ticks);
}
void FilterAndActualUnwindSegments() {
    PrimaryCallbackTiming nativeFilter{};
    RS2_CHECK(ClaimPrimaryCallbackTiming(nativeFilter, true, 100));
    RS2_CHECK(EnterPrimaryCallbackNative(nativeFilter, true, 110));
    RS2_CHECK(BeginPrimaryCallbackFilter(nativeFilter, true, 150));
    RS2_CHECK(EndPrimaryCallbackFilter(nativeFilter, true, 157));
    RS2_CHECK(nativeFilter.phase == PrimaryCallbackTimingPhase::InProgress &&
        nativeFilter.segment == PrimaryCallbackTimingSegment::Native && nativeFilter.ticks == 17);
    RS2_CHECK(LeavePrimaryCallbackNative(nativeFilter, true, 230));
    RS2_CHECK(FinalizePrimaryCallbackTiming(nativeFilter, true, 237));
    RS2_CHECK(nativeFilter.ticks == 24); // 10 pre + 7 DLL filter + 7 post, all native time excluded.
    PrimaryCallbackTiming ownFilter{};
    RS2_CHECK(ClaimPrimaryCallbackTiming(ownFilter, true, 100));
    RS2_CHECK(BeginPrimaryCallbackFilter(ownFilter, true, 102));
    RS2_CHECK(EndPrimaryCallbackFilter(ownFilter, true, 107));
    RS2_CHECK(FinalizePrimaryCallbackTiming(ownFilter, true, 110));
    RS2_CHECK(ownFilter.ticks == 10); // Enclosing own interval was split, never double counted.
    PrimaryCallbackTiming unwind{};
    RS2_CHECK(ClaimPrimaryCallbackTiming(unwind, true, 100));
    RS2_CHECK(EnterPrimaryCallbackNative(unwind, true, 110));
    RS2_CHECK(BeginPrimaryCallbackFilter(unwind, true, 120));
    RS2_CHECK(EndPrimaryCallbackFilter(unwind, true, 124));
    RS2_CHECK(unwind.phase == PrimaryCallbackTimingPhase::InProgress); // SEARCH is not completion.
    RS2_CHECK(BeginPrimaryCallbackUnwind(unwind, true, 250));
    RS2_CHECK(FinalizePrimaryCallbackTiming(unwind, true, 260));
    RS2_CHECK(unwind.ticks == 24); // Inner native handlers/unwind124..250 remain excluded.
    PrimaryCallbackTiming ownUnwind{};
    RS2_CHECK(ClaimPrimaryCallbackTiming(ownUnwind,true,100));
    RS2_CHECK(BeginPrimaryCallbackFilter(ownUnwind,true,102));
    RS2_CHECK(EndPrimaryCallbackFilter(ownUnwind,true,107));
    RS2_CHECK(BeginPrimaryCallbackUnwind(ownUnwind,true,250));
    RS2_CHECK(FinalizePrimaryCallbackTiming(ownUnwind,true,260));
    RS2_CHECK(ownUnwind.ticks==17); // 2 pre-fault +5 filter +10 finally; SEARCH gap107..250 excluded.
}
void InvalidDiagnosticEndpointsAndOverlap() {
    for (const auto qpc : {0ULL, UINT64_MAX}) {
        PrimaryCallbackTiming invalid{};
        RS2_CHECK(ClaimPrimaryCallbackTiming(invalid, true, qpc));
        RS2_CHECK(!FinalizePrimaryCallbackTiming(invalid, true, 100));
        RS2_CHECK(invalid.phase == PrimaryCallbackTimingPhase::CompleteInvalid && !invalid.ticks);
    }
    PrimaryCallbackTiming absent{};
    RS2_CHECK(ClaimPrimaryCallbackTiming(absent, false, 0));
    RS2_CHECK(!FinalizePrimaryCallbackTiming(absent, true, 100));
    RS2_CHECK(absent.phase == PrimaryCallbackTimingPhase::CompleteInvalid && !absent.ticks);
    PrimaryCallbackTiming regress{};
    RS2_CHECK(ClaimPrimaryCallbackTiming(regress, true, 100));
    RS2_CHECK(EnterPrimaryCallbackNative(regress, true, 110));
    RS2_CHECK(!LeavePrimaryCallbackNative(regress, true, 109));
    RS2_CHECK(!FinalizePrimaryCallbackTiming(regress, true, 115) && !regress.ticks);
    PrimaryCallbackTiming overlap{};
    RS2_CHECK(ClaimPrimaryCallbackTiming(overlap, true, 100));
    RS2_CHECK(BeginPrimaryCallbackFilter(overlap, true, 102));
    RS2_CHECK(!BeginPrimaryCallbackFilter(overlap, true, 103));
    RS2_CHECK(!EndPrimaryCallbackFilter(overlap, true, 104));
    RS2_CHECK(!FinalizePrimaryCallbackTiming(overlap, true, 105) && !overlap.ticks);
    PrimaryCallbackTiming incomplete{};
    RS2_CHECK(ClaimPrimaryCallbackTiming(incomplete, true, 100));
    RS2_CHECK(EnterPrimaryCallbackNative(incomplete, true, 110));
    RS2_CHECK(!FinalizePrimaryCallbackTiming(incomplete, true, 120));
    RS2_CHECK(incomplete.phase == PrimaryCallbackTimingPhase::CompleteInvalid && !incomplete.ticks);
    PrimaryCallbackTiming overflow{};
    RS2_CHECK(ClaimPrimaryCallbackTiming(overflow, true, 100));
    overflow.ticks = INT64_MAX - 1;
    RS2_CHECK(!FinalizePrimaryCallbackTiming(overflow, true, 102) && !overflow.ticks);
    // No second claim/foreign/nested caller may reset an active measurement.
    PrimaryCallbackTiming active{};
    RS2_CHECK(ClaimPrimaryCallbackTiming(active, true, 100));
    const auto inProgress = active;
    RS2_CHECK(!ClaimPrimaryCallbackTiming(active, true, 101));
    RS2_CHECK(std::memcmp(&active, &inProgress, sizeof(active)) == 0);
    InvalidatePrimaryCallbackTiming(active); // Qualified outer owner detects unprovable overlap.
    RS2_CHECK(!FinalizePrimaryCallbackTiming(active, true, 105) && !active.ticks);
}
}
void LeechRecoveryPolicyTests() {
    ExactCreateAncestry(); SameServiceHeadroom(); NormalAndRefusedMeasurement(); FilterAndActualUnwindSegments();
    InvalidDiagnosticEndpointsAndOverlap();
}
} // namespace rs2fix::testcases
