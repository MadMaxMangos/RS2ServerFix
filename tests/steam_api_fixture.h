#pragma once
#include <cstdint>

// Owned inert API oracle. Both host and fake use these scalars, never Steam data.
struct FixtureSteamSnapshot {
    std::uint32_t factory, init, shutdown, methods[44], badArguments, factoryAlias;
#if defined(RS2_REPORTING_FIXTURE)
    // Retained own-client loads / native-Shutdown releases, not qualifier leases.
    std::uint32_t pump, clientLoadAttempts, clientLoads, clientUnloads, clientLoadFailures;
    // Measured INSIDE this own-code original, never by a companion accessor.
    // Pair/call ID reset on entry; invalid clocks latch an error and leave zero.
    std::int64_t pumpInnerBefore, pumpInnerAfter;
    std::uint32_t pumpInnerCall, pumpClockErrors;
#endif
};
using FixtureSteamSnapshotFn = FixtureSteamSnapshot (*)();
inline constexpr char kFixtureSteamSignature[] = "RS2-OWN-INERT-STEAM-FIXTURE-NOT-FOR-DEPLOYMENT";
inline constexpr std::uint64_t kFixtureSteamId = 0x1122334455667788ull;
inline constexpr std::uintptr_t kFixtureUnreadablePointer = 1;
#if defined(RS2_REPORTING_FIXTURE)
inline constexpr char kFixtureSteamClientSignature[] = "RS2-OWN-INERT-STEAM-CLIENT-FIXTURE-NOT-FOR-DEPLOYMENT";
inline constexpr wchar_t kFixtureSteamClientLeaf[] = L"rs2_test_steam_client.dll";
#endif
