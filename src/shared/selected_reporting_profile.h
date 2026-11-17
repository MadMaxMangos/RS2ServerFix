#pragma once
#include "companion/steam_reporting_ancestry.h"
#include "companion/steam_reporting_prepared.h"
#include "companion/steam_reporting_profile.h"
#include "companion/steam_reporting_source.h"
#include "companion/steam_reporting_task.h"
#include "companion/steam_reporting_native_profile.h"
#include "companion/steam_reporting_native_source.h"
#include "companion/steam_observer_profile.h"
#include "companion/build_identity.h"
#if defined(RS2_STARTUP_TEST_PROFILE)
#include "fixture_profile.h"
#endif

// Fixture selection is compile-time only. Production host selection is closed
// over exact preserved PE hashes, never config, registry, filename or live state.
namespace rs2fix::reporting {
#if defined(RS2_STARTUP_TEST_PROFILE)
inline const ReportingProfile& SelectedReportingProfile() noexcept { return kFixtureReportingProfile; }
inline const NativeLoggingProfile& SelectedNativeLoggingProfile() noexcept { return kFixtureNativeLoggingProfile; }
inline const NativeLogLayout& SelectedNativeLogLayout() noexcept { return kFixtureNativeLogLayout; }
inline constexpr std::uint32_t kSelectedNativeLogEntry=kFixtureNativeLogEntry;
inline const ReportingIdentities& SelectedReportingIdentities() noexcept { return kFixtureReportingIdentities; }
inline const SourceLayout& SelectedSourceLayout() noexcept { return kFixtureSourceLayout; }
inline const PreparedLayout& SelectedPreparedLayout() noexcept { return kFixturePreparedLayout; }
inline const TaskLayout& SelectedTaskLayout() noexcept { return kFixtureTaskLayout; }
inline const AncestryProfile& SelectedAncestryProfile() noexcept { return kFixtureAncestryProfile; }
inline constexpr const wchar_t* kSelectedSteamClientLeaf=L"rs2_test_steam_client.dll";
#else
inline const ReportingProfile& SelectedReportingProfile() noexcept { return ProductionReportingProfile(); }
inline const NativeLoggingProfile& SelectedNativeLoggingProfile() noexcept { return ProductionNativeLoggingProfile(); }
inline const NativeLogLayout& SelectedNativeLogLayout() noexcept { return ProductionNativeLogLayout(); }
inline constexpr std::uint32_t kSelectedNativeLogEntry=0x9CF10;
inline const ReportingIdentities& SelectedReportingIdentities() noexcept { return ProductionReportingIdentities(); }
inline const SourceLayout& SelectedSourceLayout() noexcept { return ProductionSourceLayout(); }
inline const PreparedLayout& SelectedPreparedLayout() noexcept { return ProductionPreparedLayout(); }
inline const TaskLayout& SelectedTaskLayout() noexcept { return ProductionTaskLayout(); }
inline const AncestryProfile& SelectedAncestryProfile() noexcept { return ProductionAncestryProfile(); }
inline constexpr const wchar_t* kSelectedSteamClientLeaf=L"steamclient64.dll";
#endif

inline const ReportingIdentities& SelectedReportingIdentities(const Sha256Digest& hostDigest) noexcept {
#if defined(RS2_STARTUP_TEST_PROFILE)
    (void)hostDigest;
    return kFixtureReportingIdentities;
#else
    return hostDigest==kCurrentStockDigest ? StockReportingIdentities() : ProductionReportingIdentities();
#endif
}

inline const observer::Profile& SelectedReportingObserverProfile(const Sha256Digest& hostDigest) noexcept {
#if defined(RS2_STARTUP_TEST_PROFILE)
    (void)hostDigest;
    return observer::kFixtureObserverProfile;
#else
    return hostDigest==kCurrentStockDigest ? observer::StockReportingObserverProfile() : observer::ProductionObserverProfile();
#endif
}

// A failed fixture/unknown-host qualification must never fall through to a
// production depot profile. These are cold, immutable candidate selectors.
inline const ReportingIdentities* SelectedDepotReportingIdentities(const Sha256Digest& hostDigest) noexcept {
#if defined(RS2_STARTUP_TEST_PROFILE)
    (void)hostDigest; return nullptr;
#else
    if(hostDigest==kCurrentStockDigest) return &StockDepotReportingIdentities();
    if(hostDigest==kCurrentFullDumpDigest) return &DepotReportingIdentities();
    return nullptr;
#endif
}
inline const observer::Profile* SelectedDepotReportingObserverProfile(const Sha256Digest& hostDigest) noexcept {
#if defined(RS2_STARTUP_TEST_PROFILE)
    (void)hostDigest; return nullptr;
#else
    if(hostDigest==kCurrentStockDigest) return &observer::StockDepotReportingObserverProfile();
    if(hostDigest==kCurrentFullDumpDigest) return &observer::DepotReportingObserverProfile();
    return nullptr;
#endif
}
} // namespace rs2fix::reporting
