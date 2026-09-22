#pragma once
#include "companion/steam_reporting_ancestry.h"
#include "companion/steam_reporting_prepared.h"
#include "companion/steam_reporting_profile.h"
#include "companion/steam_reporting_source.h"
#include "companion/steam_reporting_task.h"
#if defined(RS2_STARTUP_TEST_PROFILE)
#include "fixture_profile.h"
#endif

// Compile-time selection only. No configuration, registry, filename supplied by
// the operator, or mutable native state can enable a fixture profile in production.
namespace rs2fix::reporting {
#if defined(RS2_STARTUP_TEST_PROFILE)
inline const ReportingProfile& SelectedReportingProfile() noexcept { return kFixtureReportingProfile; }
inline const ReportingIdentities& SelectedReportingIdentities() noexcept { return kFixtureReportingIdentities; }
inline const SourceLayout& SelectedSourceLayout() noexcept { return kFixtureSourceLayout; }
inline const PreparedLayout& SelectedPreparedLayout() noexcept { return kFixturePreparedLayout; }
inline const TaskLayout& SelectedTaskLayout() noexcept { return kFixtureTaskLayout; }
inline const AncestryProfile& SelectedAncestryProfile() noexcept { return kFixtureAncestryProfile; }
inline constexpr const wchar_t* kSelectedSteamClientLeaf=L"rs2_test_steam_client.dll";
#else
inline const ReportingProfile& SelectedReportingProfile() noexcept { return ProductionReportingProfile(); }
inline const ReportingIdentities& SelectedReportingIdentities() noexcept { return ProductionReportingIdentities(); }
inline const SourceLayout& SelectedSourceLayout() noexcept { return ProductionSourceLayout(); }
inline const PreparedLayout& SelectedPreparedLayout() noexcept { return ProductionPreparedLayout(); }
inline const TaskLayout& SelectedTaskLayout() noexcept { return ProductionTaskLayout(); }
inline const AncestryProfile& SelectedAncestryProfile() noexcept { return ProductionAncestryProfile(); }
inline constexpr const wchar_t* kSelectedSteamClientLeaf=L"steamclient64.dll";
#endif
} // namespace rs2fix::reporting
