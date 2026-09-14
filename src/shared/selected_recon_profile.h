#pragma once

// The production bootstrap never includes this correction profile selector.
#if defined(RS2_STARTUP_TEST_PROFILE)
#include "fixture_profile.h"
namespace rs2fix {
inline constexpr const ReconProfile& kSelectedReconProfile = kFixtureReconProfile;
}
#else
#include "companion/recon_profile.h"
namespace rs2fix {
inline constexpr const ReconProfile& kSelectedReconProfile = kProductionReconProfile;
}
#endif
