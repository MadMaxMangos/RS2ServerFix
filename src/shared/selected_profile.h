#pragma once

// Only explicitly named test targets receive this definition/include directory.
#if defined(RS2_STARTUP_TEST_PROFILE)
#include "fixture_profile.h"
namespace rs2fix {
inline constexpr const StartupProfile& kSelectedStartupProfile = kFixtureStartupProfile;
}
#else
#include "shared/production_startup.h"
namespace rs2fix {
inline constexpr const StartupProfile& kSelectedStartupProfile = kProductionStartupProfile;
}
#endif
