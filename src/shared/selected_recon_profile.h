#pragma once

// The production bootstrap never includes this correction profile selector.
#if defined(RS2_STARTUP_TEST_PROFILE)
#include "fixture_profile.h"
namespace rs2fix {
inline constexpr const ReconProfile& kSelectedReconProfile = kFixtureReconProfile;
}
#else
#include "companion/recon_profile.h"
#include "companion/build_identity.h"
namespace rs2fix {
inline constexpr const ReconProfile& kSelectedReconProfile = kProductionReconProfile;
}
#endif

namespace rs2fix {
inline const ReconProfile& SelectedReconProfile(const Sha256Digest& hostDigest) noexcept {
#if defined(RS2_STEAM_REPORTING) && !defined(RS2_STARTUP_TEST_PROFILE)
    // The instruction/constant recipes are identical in these two exact PEs.
    // Keep the actual host identity in the immutable profile; unknown hashes
    // select the original profile and still fail RunReconFix's exact comparison.
    static constexpr ReconProfile stock=[]() constexpr {
        auto profile=kProductionReconProfile;
        profile.hostDigest=kCurrentStockDigest;
        return profile;
    }();
    if(hostDigest==kCurrentStockDigest) return stock;
#else
    (void)hostDigest;
#endif
    return kSelectedReconProfile;
}
}
