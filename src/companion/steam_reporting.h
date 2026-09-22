#pragma once
#include "companion/steam_observer.h"

namespace rs2fix::reporting {
// Always independent of recon's already-final result/marker. Rejected reporting
// leaves all Steam IAT cells native; there is no implicit verbose-observer fallback.
void StartReporting(const BootstrapContextV3&, const StartupProfile&, const observer::Profile&,
    const Sha256Digest& hostDigest, HostHashLease&, const wchar_t* directory,
    bool reconEligible) noexcept;
} // namespace rs2fix::reporting
