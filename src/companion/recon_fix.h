#pragma once

#include "companion/recon_profile.h"
#include "companion/recon_types.h"
#include "shared/startup_profile.h"

namespace rs2fix {

struct ReconOps {
    MemoryOps memory;
    void* context{};
    bool (*protect)(void*, std::uintptr_t, std::size_t, DWORD, DWORD*, DWORD*) noexcept{};
    bool (*writeDword)(void*, std::uintptr_t, std::uint32_t, DWORD*) noexcept{};
    bool (*flush)(void*, std::uintptr_t, std::size_t, DWORD*) noexcept{};
    FixReason (*validateHostIdentity)(void*, DWORD*) noexcept{};
};

class HostHashLease;
ReconOps ProductionReconOps(HostHashLease* lease) noexcept;

// Failure after an unproven rollback is Fatal: the caller must not enter game code.
// No mutation APIs are called for Passive, including protection or cache flush.
ReconResult RunReconFix(const BootstrapContextV3& context,
    const StartupProfile& startup, const ReconProfile& profile, ReconMode mode,
    const Sha256Digest& hostDigest, const ReconOps& ops) noexcept;

[[noreturn]] void FailFastRecon() noexcept;

} // namespace rs2fix
