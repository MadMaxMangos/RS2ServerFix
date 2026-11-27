#pragma once

#include "companion/console_status.h"
#include "companion/marker.h"
#include "companion/package_check_profile.h"
#include "companion/recon_types.h"
#include "shared/startup_profile.h"

#include <array>

namespace rs2fix {

struct PackageCheckOps {
    MemoryOps memory;
    void* context{};
    bool (*protect)(void*, std::uintptr_t, std::size_t, DWORD, DWORD*, DWORD*) noexcept{};
    bool (*writeBytes)(void*, std::uintptr_t, const void*, std::size_t, DWORD*) noexcept{};
    bool (*flush)(void*, std::uintptr_t, std::size_t, DWORD*) noexcept{};
    FixReason (*validateHostIdentity)(void*, DWORD*) noexcept{};
};

class HostHashLease;
PackageCheckOps ProductionPackageCheckOps(HostHashLease* lease) noexcept;

// Exact production hosts only; nullptr for anything else, including fixtures.
const PackageCheckProfile* SelectedPackageCheckProfile(const Sha256Digest& hostDigest) noexcept;

using PackageCheckStub = std::array<std::uint8_t, kPackageCheckStubSize>;
bool BuildPackageCheckStub(const PackageCheckProfile& profile, PackageCheckStub* stub) noexcept;

// Same transaction discipline as RunReconFix: every proof precedes the single
// writable interval; a failed install rolls back; an unproven rollback is
// Fatal and the caller must not enter game code. Passive never mutates.
ReconResult RunPackageCheckBypass(const BootstrapContextV3& context,
    const StartupProfile& startup, const PackageCheckProfile& profile, ReconMode mode,
    const Sha256Digest& hostDigest, const PackageCheckOps& ops) noexcept;

// RS2PackageCheck.ini beside the executable. Only AllowAnyMutator=true installs
// the bypass. False, a missing key or file (stock default), and anything invalid
// leave the stock safelist download and check running. The key is
// case-insensitive; values are true/false/1/0. Blank lines, ;/# comments and
// [section] headers are ignored; any other line makes the file invalid.
enum class PackageCheckConfig : std::uint32_t { Unread, Absent, Enabled, Disabled, Invalid };
PackageCheckConfig ParsePackageCheckConfig(const char* bytes, std::size_t size) noexcept;
PackageCheckConfig ReadPackageCheckConfig(const wchar_t* directory, DWORD* error) noexcept;
const char* PackageCheckConfigName(PackageCheckConfig config) noexcept;

enum class PackageCheckStage : std::uint32_t { Skipped, ConfigOff, Ran };
struct PackageCheckReport {
    PackageCheckStage stage{PackageCheckStage::Skipped};
    PackageCheckConfig config{PackageCheckConfig::Unread};
    ReconMode mode{ReconMode::Passive};
    ReconResult result{};
    BuildIdentity host{BuildIdentity::Indeterminate};
    DWORD processId{};
};
// One printable ASCII line ending in CRLF, the shape ValidConsoleReport accepts.
bool FormatPackageCheckLine(const PackageCheckReport& report, ConsoleReportContext* output) noexcept;

// Runs after recon's marker and result are frozen; cannot change either.
// reconAccepted must be MarkerStateAccepted(marker) && the marker was written.
// Writes RS2ServerFix.packagecheck.<pid>.log beside the executable (best
// effort) and starts a console report unless the outcome is Fatal, which the
// caller reports on its ready-console path before failing fast.
PackageCheckReport RunPackageCheckStartup(const BootstrapContextV3& context,
    const StartupProfile& startup, const MarkerData& marker, bool reconAccepted,
    HostHashLease* lease, const wchar_t* hostDirectory, ConsoleReportContext* line,
    const MarkerFileOps& fileOps = ProductionMarkerFileOps()) noexcept;

} // namespace rs2fix
