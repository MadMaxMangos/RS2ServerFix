#pragma once
#include <Windows.h>
#include <cstdint>
namespace rs2fix {
enum class ReconMode : std::uint32_t { Passive, Active };
enum class ReconOutcome : std::uint32_t { Passive, Disabled, Active, RolledBack, Fatal };
enum class FixReason : std::uint32_t {
    None, InvalidContext, StartupRejected, UnsupportedHost,
    HostOpenSharingViolation, HostOpenFailed, HostHashBudgetExceeded,
    HostIdentityChanged, HostHashMismatch, HostHashFailed,
    CodeUnreadable, FunctionMismatch, ConstantMismatch, ProtectionMismatch,
    PreparedDigestMismatch, ProtectFailed, WriteFailed, ReadbackFailed,
    RestoreFailed, FlushFailed, RollbackFailed
};
struct ReconResult {
    ReconOutcome outcome{ReconOutcome::Disabled};
    FixReason reason{FixReason::InvalidContext};
    DWORD error{};
    bool qualified{};
};
const char* ReconModeName(ReconMode mode) noexcept;
const char* ReconOutcomeName(ReconOutcome outcome) noexcept;
const char* FixReasonName(FixReason reason) noexcept;
inline constexpr char kReconFixId[] = "recon-exclusive-scale-v1";
}
