#include "companion/recon_types.h"

namespace rs2fix {
const char* ReconModeName(ReconMode mode) noexcept {
    return mode == ReconMode::Active ? "active" : "passive";
}
const char* ReconOutcomeName(ReconOutcome outcome) noexcept {
    switch (outcome) {
    case ReconOutcome::Passive: return "passive";
    case ReconOutcome::Disabled: return "disabled";
    case ReconOutcome::Active: return "active";
    case ReconOutcome::RolledBack: return "rolled_back";
    case ReconOutcome::Fatal: return "fatal";
    }
    return "disabled";
}
const char* FixReasonName(FixReason reason) noexcept {
    switch (reason) {
    case FixReason::None: return "none";
    case FixReason::InvalidContext: return "invalid_context";
    case FixReason::StartupRejected: return "startup_rejected";
    case FixReason::UnsupportedHost: return "unsupported_host";
    case FixReason::HostOpenSharingViolation: return "host_open_sharing_violation";
    case FixReason::HostOpenFailed: return "host_open_failed";
    case FixReason::HostHashBudgetExceeded: return "host_hash_budget_exceeded";
    case FixReason::HostIdentityChanged: return "host_identity_changed";
    case FixReason::HostHashMismatch: return "host_hash_mismatch";
    case FixReason::HostHashFailed: return "host_hash_failed";
    case FixReason::CodeUnreadable: return "code_unreadable";
    case FixReason::FunctionMismatch: return "function_mismatch";
    case FixReason::ConstantMismatch: return "constant_mismatch";
    case FixReason::ProtectionMismatch: return "protection_mismatch";
    case FixReason::PreparedDigestMismatch: return "prepared_digest_mismatch";
    case FixReason::ProtectFailed: return "protect_failed";
    case FixReason::WriteFailed: return "write_failed";
    case FixReason::ReadbackFailed: return "readback_failed";
    case FixReason::RestoreFailed: return "restore_failed";
    case FixReason::FlushFailed: return "flush_failed";
    case FixReason::RollbackFailed: return "rollback_failed";
    }
    return "invalid_context";
}
} // namespace rs2fix
