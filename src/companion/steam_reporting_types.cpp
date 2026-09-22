#include "companion/steam_reporting_types.h"

namespace rs2fix::reporting {
const char* ModeName(Mode mode) noexcept {
    switch (mode) {
    case Mode::Disabled: return "disabled";
    case Mode::Observe: return "observe";
    case Mode::Repair: return "repair";
    default: return "invalid";
    }
}
const char* ReasonName(Reason reason) noexcept {
    static constexpr const char* names[]{
        "none", "config-missing", "config-disabled", "config-invalid", "observer-required",
        "recon-ineligible", "host-mismatch", "sdk-mismatch", "steamclient-mismatch",
        "profile-mismatch", "preparation-failed", "identity-incomplete", "clock-failed",
        "counter-overflow", "foreign-thread", "unknown-ancestry", "truncated-stack", "reentry",
        "lifecycle-crossing", "init-failed", "unsupported-reinit", "stopping",
        "source-unavailable", "source-lifetime", "source-class", "world-not-ready", "travel",
        "unsupported-counts", "wrapper-mismatch", "proxy-unavailable", "unregistered",
        "public-ip-unavailable", "pending", "request-floor", "producer-ambiguous", "freshness-expired",
        "task-not-ready", "task-ambiguous", "task-mismatch", "holder-mismatch", "task-reused",
        "builder-changed", "install-failed", "postcheck-failed", "stranded-wrapper",
        "prepared-unavailable", "prepared-malformed", "prepared-limit", "prepared-mismatch",
        "native-backoff", "known-spin", "native-unwind", "write-fault",
        "record-loss", "writer-failed", "log-limit", "status-unavailable",
        "spectators-present", "capacity-mismatch"
    };
    static_assert(sizeof(names) / sizeof(names[0]) == kReasonCount);
    const auto index = static_cast<std::size_t>(reason);
    return index < kReasonCount ? names[index] : "invalid-reason";
}
} // namespace rs2fix::reporting
