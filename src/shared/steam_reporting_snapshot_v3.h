#pragma once
#include "shared/steam_reporting_status_v3.h"

namespace rs2fix::reporting {
struct StatusReadOpsV3 {
    void* context;
    bool (*read)(void*, std::size_t offset, void*, std::size_t bytes) noexcept;
};
enum class SnapshotResultV3 { Coherent, Unpublished, Busy, ReadFailure, Invalid };
struct StatusSnapshotV3 {
    StatusWireV3 wire;
    unsigned attempts;
    bool headerAvailable;
    bool coreAvailable;
    bool logIdentityAvailable;
    bool consoleDiagnosticsAvailable;
    bool workerPauseChanged;
};

// Caller first qualifies the exact V3 export/module/process identity. This
// bounded protocol reader also serves local console snapshots; it owns no OS
// handle and never turns missing/unstable evidence into readiness or data loss.
SnapshotResultV3 ReadStatusSnapshotV3(const StatusReadOpsV3&, StatusSnapshotV3*) noexcept;
// Semantic readiness only after caller's independent host/process/run checks.
// Console diagnostics are intentionally not an input to this decision.
bool SnapshotCurrentlyReadyV3(const StatusSnapshotV3&, std::uint64_t nowQpc,
    std::uint64_t frequency) noexcept;
} // namespace rs2fix::reporting
