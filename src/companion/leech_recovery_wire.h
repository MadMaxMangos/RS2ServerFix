#pragma once
#include "shared/leech_recovery_status.h"

extern "C" rs2fix::reporting::RecoveryStatusWireV1 RS2LeechRecovery_StatusV1;
namespace rs2fix::reporting {
// One initialization and one qualified owner writer. Neither callback nor
// control worker may publish. No I/O, native call, allocation or quota action.
bool InitializeRecoveryStatus(RecoveryStatusWireV1&, const StatusHeader&) noexcept;
bool PublishRecoveryStatus(RecoveryStatusWireV1&, const ReportRecoveryPayload&) noexcept;
RecoverySnapshotResult ReadRecoveryStatusSnapshot(const RecoveryStatusWireV1&, RecoveryStatusSnapshot*) noexcept;
RecoverySnapshotResult ReadRecoveryStatusSnapshot(const RecoveryStatusWireV1&,
    const StatusHeader& matchingIdentity, RecoveryStatusSnapshot*) noexcept;
} // namespace rs2fix::reporting
