#pragma once
#include "companion/steam_reporting_status.h"
#include "shared/steam_reporting_status_v3.h"

namespace rs2fix::reporting {
struct OwnerSnapshotV3 { StatusPayload owner; OwnerTransport transport; std::uint64_t sequence; };

// Each region has one writer after initialization. No new worker may reuse a
// previous writer's storage. All storage is process-resident and starts zeroed.
bool InitializeStatusV3(StatusWireV3&, const StatusHeader&, const StatusPayload&) noexcept;
bool PublishOwnerV3(StatusWireV3&, const StatusPayload&, const OwnerTransport&) noexcept;
bool PublishWorkerV3(StatusWireV3&, const WorkerTransport&) noexcept;
bool PublishConsoleV3(StatusWireV3&, const ConsoleDiagnostics&) noexcept;
bool PublishLogIdentityV3(StatusWireV3&, const LogIdentity&) noexcept;
// Read even after stop/fault so accepted receipts can finish without reviving
// admission. This is a coherent counter copy, never a readiness verdict.
bool ReadOwnerV3(const StatusWireV3&, OwnerSnapshotV3*) noexcept;
void RevokeStatus(StatusWireV3&, Reason) noexcept;
void LoseStatus(StatusWireV3&, Reason) noexcept;
void StopStatus(StatusWireV3&, std::uint64_t qpc) noexcept;
bool StatusRevoked(const StatusWireV3&) noexcept;
// Temporary transport reasons cannot be converted into sticky runtime faults.
bool LatchTransportFault(StatusWireV3&, TransportReason) noexcept;
} // namespace rs2fix::reporting
