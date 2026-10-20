#pragma once
#include "companion/steam_reporting_format_v3.h"
#include "companion/steam_reporting_pipeline.h"
#include "shared/leech_recovery_status.h"

namespace rs2fix::reporting {
struct NativeTransport;
// Cold preparation only: bounded resident storage, hash provider, calibration
// and one receipt thread. No logger/file discovery or native call occurs here.
NativeTransport* PrepareNativeTransport(StatusWireV3&,ReportRingV3&,const ConfigV3&,
    const ReportingIdentities&,DWORD ownerThreadId,DWORD* error) noexcept;
// Immutable startup result arrives only AFTER the existing marker attempt.
bool CompleteNativeTransportStartup(NativeTransport*,const NativeStartupSummary&) noexcept;
bool AttachNativeTransportRecovery(NativeTransport*,RecoveryStatusWireV1*) noexcept;
// Startup scheduling only; hook APIs below perform no event/thread operations.
void ArmNativeTransport(NativeTransport*) noexcept;
void StopNativeTransport(NativeTransport*) noexcept;
// Owner-only copied path request. Epoch increases on a changed live sink
// identity; the worker never receives engine pointers or an archive handle.
bool RequestNativeLogFile(NativeTransport*,std::uint64_t epoch,std::uint64_t prefixMode,
    const std::uint16_t*,std::size_t chars) noexcept;
std::uint64_t NativeTransportQualifiedEpoch(const NativeTransport*) noexcept;
// Owner-only scalar drain observation, never native-call authority. Root must
// separately check current generated/submitted/observed equality, zero reserved
// credit, fresh recording/lifecycle/source and the actual call admission gates.
bool NativeTransportQuiescent(const NativeTransport*,std::uint64_t expectedGeneratedSequence,
    std::uint64_t expectedQualifiedEpoch) noexcept;
// Queue access is not native-call authority: caller must still prove normal
// owner pump ancestry/lifecycle, live sink and cadence at the actual call seam.
const NativeReadyFrame* NativeTransportFrame(NativeTransport*,std::uint64_t epoch) noexcept;
bool NativeTransportReturned(NativeTransport*,std::uint64_t ticket) noexcept;
#if defined(RS2_REPORTING_TESTING)
// Own fixtures only, not a runtime hook API. Storage is retained even on finish.
bool WaitNativeTransportForTest(NativeTransport*,DWORD milliseconds) noexcept;
#endif
}
