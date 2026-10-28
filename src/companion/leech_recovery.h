#pragma once
#include "companion/leech_recovery_control.h"
#include "companion/leech_recovery_console.h"
#include "companion/leech_recovery_native.h"
#include "companion/leech_recovery_policy.h"
#include "companion/leech_recovery_wire.h"
#include "companion/steam_reporting_capture.h"
#include "companion/steam_reporting_source.h"
#include "companion/steam_reporting_task.h"

namespace rs2fix::reporting {
struct Runtime;
// One process-resident owner sidecar. Native addresses are comparison tokens,
// not leases and never enter DATA/records/control-worker memory. It is retained
// after refusal because an outstanding native Create can still call its guard.
struct LeechRecovery {
    Runtime* runtime;
    RecoveryStatusWireV1* status;
    recovery::ControlState control;
    LeechConsoleAdapter console;
    StartupProfile startup;
    RecoveryNativeContext native;
    RecoveryNativeCalls calls;
    RecoveryMetadataCalls metadataCalls;
    RecoveryRandomOps metadataRandom;
    // Opaque storage permits an explicitly aligned16 view without changing
    // this process-private POD's natural alignment or relying on tail padding.
    std::uint8_t metadataPropertiesStorage[sizeof(RecoveryMetadataProperties)+15];
    RecoveryMetadataMembers metadataMembers;
    CaptureProfile createCapture;
    ReportRecoveryPayload value;
    ReportRecoveryPayload pendingRecords[9];
    SourceSnapshot source, scratchSource;
    TaskSnapshot oldHeartbeat;
    RecoveryNativeSnapshot before, current;
    RecoveryNativeString publishedSession;
    unsigned char publishedSessionBytes[1024];
    RecoveryGenericTask beforeCreate[kRecoveryGenericSlots];
    PrimaryCallbackTiming callbackTiming;
    std::uintptr_t finishDescriptor;
    std::uint32_t holder, finishId, createSlot, createId, createHolder;
    std::uint16_t finishSlot, finishType;
    std::uint32_t callbackDepth, callbackError;
    std::uint32_t pendingCount, pendingRead;
    std::uint32_t beforeCreateIssued, beforeCreateRequestSlot;
    std::uint64_t callbackQpc, lastEmissionQpc, qualifyingRecordSequence;
    std::uint64_t metadataDeadlineQpc, metadataLastProbeQpc;
    volatile LONG foreignFault;
    bool prepared, controlStarted, requested, terminal, finalPending;
    bool finishObserved, finishTrue, enqueueReturned, cancelEntered;
    bool createInstalled, createForwarded, createReturned, exceptionPending;
    bool resourceReleaseAttempted, bindEntered, bindCompleted, recipeEntered, recipeReturned;
    bool metadataHeadOwned, metadataDestructorEntered, metadataUpdateReturned, haveMetadataProbe;
};
static_assert(std::is_trivially_copyable_v<LeechRecovery> &&
    std::is_standard_layout_v<LeechRecovery> && std::is_trivially_destructible_v<LeechRecovery>);

// Cold opt-in preparation is isolated from normal reporting. False disables
// recovery only; no native SDK call or task callback installation occurs here.
bool PrepareLeechRecovery(LeechRecovery&, Runtime&, const StartupProfile&,
    const wchar_t* executableDirectory, HMODULE companion) noexcept;
void ArmLeechRecovery(LeechRecovery&) noexcept;
bool RecoveryServiceDue(const Runtime&) noexcept;
// Called only from the current directly captured top-level normal AfterPump.
// True means this visit belongs to recovery and must skip ordinary management.
bool ServiceLeechRecovery(Runtime&, CallerClass, std::size_t hostFrameCount,
    bool truncated, std::int64_t qpc);
void RecoveryOwnerClockFault(Runtime&) noexcept;
#if defined(RS2_REPORTING_TESTING)
RecoveryReason NativeGuardReasonForTest(RecoveryNativeResult,const RecoveryNativeSnapshot&,
    const TaskSnapshot&) noexcept;
void SetLeechRecoveryCurrentForTest(LeechRecovery*) noexcept;
void ObserveLeechFinishForTest(LeechRecovery&,const bool*,std::uint32_t,bool,std::int32_t) noexcept;
bool FinishLeechErrorForTest(LeechRecovery&,std::int32_t,std::uint32_t) noexcept;
void FinishLeechTerminalForTest(Runtime&,LeechRecovery&,std::uint64_t) noexcept;
void ReleaseLeechOwnedForTest(Runtime&,LeechRecovery&);
void SubmitLeechFinishForTest(Runtime&,LeechRecovery&);
void RecreateLeechForTest(Runtime&,LeechRecovery&);
bool ChangedOnlyLeechCreateForTest(LeechRecovery&,bool) noexcept;
bool InstallLeechCreateGuardForTest(Runtime&,LeechRecovery&) noexcept;
void InvokeLeechCreateSuccessForTest(LeechRecovery&,const void*,std::uint32_t);
void SetLeechCreateCaptureForTest(const std::uint32_t*,std::size_t,bool,bool) noexcept;
#endif

// Existing runtime adapters: same source/SDK gates and checked ring credit.
// The source adapter never calls ObtainSource or resets normal binding state.
bool RecoveryRuntimeSafeOwner(Runtime&) noexcept;
Reason RecoveryRuntimeSource(Runtime&, SourceSnapshot*) noexcept;
Reason RecoveryRuntimeTask(Runtime&, TaskSnapshot*) noexcept;
Reason RecoveryRuntimeRetire(Runtime&) noexcept;
bool EmitRecoveryRuntimeRecord(Runtime&, const ReportRecoveryPayload&,
    std::int64_t headerQpc, std::uint64_t* acceptedSequence) noexcept;
} // namespace rs2fix::reporting
