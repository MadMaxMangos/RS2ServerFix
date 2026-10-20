#pragma once
#include "shared/steam_reporting_snapshot_v3.h"

namespace rs2fix::reporting {
inline constexpr std::uint32_t kRecoveryStatusSchemaV1 = 1;
inline constexpr std::uint32_t kRecoveryArtifactVersion = 0x00060200U;
enum class RecoveryPhase : std::uint64_t {
    Disabled = 0, Armed = 1, Requested = 2, Qualifying = 3, FinishSubmitted = 4,
    FinishAccepted = 5, Recreating = 6, Published = 7, Observed = 8, Failed = 9,
    Rejected = 10, Count = 11
};
enum class RecoveryEvent : std::uint64_t { None = 0, Transition = 1, Final = 2, Exception = 3, Count = 4 };
enum class RecoveryReason : std::uint64_t {
    None = 0, PermissionDisabled = 1, InvalidRequest = 2, SourceUnavailable = 3,
    SourceChanged = 4, SpectatorsPresent = 5, CountsInvalid = 6, NativeProfileMismatch = 7,
    LifecycleChanged = 8, KernelChanged = 9, HeartbeatUnavailable = 10, ScheduleUnsupported = 11,
    DescriptorUnavailable = 12, RequestPoolUnavailable = 13, GenericPoolUnavailable = 14,
    RecordingNotQuiescent = 15, QuotaUnavailable = 16, RetirementFailed = 17,
    RecordingUnavailable = 18, FinishEnqueueFailed = 19, CallbackInvalid = 20,
    FinishRejected = 21, FinishTimeout = 22, AttemptTimeout = 23, CreateFailed = 24,
    CacheClearedNoSession = 25, ClockFault = 26, NativeException = 27, InverseUnavailable = 28,
    ControlWorkerUnavailable = 29, BindingNotReady = 30,
    ControlConfigMissing = 31, ControlConfigInvalid = 32, ControlIdentityMismatch = 33,
    ControlPathRejected = 34, ControlSecurityRejected = 35, ControlReadFailure = 36,
    ControlEndpointUnavailable = 37,
    GuardSnapshotInvalidContext = 38, GuardSnapshotUnreadable = 39,
    GuardSnapshotChanged = 40, GuardSnapshotBudget = 41,
    GuardSnapshotShape = 42, GuardSnapshotAlias = 43,
    GuardSnapshotDescriptor = 44, GuardSnapshotPool = 45,
    GuardSnapshotReadiness = 46, GuardSnapshotHook = 47,
    GuardSnapshotAllocator = 48, GuardSnapshotImport = 49,
    GuardSnapshotProvenance = 50, GuardReadiness = 51,
    GuardStandalone = 52, GuardSession = 53, GuardIssuedId = 54,
    GuardFinishFree = 55, GuardCreateFree = 56,
    GuardHeartbeatSlot = 57, GuardHeartbeatType = 58,
    GuardHeartbeatId = 59, GuardGenericId = 60,
    GuardGenericHolder = 61, GuardHeartbeatReferences = 62,
    SnapshotGuardPassed = 63, Count = 64
};
enum class RecoveryOutcome : std::uint64_t {
    None = 0, MechanicsFailed = 1, ClearedCacheNoSession = 2, NativeUnwind = 3,
    RecordingUnavailable = 4, PublishedNotDelivered = 5, DeliveredSelectionUnknown = 6,
    AdoptedCountUnrepaired = 7, RepairedObserved = 8, Inconclusive = 9, Count = 10
};
enum class ResourcePhase : std::uint64_t {
    None = 0, AllocatedUnbound = 1, BoundLocal = 2, EnqueueEntered = 3, LocalReleased = 4, Count = 5
};
enum class NativeStage : std::uint64_t {
    None = 0, Descriptor = 1, Allocate = 2, Bind = 3, Copy = 4, Retire = 5, Cancel = 6,
    Enqueue = 7, LocalRelease = 8, Cleanup = 9, Create = 10, Publish = 11, Rebind = 12,
    Start = 13, GuardInstall = 14, CreateGuard = 15, CreateForward = 16, Count = 17
};
enum class CallbackResult : std::uint64_t {
    NotObserved = 0, True = 1, False = 2, Null = 3, Unreadable = 4, Invalid = 5, Count = 6
};
enum RecoveryFlags : std::uint64_t {
    RecoveryPermissionEnabled = 1ULL << 0,
    RecoveryCancellationCompleted = 1ULL << 1,
    RecoveryRestartRequired = 1ULL << 2,
    RecoveryCallbackObserved = 1ULL << 3,
    RecoveryAttributionValid = 1ULL << 4,
    RecoveryDeliveryReceiptObserved = 1ULL << 5,
    RecoveryRecipeEntered = 1ULL << 6,
    RecoveryRecipeNormalCompleted = 1ULL << 7,
    RecoveryExceptionObserved = 1ULL << 8,
    RecoveryTerminal = 1ULL << 9,
    RecoveryCreateGuardInstalled = 1ULL << 10,
    RecoveryCreateCallbackObserved = 1ULL << 11,
    RecoveryCreateForwardEntered = 1ULL << 12,
    RecoveryCreateForwardNormalCompleted = 1ULL << 13,
    RecoveryCallbackOwnTimingValid = 1ULL << 14
};
inline constexpr std::uint64_t kRecoveryKnownFlags = 0x7fff;
struct ReportRecoveryPayload {
    std::uint64_t phase, event, reason, outcome, flags;
    std::uint64_t operationSequence, transitionSequence, qpc, sourceEpoch, sdkEpoch, ownerThreadId;
    std::uint64_t resourcePhase, nativeStage, exceptionCode, requestId, callbackId, callbackResult, apiReturnedId;
    std::uint64_t oldSdkFingerprint, newSdkFingerprint, oldCacheFingerprint, newCacheFingerprint;
    std::uint64_t finishDeadlineQpc, overallDeadlineQpc, recordSequence, callbackOwnTicks;
};
struct alignas(8) RecoveryStatusWireV1 {
    std::uint32_t schema, bytes, artifactVersion, pid;
    std::uint8_t runId[16];
    std::uint64_t headerReady, ownerSequence;
    ReportRecoveryPayload payload;
};
enum class RecoverySnapshotResult { Coherent, Busy, Unavailable, Invalid, ReadFailure };
struct RecoveryReadOps {
    void* context;
    bool (*read)(void*, std::size_t offset, void*, std::size_t bytes) noexcept;
};
struct RecoveryStatusSnapshot { RecoveryStatusWireV1 wire; unsigned attempts; };

// Identity is independent of normal CORE/worker/log readiness and grants no
// recovery authority. The caller still qualifies process/module custody.
bool ReportingIdentityValidV3(const StatusHeader&) noexcept;
SnapshotResultV3 ReadReportingIdentityV3(const StatusReadOpsV3&, StatusHeader*) noexcept;
bool RecoveryPayloadValid(const ReportRecoveryPayload&) noexcept;
// The unbound overload checks wire coherence/shape only. Consumers qualify the
// immutable V3 identity and use the matchingIdentity overload for custody.
RecoverySnapshotResult ReadRecoveryStatusSnapshot(const RecoveryReadOps&, RecoveryStatusSnapshot*) noexcept;
RecoverySnapshotResult ReadRecoveryStatusSnapshot(const RecoveryReadOps&,
    const StatusHeader& matchingIdentity, RecoveryStatusSnapshot*) noexcept;
const char* RecoverySnapshotResultName(RecoverySnapshotResult) noexcept;

#define RS2_RECOVERY_VALUE(Type, Name, Value) static_assert(static_cast<std::uint64_t>(Type::Name) == Value)
RS2_RECOVERY_VALUE(RecoveryPhase, Disabled, 0); RS2_RECOVERY_VALUE(RecoveryPhase, Armed, 1);
RS2_RECOVERY_VALUE(RecoveryPhase, Requested, 2); RS2_RECOVERY_VALUE(RecoveryPhase, Qualifying, 3);
RS2_RECOVERY_VALUE(RecoveryPhase, FinishSubmitted, 4); RS2_RECOVERY_VALUE(RecoveryPhase, FinishAccepted, 5);
RS2_RECOVERY_VALUE(RecoveryPhase, Recreating, 6); RS2_RECOVERY_VALUE(RecoveryPhase, Published, 7);
RS2_RECOVERY_VALUE(RecoveryPhase, Observed, 8); RS2_RECOVERY_VALUE(RecoveryPhase, Failed, 9);
RS2_RECOVERY_VALUE(RecoveryPhase, Rejected, 10); RS2_RECOVERY_VALUE(RecoveryPhase, Count, 11);
RS2_RECOVERY_VALUE(RecoveryEvent, None, 0); RS2_RECOVERY_VALUE(RecoveryEvent, Transition, 1);
RS2_RECOVERY_VALUE(RecoveryEvent, Final, 2); RS2_RECOVERY_VALUE(RecoveryEvent, Exception, 3);
RS2_RECOVERY_VALUE(RecoveryEvent, Count, 4);
RS2_RECOVERY_VALUE(RecoveryReason, None, 0); RS2_RECOVERY_VALUE(RecoveryReason, PermissionDisabled, 1);
RS2_RECOVERY_VALUE(RecoveryReason, InvalidRequest, 2); RS2_RECOVERY_VALUE(RecoveryReason, SourceUnavailable, 3);
RS2_RECOVERY_VALUE(RecoveryReason, SourceChanged, 4); RS2_RECOVERY_VALUE(RecoveryReason, SpectatorsPresent, 5);
RS2_RECOVERY_VALUE(RecoveryReason, CountsInvalid, 6); RS2_RECOVERY_VALUE(RecoveryReason, NativeProfileMismatch, 7);
RS2_RECOVERY_VALUE(RecoveryReason, LifecycleChanged, 8); RS2_RECOVERY_VALUE(RecoveryReason, KernelChanged, 9);
RS2_RECOVERY_VALUE(RecoveryReason, HeartbeatUnavailable, 10); RS2_RECOVERY_VALUE(RecoveryReason, ScheduleUnsupported, 11);
RS2_RECOVERY_VALUE(RecoveryReason, DescriptorUnavailable, 12); RS2_RECOVERY_VALUE(RecoveryReason, RequestPoolUnavailable, 13);
RS2_RECOVERY_VALUE(RecoveryReason, GenericPoolUnavailable, 14); RS2_RECOVERY_VALUE(RecoveryReason, RecordingNotQuiescent, 15);
RS2_RECOVERY_VALUE(RecoveryReason, QuotaUnavailable, 16); RS2_RECOVERY_VALUE(RecoveryReason, RetirementFailed, 17);
RS2_RECOVERY_VALUE(RecoveryReason, RecordingUnavailable, 18); RS2_RECOVERY_VALUE(RecoveryReason, FinishEnqueueFailed, 19);
RS2_RECOVERY_VALUE(RecoveryReason, CallbackInvalid, 20); RS2_RECOVERY_VALUE(RecoveryReason, FinishRejected, 21);
RS2_RECOVERY_VALUE(RecoveryReason, FinishTimeout, 22); RS2_RECOVERY_VALUE(RecoveryReason, AttemptTimeout, 23);
RS2_RECOVERY_VALUE(RecoveryReason, CreateFailed, 24); RS2_RECOVERY_VALUE(RecoveryReason, CacheClearedNoSession, 25);
RS2_RECOVERY_VALUE(RecoveryReason, ClockFault, 26); RS2_RECOVERY_VALUE(RecoveryReason, NativeException, 27);
RS2_RECOVERY_VALUE(RecoveryReason, InverseUnavailable, 28); RS2_RECOVERY_VALUE(RecoveryReason, ControlWorkerUnavailable, 29);
RS2_RECOVERY_VALUE(RecoveryReason, BindingNotReady, 30);
RS2_RECOVERY_VALUE(RecoveryReason, ControlConfigMissing, 31); RS2_RECOVERY_VALUE(RecoveryReason, ControlConfigInvalid, 32);
RS2_RECOVERY_VALUE(RecoveryReason, ControlIdentityMismatch, 33); RS2_RECOVERY_VALUE(RecoveryReason, ControlPathRejected, 34);
RS2_RECOVERY_VALUE(RecoveryReason, ControlSecurityRejected, 35); RS2_RECOVERY_VALUE(RecoveryReason, ControlReadFailure, 36);
RS2_RECOVERY_VALUE(RecoveryReason, ControlEndpointUnavailable, 37);
RS2_RECOVERY_VALUE(RecoveryReason, GuardSnapshotInvalidContext, 38);
RS2_RECOVERY_VALUE(RecoveryReason, SnapshotGuardPassed, 63); RS2_RECOVERY_VALUE(RecoveryReason, Count, 64);
RS2_RECOVERY_VALUE(RecoveryOutcome, None, 0); RS2_RECOVERY_VALUE(RecoveryOutcome, MechanicsFailed, 1);
RS2_RECOVERY_VALUE(RecoveryOutcome, ClearedCacheNoSession, 2); RS2_RECOVERY_VALUE(RecoveryOutcome, NativeUnwind, 3);
RS2_RECOVERY_VALUE(RecoveryOutcome, RecordingUnavailable, 4); RS2_RECOVERY_VALUE(RecoveryOutcome, PublishedNotDelivered, 5);
RS2_RECOVERY_VALUE(RecoveryOutcome, DeliveredSelectionUnknown, 6); RS2_RECOVERY_VALUE(RecoveryOutcome, AdoptedCountUnrepaired, 7);
RS2_RECOVERY_VALUE(RecoveryOutcome, RepairedObserved, 8); RS2_RECOVERY_VALUE(RecoveryOutcome, Inconclusive, 9);
RS2_RECOVERY_VALUE(RecoveryOutcome, Count, 10);
RS2_RECOVERY_VALUE(ResourcePhase, None, 0); RS2_RECOVERY_VALUE(ResourcePhase, AllocatedUnbound, 1);
RS2_RECOVERY_VALUE(ResourcePhase, BoundLocal, 2); RS2_RECOVERY_VALUE(ResourcePhase, EnqueueEntered, 3);
RS2_RECOVERY_VALUE(ResourcePhase, LocalReleased, 4); RS2_RECOVERY_VALUE(ResourcePhase, Count, 5);
RS2_RECOVERY_VALUE(NativeStage, None, 0); RS2_RECOVERY_VALUE(NativeStage, Descriptor, 1);
RS2_RECOVERY_VALUE(NativeStage, Allocate, 2); RS2_RECOVERY_VALUE(NativeStage, Bind, 3);
RS2_RECOVERY_VALUE(NativeStage, Copy, 4); RS2_RECOVERY_VALUE(NativeStage, Retire, 5);
RS2_RECOVERY_VALUE(NativeStage, Cancel, 6); RS2_RECOVERY_VALUE(NativeStage, Enqueue, 7);
RS2_RECOVERY_VALUE(NativeStage, LocalRelease, 8); RS2_RECOVERY_VALUE(NativeStage, Cleanup, 9);
RS2_RECOVERY_VALUE(NativeStage, Create, 10); RS2_RECOVERY_VALUE(NativeStage, Publish, 11);
RS2_RECOVERY_VALUE(NativeStage, Rebind, 12); RS2_RECOVERY_VALUE(NativeStage, Start, 13);
RS2_RECOVERY_VALUE(NativeStage, GuardInstall, 14); RS2_RECOVERY_VALUE(NativeStage, CreateGuard, 15);
RS2_RECOVERY_VALUE(NativeStage, CreateForward, 16); RS2_RECOVERY_VALUE(NativeStage, Count, 17);
RS2_RECOVERY_VALUE(CallbackResult, NotObserved, 0); RS2_RECOVERY_VALUE(CallbackResult, True, 1);
RS2_RECOVERY_VALUE(CallbackResult, False, 2); RS2_RECOVERY_VALUE(CallbackResult, Null, 3);
RS2_RECOVERY_VALUE(CallbackResult, Unreadable, 4); RS2_RECOVERY_VALUE(CallbackResult, Invalid, 5);
RS2_RECOVERY_VALUE(CallbackResult, Count, 6);
#undef RS2_RECOVERY_VALUE
static_assert(RecoveryPermissionEnabled == 1 && RecoveryCancellationCompleted == 2 && RecoveryRestartRequired == 4);
static_assert(RecoveryCallbackObserved == 8 && RecoveryAttributionValid == 16 && RecoveryDeliveryReceiptObserved == 32);
static_assert(RecoveryRecipeEntered == 64 && RecoveryRecipeNormalCompleted == 128 && RecoveryExceptionObserved == 256);
static_assert(RecoveryTerminal == 512 && RecoveryCreateGuardInstalled == 1024 && RecoveryCreateCallbackObserved == 2048);
static_assert(RecoveryCreateForwardEntered == 4096 && RecoveryCreateForwardNormalCompleted == 8192);
static_assert(RecoveryCallbackOwnTimingValid == 16384 && kRecoveryKnownFlags == 0x7fff);
#define RS2_RECOVERY_OFFSET(Field, Index) static_assert(offsetof(ReportRecoveryPayload, Field) == 8 * Index)
RS2_RECOVERY_OFFSET(phase, 0); RS2_RECOVERY_OFFSET(event, 1); RS2_RECOVERY_OFFSET(reason, 2);
RS2_RECOVERY_OFFSET(outcome, 3); RS2_RECOVERY_OFFSET(flags, 4); RS2_RECOVERY_OFFSET(operationSequence, 5);
RS2_RECOVERY_OFFSET(transitionSequence, 6); RS2_RECOVERY_OFFSET(qpc, 7); RS2_RECOVERY_OFFSET(sourceEpoch, 8);
RS2_RECOVERY_OFFSET(sdkEpoch, 9); RS2_RECOVERY_OFFSET(ownerThreadId, 10); RS2_RECOVERY_OFFSET(resourcePhase, 11);
RS2_RECOVERY_OFFSET(nativeStage, 12); RS2_RECOVERY_OFFSET(exceptionCode, 13); RS2_RECOVERY_OFFSET(requestId, 14);
RS2_RECOVERY_OFFSET(callbackId, 15); RS2_RECOVERY_OFFSET(callbackResult, 16); RS2_RECOVERY_OFFSET(apiReturnedId, 17);
RS2_RECOVERY_OFFSET(oldSdkFingerprint, 18); RS2_RECOVERY_OFFSET(newSdkFingerprint, 19);
RS2_RECOVERY_OFFSET(oldCacheFingerprint, 20); RS2_RECOVERY_OFFSET(newCacheFingerprint, 21);
RS2_RECOVERY_OFFSET(finishDeadlineQpc, 22); RS2_RECOVERY_OFFSET(overallDeadlineQpc, 23);
RS2_RECOVERY_OFFSET(recordSequence, 24); RS2_RECOVERY_OFFSET(callbackOwnTicks, 25);
#undef RS2_RECOVERY_OFFSET
static_assert(sizeof(ReportRecoveryPayload) == 208 && alignof(ReportRecoveryPayload) == 8);
static_assert(offsetof(RecoveryStatusWireV1, schema) == 0 && offsetof(RecoveryStatusWireV1, bytes) == 4);
static_assert(offsetof(RecoveryStatusWireV1, artifactVersion) == 8 && offsetof(RecoveryStatusWireV1, pid) == 12);
static_assert(offsetof(RecoveryStatusWireV1, runId) == 16 && offsetof(RecoveryStatusWireV1, headerReady) == 32);
static_assert(offsetof(RecoveryStatusWireV1, ownerSequence) == 40 && offsetof(RecoveryStatusWireV1, payload) == 48);
static_assert(sizeof(RecoveryStatusWireV1) == 256 && alignof(RecoveryStatusWireV1) == 8);
static_assert(std::is_trivial_v<RecoveryStatusWireV1> && std::is_standard_layout_v<RecoveryStatusWireV1> &&
    std::is_trivially_copyable_v<RecoveryStatusWireV1>);
static_assert(sizeof(StatusWire) == 1288 && sizeof(StatusWireV3) == 3896 && kRuntimeReasonCountV3 == 59);
} // namespace rs2fix::reporting
