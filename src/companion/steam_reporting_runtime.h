#pragma once

#include "companion/steam_observer_dispatch.h"
#include "companion/steam_reporting_capture.h"
#include "companion/steam_reporting_client.h"
#include "companion/steam_reporting_prepared.h"
#include "companion/steam_reporting_records_v3.h"
#include "companion/steam_reporting_native_log.h"
#include "companion/steam_reporting_source.h"
#include "companion/steam_reporting_state.h"
#include "companion/steam_reporting_task.h"

namespace rs2fix::reporting {
struct LeechRecovery;
// Copied before publication. Fixture profiles vary addresses, never the native
// layouts or admission rules. Contexts and callbacks must be process-resident.
struct RuntimeConfig {
    Mode mode;
    Diagnostics diagnostics;
    NativeTransport* nativeTransport;
    DWORD ownerThreadId;
    std::uintptr_t hostBase;
    std::uint32_t hostSize;
    MemoryOps memory;
    observer::DispatchState* dispatch;
    StatusWireV3* status;
    ReportSinkV3 sink;
    observer::ShutdownFn pumpOriginal;
    BuilderFn builderOriginal;
    std::uintptr_t builderWrapper;
    SourceLayout source;
    PreparedLayout prepared;
    TaskLayout task;
    AncestryProfile ancestry;
    CaptureProfile pumpCapture;
    CaptureProfile builderCapture;
    void* noticeContext;
    void (*notice)(void*, bool ready, Reason) noexcept;
    ClientQualification (*qualifyClient)() noexcept;
    LeechRecovery* recovery; // Optional, disabled-default process-resident sidecar.
};
struct PendingDuration {
    DurationClass kind;
    std::uint64_t ticks;
    std::int64_t entryQpc;
    bool topLevel;
    bool valid;
};
// Owned by one invocation and passed explicitly to its emitters. A nested
// callback receives its own reservation; there is no shared current-credit ptr.
struct CaptureReservation {
    std::uint64_t remaining;
    bool active;
    bool control;
};
struct Runtime {
    RuntimeConfig config;
    ProducerState producer;
    TaskBinding task;
    TaskSchedule schedule;
    std::uint32_t nativeTaskState;
    SourceSnapshot source;
    StatusPayload counters;
    OwnerTransport transport;
    NativeLogService nativeLog;
    PendingDuration pendingDuration;
    CaptureReservation recoveryQuota;
    std::uint64_t initialLifecycle;
    std::uint64_t idleLifecycle;
    std::uint64_t initCalls;
    std::uint64_t clientQualificationMs;
    std::int64_t lastClock;
    std::int64_t lastManagement;
    std::int64_t lastAnchor;
    std::uint32_t pumpDepth;
    std::uint32_t builderDepth;
    std::uint32_t timingDepth;
    bool timingGap;
    bool haveClock;
    bool haveManagement;
    bool haveAnchor;
    bool clientQualified;
    bool sdkReady;
    bool sourceReady;
    bool taskAdmission;
    bool readyNotified;
    bool resumeWaitNativeClear;
    bool bindingSuspended;
    char scratch[kJsonBytes];
};
// Invocation-owned scalars survive native unwind; no native object is retained
// by records or the worker. dirtyAddress is used only by the immediate forwarder.
struct BuilderDecision {
    ReportRecordV3 event;
    CaptureReservation credit;
    std::uintptr_t dirtyAddress;
    std::int64_t startedQpc;
    std::int64_t probeFinishedQpc;
    bool attempted;
    bool eligible;
};
static_assert(std::is_trivially_copyable_v<Runtime> && std::is_standard_layout_v<Runtime> &&
    std::is_trivially_destructible_v<Runtime> && std::is_trivial_v<BuilderDecision>);

Reason InitializeRuntime(Runtime&, const RuntimeConfig&, std::int64_t frequency) noexcept;
observer::LifecycleSink RuntimeLifecycleSink(Runtime&) noexcept;
bool RuntimeOwner(const Runtime&) noexcept;
bool RuntimeAdmission(Runtime&) noexcept;
// Existing lifecycle/SDK safety is distinct from recording/repair permission.
bool RuntimeCaptureAdmission(Runtime&) noexcept;
bool RuntimeCleanupAdmission(Runtime&) noexcept;
void CleanupRevokedRuntime(Runtime&, CallerClass) noexcept;
bool RuntimeClock(Runtime&, std::int64_t* now) noexcept;
bool ValidateRuntimeEntry(Runtime&, std::int64_t entryQpc) noexcept;
void FailRuntimeTiming(Runtime&, Reason) noexcept;
void RevokeRuntime(Runtime&, Reason) noexcept;
bool ReserveCapture(Runtime&,CaptureReservation&,std::uint64_t amount,bool control=false) noexcept;
void ReleaseCapture(Runtime&,CaptureReservation&) noexcept;
void PauseRuntimeTransport(Runtime&,TransportReason,std::int64_t now) noexcept;
void RefreshRuntimeTransport(Runtime&,const NativeServiceResult&,std::int64_t now) noexcept;
// Forwarders call these only after their exact compiled capture prefix passed.
// Passing a class does not let callers skip capture; no production API learns a
// class from native mutable data. Their separate fixture calls test owner logic.
void ManagePump(Runtime&, CallerClass, std::int64_t now,CaptureReservation&) noexcept;
void PrepareBuilder(Runtime&, CallerClass, void* borrowedHolder,
    std::int64_t now, std::uint64_t classificationTicks, BuilderDecision*) noexcept;
void FinishBuilder(Runtime&, BuilderDecision&, bool returned, bool result,
    bool selected, std::int64_t returnQpc, std::uint64_t nativeTicks) noexcept;
void PublishRuntimeStatus(Runtime&, std::int64_t now, bool allowAnchor,CaptureReservation* credit=nullptr) noexcept;
// Owner-only single-slot timing handoff. A failed consume retains the record and
// permanently freezes accounting; it never retries after a logical timing gap.
bool ConsumeRuntimeDuration(Runtime&) noexcept;
bool StageRuntimeDuration(Runtime&, DurationClass, std::uint64_t ticks,
    std::int64_t entryQpc, bool topLevel) noexcept;
} // namespace rs2fix::reporting
