#pragma once

#include "companion/steam_observer_dispatch.h"
#include "companion/steam_reporting_capture.h"
#include "companion/steam_reporting_client.h"
#include "companion/steam_reporting_prepared.h"
#include "companion/steam_reporting_records.h"
#include "companion/steam_reporting_source.h"
#include "companion/steam_reporting_state.h"
#include "companion/steam_reporting_task.h"

namespace rs2fix::reporting {
// Copied before publication. Fixture profiles vary addresses, never the native
// layouts or admission rules. Contexts and callbacks must be process-resident.
struct RuntimeConfig {
    Mode mode;
    DWORD ownerThreadId;
    std::uintptr_t hostBase;
    std::uint32_t hostSize;
    MemoryOps memory;
    observer::DispatchState* dispatch;
    StatusWire* status;
    ReportSink sink;
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
};
struct PendingDuration {
    DurationClass kind;
    std::uint64_t ticks;
    std::int64_t entryQpc;
    bool topLevel;
    bool valid;
};
struct Runtime {
    RuntimeConfig config;
    ProducerState producer;
    TaskBinding task;
    TaskSchedule schedule;
    std::uint32_t nativeTaskState;
    SourceSnapshot source;
    StatusPayload counters;
    PendingDuration pendingDuration;
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
    char scratch[kJsonBytes];
};
// Invocation-owned scalars survive native unwind; no native object is retained
// by records or the worker. dirtyAddress is used only by the immediate forwarder.
struct BuilderDecision {
    ReportRecord event;
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
bool RuntimeCleanupAdmission(Runtime&) noexcept;
void CleanupRevokedRuntime(Runtime&, CallerClass) noexcept;
bool RuntimeClock(Runtime&, std::int64_t* now) noexcept;
bool ValidateRuntimeEntry(Runtime&, std::int64_t entryQpc) noexcept;
void FailRuntimeTiming(Runtime&, Reason) noexcept;
void RevokeRuntime(Runtime&, Reason) noexcept;
// Forwarders call these only after their exact compiled capture prefix passed.
// Passing a class does not let callers skip capture; no production API learns a
// class from native mutable data. Their separate fixture calls test owner logic.
void ManagePump(Runtime&, CallerClass, std::int64_t now) noexcept;
void PrepareBuilder(Runtime&, CallerClass, void* borrowedHolder,
    std::int64_t now, std::uint64_t classificationTicks, BuilderDecision*) noexcept;
void FinishBuilder(Runtime&, BuilderDecision&, bool returned, bool result,
    bool selected, std::int64_t returnQpc, std::uint64_t nativeTicks) noexcept;
void PublishRuntimeStatus(Runtime&, std::int64_t now, bool allowAnchor) noexcept;
// Owner-only single-slot timing handoff. A failed consume retains the record and
// permanently freezes accounting; it never retries after a logical timing gap.
bool ConsumeRuntimeDuration(Runtime&) noexcept;
bool StageRuntimeDuration(Runtime&, DurationClass, std::uint64_t ticks,
    std::int64_t entryQpc, bool topLevel) noexcept;
} // namespace rs2fix::reporting
