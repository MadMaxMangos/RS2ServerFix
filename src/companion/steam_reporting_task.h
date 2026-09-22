#pragma once

#include "companion/steam_reporting_types.h"
#include "shared/startup_profile.h"

namespace rs2fix::reporting {
using BuilderFn = bool (*)(void* borrowedHolder);
enum class TaskPhase : LONG { Empty = 0, Preparing, Armed, Retired, Inert };

// Only RVAs vary for inert fixtures; the accepted field layout/slot count and
// metadata type stay fixed. Production never learns a layout from mutable data.
struct TaskLayout {
    std::uint32_t poolRva;
    std::uint32_t selectedIdRva;
    std::uint32_t invalidIdRva;
    std::uint32_t counterRva;
    std::uint32_t registryRva;
    std::uint32_t metadataVtableRva;
    std::uint32_t builderRva;
    std::uint32_t serviceStateRva;
};
const TaskLayout& ProductionTaskLayout() noexcept;

struct TaskAccess {
    MemoryOps memory;
    std::uintptr_t hostBase;
    std::uint32_t hostImageSize;
    void* context;
    bool (*compareExchange)(void*, std::uintptr_t address, std::uintptr_t expected,
        std::uintptr_t desired, std::uintptr_t* observed, DWORD* error) noexcept;
    // Admission includes root-owned ancestry/source/lifecycle/revocation gates.
    // safeOwner independently permits fixed-table cleanup after diagnostic
    // revocation only. It must still qualify the thread, gate, same idle SDK
    // lifecycle and absence of stopping, including checks around each probe/CAS.
    bool (*admission)(void*) noexcept;
    bool (*safeOwner)(void*) noexcept;
    // Pure owner-thread identity, distinct from safeOwner's composite lifetime
    // predicate. Required to classify an entry rejection without native reads.
    bool (*ownerThread)(void*) noexcept;
};
struct TaskEpoch { std::uint64_t source; std::uint64_t binding; };
// Owner-only opaque comparison tokens. Never queue/log these pointers or use a
// retained token as a dereference address; each read resolves the fixed roots.
struct TaskIdentity {
    std::uint32_t slot;
    std::uint32_t id;
    std::uint32_t holder;
    std::uintptr_t component;
    std::uintptr_t metadata;
};
enum class ScheduleTier : std::uint32_t { Unknown=0, OrdinaryPoll, RetryBase, Retry30s, Retry60s, Retry5m, Retry30m };
// Observation only. Native clock conversion is unqualified: neither a delay
// tier nor an expedite flag is a completed attempt or a next-eligibility time.
struct TaskSchedule {
    std::uint64_t anchorBits;
    std::uint64_t interval;
    std::int64_t intervalOverride;
    std::int64_t retryOverride;
    std::int32_t errors;
    std::int32_t throttles;
    std::uint16_t retryLimit;
    std::uint8_t expedite;
    bool valid;
    ScheduleTier tier;
    std::uint64_t delayUnits;
};
bool EqualTaskSchedule(const TaskSchedule&,const TaskSchedule&) noexcept;
struct TaskSnapshot {
    TaskIdentity identity;
    std::uint32_t state;
    std::uint32_t nativeCounter;
    std::uintptr_t builder;
    TaskSchedule schedule;
};
struct TaskBinding {
    volatile LONG phase;
    Reason fault;
    DWORD lastError;
    std::uintptr_t original; // Immutable after initialization, even after retirement.
    std::uintptr_t wrapper;  // Process-resident target, never hot-unloaded.
    TaskEpoch epoch;
    TaskIdentity identity;
    TaskIdentity lastIdentity;
    std::uint32_t lastNativeCounter;
    std::uint32_t lastBoundId;
    bool haveCounter;
    bool haveHistory;
    bool haveIdentity;
    bool continuingTask; // Same-ID refresh only after exact healthy stock restoration.
    bool inverseAttempted;
    bool stranded;
};
static_assert(std::is_trivial_v<TaskBinding> && std::is_standard_layout_v<TaskBinding>);

Reason InitializeTaskBinding(TaskBinding&, std::uintptr_t original, std::uintptr_t wrapper) noexcept;
TaskPhase ReadTaskPhase(TaskBinding&) noexcept;
bool EqualTaskIdentity(const TaskIdentity&, const TaskIdentity&) noexcept;
// Reads at most 128 header pairs plus the selected scalar fields. It never
// reads endpoint strings, resolves native holders, or invokes native methods.
Reason ReadSelectedTask(const TaskAccess&, const TaskLayout&, TaskSnapshot*) noexcept;
// After an Armed binding's full-scan uniqueness proof, read only its known fixed
// slot. The cold-qualified constructor issues every new task a globally growing
// ID; a decreasing/wrapped counter faults, while a changed selected/slot tuple is
// never adopted. Reads still resolve fixed roots and double-check every scalar
// identity/lifetime field. Successful reads advance the observed global counter.
Reason ReadBoundTask(TaskBinding&, const TaskAccess&, const TaskLayout&, TaskSnapshot*) noexcept;
// Install only from Empty/Retired, after a complete queued-state requalification.
// Preparing identity/original are visible before the single +40 CAS; postcheck
// failure permanently latches Inert and attempts only the owned inverse.
// Optional output is cleared on entry and contains only the verified postcheck
// observation after Armed publication, never a preflight/failed-install sample.
Reason InstallTaskBinding(TaskBinding&, const TaskAccess&, const TaskLayout&, TaskEpoch,
    TaskSnapshot* installed=nullptr) noexcept;
// Accept a copied holder VALUE, not its temporary address. Epoch mismatch is
// rejected before native reads; no shared registry indexing from arbitrary data.
Reason ValidateBuilderTask(TaskBinding&, const TaskAccess&, const TaskLayout&,
    TaskEpoch, const void* borrowedHolder, TaskSnapshot*) noexcept;
// Healthy retirement of an executing/cancelled task (4/5) is deferred without
// mutation: TaskNotReady, still Armed. Root must already revoke old-epoch source
// authority while waiting; the wrapper therefore only forwards. Once queued,
// restore to stock before any fresh-epoch install. Fault retirement is Inert and
// can inverse an owned pointer even after tuple loss, on the safe live-table owner.
Reason RetireTaskBinding(TaskBinding&, const TaskAccess&, const TaskLayout&,
    Reason fault=Reason::None) noexcept;
} // namespace rs2fix::reporting
