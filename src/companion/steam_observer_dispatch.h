#pragma once

#include "shared/startup_profile.h"
#include <cstddef>
#include <cstdint>
#include <type_traits>

// Internal observational ABI only. No Steam header, imported SDK symbol or game
// type is required: machine signatures come from the qualified 013 evidence.
namespace rs2fix::observer {
inline constexpr std::size_t kSlotCount = 44;
inline constexpr std::size_t kBindingCapacity = 16;
inline constexpr std::size_t kQueueCapacity = 4096;
enum class Gate : LONG { Preparing = 0, Armed, Contaminated, Disabled };
enum class Reason : std::uint32_t {
    None, ConfigMissing, ConfigDisabled, ConfigInvalid, ReconIneligible,
    CoreMarkerFailed, InvalidContext, HostMismatch, SdkIdentityMismatch,
    SdkBindingMismatch, AlreadyInitialized, ProfileMismatch, PreparationFailed,
    Contaminated, PageMismatch, ProtectFailed, CellChanged, VerifyFailed,
    RollbackFailed, InvalidObject, PoolExhausted, LifecycleCrossing,
    LifecycleOverflow, CounterOverflow, WriterFailed, LogLimit, KeyStoreFailed,
    OutputPathFailed, LogFileFailed, WorkerStartFailed, CryptoFailed, UnsupportedProtection
};
const char* ReasonName(Reason reason) noexcept;
enum class Method : std::uint32_t {
    LogOnAnonymous = 6, BLoggedOn = 8, SetMaxPlayerCount = 12, SetKeyValue = 20,
    BUpdateUserData = 27, BeginAuthSession = 29, EndAuthSession = 30,
    EnableHeartbeats = 39, SetHeartbeatInterval = 40,
    Factory = 44, Init = 45, Shutdown = 46, Count = 47
};
inline constexpr std::size_t kMethodCount = static_cast<std::size_t>(Method::Count);
enum class Phase : std::uint32_t { Enter, Complete, Unwind, Binding, Coverage };
enum EventFlags : std::uint32_t {
    HasSteamId = 1, UnknownCaller = 2, LifecycleAmbiguous = 4
};
// Owned scalar copies only. In particular no SDK string/ticket buffer pointer
// can outlive a call through the queue. SteamId is pseudonymised by the writer.
struct Event {
    std::uint64_t callId;
    std::int64_t entryQpc;
    std::int64_t qpc;
    std::uint64_t entryLifecycle;
    std::uint64_t lifecycle;
    std::uint64_t steamId;
    std::int64_t argument;
    std::int64_t result;
    std::uint32_t threadId;
    std::uint32_t callerRva;
    std::uint32_t bindingId;
    std::uint32_t bindingSequence;
    Method method;
    Phase phase;
    Reason reason;
    std::uint32_t flags;
};
struct EventSink {
    void* context;
    void (*publish)(void*, const Event&) noexcept;
};
// C++ language linkage is deliberate under /EHsc. The flat Init retains its
// six-argument x64 ABI; it is not virtual slot zero's member signature.
using FactoryFn = void* (*)(std::int32_t, const char*);
using InitFn = bool (*)(std::uint32_t, std::uint16_t, std::uint16_t,
    std::uint16_t, std::int32_t, const char*);
using ShutdownFn = void (*)();
using VoidMethod = void (*)(void*);
using BoolMethod = bool (*)(void*);
using IntMethod = void (*)(void*, std::int32_t);
using KeyValueMethod = void (*)(void*, const char*, const char*);
using UpdateMethod = bool (*)(void*, std::uint64_t, const char*, std::uint32_t);
using BeginMethod = std::int32_t (*)(void*, const void*, std::int32_t, std::uint64_t);
using EndMethod = void (*)(void*, std::uint64_t);
using BoolArgumentMethod = void (*)(void*, bool);

// Optional reporting lifecycle observers. These own no SDK arguments and are
// absent for legacy artifacts. Returned runs while Init's owned reference is
// still held; finished runs after its balanced release, including native unwind.
struct LifecycleSink {
    void* context;
    void (*initEntered)(void*, std::uint64_t, bool) noexcept;
    void (*initReturned)(void*, std::uint64_t, bool, bool) noexcept;
    void (*initFinished)(void*, std::uint64_t, bool, bool) noexcept;
    void (*shutdownEntered)(void*, std::uint64_t) noexcept;
};

struct DispatchConfig {
    std::uintptr_t hostBase;
    std::uint32_t hostSize;
    std::uint32_t factoryReturnRva;
    const char* versionLiteral;
    std::uint32_t publisherReturnRva;
    std::uint32_t advertiseReturnRva;
    FactoryFn factory;
    InitFn init;
    ShutdownFn shutdown;
    void* validationContext;
    bool (*validateObject)(void*, void*) noexcept;
    LifecycleSink lifecycleSink;
};
struct DispatchState;
struct Proxy {
    const void* const* vtable;
    void* real;
    DispatchState* owner;
    std::uint32_t bindingId;
    std::uint32_t bindingSequence;
};
struct Binding {
    Proxy proxy;
    std::int32_t steamUser;
    bool accepted;
};
struct alignas(8) MethodCounters { volatile LONG64 entered; volatile LONG64 completed; };
struct alignas(8) DispatchState {
    volatile LONG gate;
    volatile LONG unknownLifecycle;
    volatile LONG64 lifecycle;
    volatile LONG64 nextCallId;
    volatile LONG64 coverageReasons;
    volatile LONG bindingsPublished;
    volatile LONG exhausted;
    volatile LONG loggedOnSeen[3];
    volatile LONG64 loggedOnResults[3][2];
    MethodCounters counters[kMethodCount];
    SRWLOCK cacheLock;
    Binding bindings[kBindingCapacity];
    std::uint32_t bindingCount;
    DispatchConfig config;
    EventSink sink;
};
struct CounterSnapshot {
    Gate gate;
    bool unknownLifecycle;
    std::uint64_t lifecycle;
    std::uint64_t coverageReasons;
    std::uint32_t bindingsPublished;
    bool exhausted;
    std::uint64_t entered[kMethodCount];
    std::uint64_t completed[kMethodCount];
    std::uint64_t loggedOnResults[3][2];
};
struct AcceptedBindingSnapshot {
    std::uint64_t lifecycle;
    std::uint32_t bindingId;
    std::uint32_t bindingSequence;
};
static_assert(static_cast<LONG>(Gate::Preparing) == 0);
static_assert(offsetof(Proxy, vtable) == 0 && offsetof(Proxy, real) == 8);
static_assert(alignof(DispatchState) >= 8 && offsetof(DispatchState, lifecycle) % 8 == 0);
static_assert(std::is_trivial_v<Event> && std::is_standard_layout_v<Event>);
static_assert(std::is_trivial_v<DispatchState> && std::is_standard_layout_v<DispatchState>);
static_assert(sizeof(Event) <= 128);

// Initialize owned, unused storage before any IAT publication. The installed
// state and its proxies must remain resident until process exit, even on rollback.
void InitializeDispatch(DispatchState& state, const DispatchConfig& config, EventSink sink) noexcept;
bool PublishDispatch(DispatchState& state) noexcept;
Gate ReadGate(DispatchState& state) noexcept;
// Reporting pump participation in the SAME startup commit/contamination gate.
// This never waits or invokes native code.
bool AdmitExternalCall(DispatchState& state) noexcept;
// Bounded try-lock lookup only. Never dereference the passed native interface;
// accept either the validated original or its process-resident observer proxy.
bool ReadAcceptedBinding(DispatchState&, const void* interfaceObject,
    AcceptedBindingSnapshot*) noexcept;
CounterSnapshot SnapshotCounters(DispatchState& state) noexcept;
const void* const* ProxyVtable() noexcept;
void* FactoryEntry(std::int32_t steamUser, const char* version);
bool InitEntry(std::uint32_t ip, std::uint16_t steamPort, std::uint16_t gamePort,
    std::uint16_t queryPort, std::int32_t mode, const char* version);
void ShutdownEntry();

#if defined(RS2_OBSERVER_TESTING)
// Test only: caller must have restored its own IATs and joined all fake calls.
void ResetPublishedDispatchForTest() noexcept;
#endif
} // namespace rs2fix::observer
