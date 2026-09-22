#include "companion/steam_observer_dispatch.h"
#include <intrin.h>
#include <limits>

namespace rs2fix::observer {
namespace {
PVOID volatile g_dispatch = nullptr;
constexpr std::uint64_t kLowMask = 0xffffffffULL;

std::uint64_t Read64(volatile LONG64& value) noexcept {
    return static_cast<std::uint64_t>(InterlockedCompareExchange64(&value, 0, 0));
}
void Coverage(DispatchState& state, Reason reason) noexcept {
    InterlockedOr64(&state.coverageReasons, static_cast<LONG64>(1ULL << static_cast<unsigned>(reason)));
}
std::uint64_t Increment(DispatchState& state, volatile LONG64& value) noexcept {
    auto old = Read64(value);
    for (;;) {
        if (old == UINT64_MAX) {
            Coverage(state, Reason::CounterOverflow);
            return 0; // Saturated, never wrapped into a plausible new call ID.
        }
        const auto found = static_cast<std::uint64_t>(InterlockedCompareExchange64(
            &value, static_cast<LONG64>(old + 1), static_cast<LONG64>(old)));
        if (found == old) return old + 1;
        old = found;
    }
}
DispatchState& Current() noexcept {
    auto* state = static_cast<DispatchState*>(InterlockedCompareExchangePointer(&g_dispatch, nullptr, nullptr));
    if (!state) __fastfail(7); // Wrappers are published only after immutable targets.
    return *state;
}
bool Admit(DispatchState& state, bool qualifying) noexcept {
    for (;;) {
        const auto gate = ReadGate(state);
        if (gate == Gate::Armed) return true;
        if (!qualifying || gate != Gate::Preparing) return false;
        const auto previous = static_cast<Gate>(InterlockedCompareExchange(&state.gate,
            static_cast<LONG>(Gate::Contaminated), static_cast<LONG>(Gate::Preparing)));
        if (previous == Gate::Preparing) {
            Coverage(state, Reason::Contaminated);
            return false;
        }
        // Losing admission to commit MUST retry Armed, not return raw on stale state.
    }
}
std::uint32_t CallerRva(const DispatchState& state, const void* caller, bool& known) noexcept {
    const auto address = reinterpret_cast<std::uintptr_t>(caller);
    known = address >= state.config.hostBase && address - state.config.hostBase < state.config.hostSize;
    return known ? static_cast<std::uint32_t>(address - state.config.hostBase) : 0;
}
std::int64_t Qpc() noexcept {
    LARGE_INTEGER value{};
    QueryPerformanceCounter(&value);
    return value.QuadPart;
}
Event Enter(DispatchState& state, Method method, const void* caller, const Proxy* proxy = nullptr) noexcept {
    Event event{};
    event.callId = Increment(state, state.nextCallId);
    Increment(state, state.counters[static_cast<std::size_t>(method)].entered);
    event.entryQpc = event.qpc = Qpc();
    event.entryLifecycle = event.lifecycle = Read64(state.lifecycle);
    event.threadId = GetCurrentThreadId();
    bool known{};
    event.callerRva = CallerRva(state, caller, known);
    event.flags = known ? 0U : UnknownCaller;
    if (InterlockedCompareExchange(&state.unknownLifecycle, 0, 0)) event.flags |= LifecycleAmbiguous;
    if (proxy) {
        event.bindingId = proxy->bindingId;
        event.bindingSequence = proxy->bindingSequence;
    }
    event.method = method;
    event.phase = Phase::Enter;
    return event;
}
void Publish(DispatchState& state, const Event& event) noexcept {
    if (state.sink.publish) state.sink.publish(state.sink.context, event);
}
void Complete(DispatchState& state, Event& event, std::int64_t result, bool emit = true) noexcept {
    Increment(state, state.counters[static_cast<std::size_t>(event.method)].completed);
    event.phase = Phase::Complete;
    event.result = result;
    event.qpc = Qpc();
    event.lifecycle = Read64(state.lifecycle);
    if (event.entryLifecycle != event.lifecycle ||
        InterlockedCompareExchange(&state.unknownLifecycle, 0, 0)) event.flags |= LifecycleAmbiguous;
    if (emit) Publish(state, event);
}
template<class F> F Target(Proxy* proxy, std::size_t slot) noexcept {
    // Do not cache a target across calls or retain an SDK module reference.
    return reinterpret_cast<F>((*static_cast<void***>(proxy->real))[slot]);
}
bool LifecycleEnter(DispatchState& state) noexcept {
    auto old = Read64(state.lifecycle);
    for (;;) {
        if ((old >> 32) == UINT32_MAX || (old & kLowMask) == UINT32_MAX) {
            InterlockedExchange(&state.unknownLifecycle, 1);
            Coverage(state, Reason::LifecycleOverflow);
            return false;
        }
        const auto next = old + (1ULL << 32) + 1;
        const auto found = static_cast<std::uint64_t>(InterlockedCompareExchange64(
            &state.lifecycle, static_cast<LONG64>(next), static_cast<LONG64>(old)));
        if (found == old) return true;
        old = found;
    }
}
void LifecycleLeave(DispatchState& state) noexcept {
    auto old = Read64(state.lifecycle);
    for (;;) {
        if (!(old & kLowMask)) {
            InterlockedExchange(&state.unknownLifecycle, 1);
            Coverage(state, Reason::LifecycleOverflow);
            return;
        }
        const auto found = static_cast<std::uint64_t>(InterlockedCompareExchange64(
            &state.lifecycle, static_cast<LONG64>(old - 1), static_cast<LONG64>(old)));
        if (found == old) return;
        old = found;
    }
}
void LifecycleCleanup(DispatchState& state, bool owned, Event& event, bool returned, bool result) noexcept {
    const DWORD outgoing = GetLastError();
    if (owned) LifecycleLeave(state);
    if (event.method == Method::Init && state.config.lifecycleSink.initFinished)
        state.config.lifecycleSink.initFinished(state.config.lifecycleSink.context,
            Read64(state.lifecycle), returned, result);
    if (returned) Complete(state, event, result ? 1 : 0);
    else {
        event.phase = Phase::Unwind;
        event.qpc = Qpc();
        event.lifecycle = Read64(state.lifecycle);
        event.flags |= LifecycleAmbiguous;
        Publish(state, event);
    }
    SetLastError(outgoing);
}
// POD-only SEH helpers are deliberately separate: /EHsc C++ frames alone do not
// run destructors for every Windows exception. finally observes, never catches.
bool ForwardInit(DispatchState& state, Event& event, bool owned, DWORD incoming,
    std::uint32_t ip, std::uint16_t steamPort, std::uint16_t gamePort,
    std::uint16_t queryPort, std::int32_t mode, const char* version) {
    bool returned = false;
    bool result = false;
    __try {
        SetLastError(incoming);
        result = state.config.init(ip, steamPort, gamePort, queryPort, mode, version);
        const DWORD outgoing = GetLastError();
        returned = true;
        if (state.config.lifecycleSink.initReturned)
            state.config.lifecycleSink.initReturned(state.config.lifecycleSink.context,
                Read64(state.lifecycle), owned, result);
        SetLastError(outgoing);
    } __finally {
        LifecycleCleanup(state, owned, event, returned, result);
    }
    return result;
}
void ForwardShutdown(DispatchState& state, Event& event, bool owned, DWORD incoming) {
    bool returned = false;
    __try {
        SetLastError(incoming);
        state.config.shutdown();
        returned = true;
    } __finally {
        LifecycleCleanup(state, owned, event, returned, false);
    }
}
bool CleanLifecycle(DispatchState& state, std::uint64_t before, std::uint64_t after) noexcept {
    return before == after && !(before & kLowMask) &&
        !InterlockedCompareExchange(&state.unknownLifecycle, 0, 0);
}
Binding* FindBinding(DispatchState& state, void* real, std::int32_t user, std::uint32_t sequence) noexcept {
    for (std::uint32_t i = 0; i < state.bindingCount; ++i) {
        auto& binding = state.bindings[i];
        if (binding.proxy.real == real && binding.steamUser == user &&
            binding.proxy.bindingSequence == sequence) return &binding;
    }
    return nullptr;
}
void RawCoverage(DispatchState& state, Event event, Reason reason) noexcept {
    Coverage(state, reason);
    event.phase = Phase::Coverage;
    event.reason = reason;
    event.qpc = Qpc();
    event.lifecycle = Read64(state.lifecycle);
    if (reason == Reason::LifecycleCrossing) event.flags |= LifecycleAmbiguous;
    Publish(state, event);
}

__declspec(noinline) void LogOnAnonymous(void* receiver) {
    auto* const proxy = static_cast<Proxy*>(receiver);
    const DWORD incoming = GetLastError();
    auto& state = *proxy->owner;
    auto event = Enter(state, Method::LogOnAnonymous, _ReturnAddress(), proxy);
    Publish(state, event);
    const auto target = Target<VoidMethod>(proxy, 6);
    SetLastError(incoming);
    target(proxy->real);
    const DWORD outgoing = GetLastError();
    Complete(state, event, 0);
    SetLastError(outgoing);
}
__declspec(noinline) bool BLoggedOn(void* receiver) {
    auto* const proxy = static_cast<Proxy*>(receiver);
    const DWORD incoming = GetLastError();
    auto& state = *proxy->owner;
    auto event = Enter(state, Method::BLoggedOn, _ReturnAddress(), proxy);
    const auto target = Target<BoolMethod>(proxy, 8);
    SetLastError(incoming);
    const bool result = target(proxy->real);
    const DWORD outgoing = GetLastError();
    const std::size_t bucket = !(event.flags & UnknownCaller) && event.callerRva == state.config.publisherReturnRva ? 0 :
        (!(event.flags & UnknownCaller) && event.callerRva == state.config.advertiseReturnRva ? 1 : 2);
    Increment(state, state.loggedOnResults[bucket][result ? 1 : 0]);
    const LONG value = result ? 2 : 1;
    const bool changed = InterlockedExchange(&state.loggedOnSeen[bucket], value) != value;
    Complete(state, event, result ? 1 : 0, changed);
    SetLastError(outgoing);
    return result;
}
__declspec(noinline) void SetMaxPlayerCount(void* receiver, std::int32_t count) {
    auto* const proxy = static_cast<Proxy*>(receiver);
    const DWORD incoming = GetLastError();
    auto& state = *proxy->owner;
    auto event = Enter(state, Method::SetMaxPlayerCount, _ReturnAddress(), proxy);
    event.argument = count;
    Publish(state, event);
    const auto target = Target<IntMethod>(proxy, 12);
    SetLastError(incoming);
    target(proxy->real, count);
    const DWORD outgoing = GetLastError();
    Complete(state, event, 0);
    SetLastError(outgoing);
}
__declspec(noinline) void SetKeyValue(void* receiver, const char* key, const char* value) {
    auto* const proxy = static_cast<Proxy*>(receiver);
    const DWORD incoming = GetLastError();
    auto& state = *proxy->owner;
    // Counters only: even a deliberately unreadable string remains opaque.
    Increment(state, state.counters[20].entered);
    const auto target = Target<KeyValueMethod>(proxy, 20);
    SetLastError(incoming);
    target(proxy->real, key, value);
    const DWORD outgoing = GetLastError();
    Increment(state, state.counters[20].completed);
    SetLastError(outgoing);
}
__declspec(noinline) bool BUpdateUserData(void* receiver, std::uint64_t steamId, const char* name, std::uint32_t score) {
    auto* const proxy = static_cast<Proxy*>(receiver);
    const DWORD incoming = GetLastError();
    auto& state = *proxy->owner;
    auto event = Enter(state, Method::BUpdateUserData, _ReturnAddress(), proxy);
    event.flags |= HasSteamId;
    event.steamId = steamId;
    event.argument = score;
    Publish(state, event);
    const auto target = Target<UpdateMethod>(proxy, 27);
    SetLastError(incoming);
    const bool result = target(proxy->real, steamId, name, score);
    const DWORD outgoing = GetLastError();
    Complete(state, event, result ? 1 : 0);
    SetLastError(outgoing);
    return result;
}
__declspec(noinline) std::int32_t BeginAuthSession(void* receiver, const void* ticket, std::int32_t length, std::uint64_t steamId) {
    auto* const proxy = static_cast<Proxy*>(receiver);
    const DWORD incoming = GetLastError();
    auto& state = *proxy->owner;
    auto event = Enter(state, Method::BeginAuthSession, _ReturnAddress(), proxy);
    event.flags |= HasSteamId;
    event.steamId = steamId;
    event.argument = length;
    Publish(state, event);
    const auto target = Target<BeginMethod>(proxy, 29);
    SetLastError(incoming);
    const auto result = target(proxy->real, ticket, length, steamId);
    const DWORD outgoing = GetLastError();
    Complete(state, event, result);
    SetLastError(outgoing);
    return result;
}
__declspec(noinline) void EndAuthSession(void* receiver, std::uint64_t steamId) {
    auto* const proxy = static_cast<Proxy*>(receiver);
    const DWORD incoming = GetLastError();
    auto& state = *proxy->owner;
    auto event = Enter(state, Method::EndAuthSession, _ReturnAddress(), proxy);
    event.flags |= HasSteamId;
    event.steamId = steamId;
    Publish(state, event);
    const auto target = Target<EndMethod>(proxy, 30);
    SetLastError(incoming);
    target(proxy->real, steamId);
    const DWORD outgoing = GetLastError();
    Complete(state, event, 0);
    SetLastError(outgoing);
}
__declspec(noinline) void EnableHeartbeats(void* receiver, bool enabled) {
    auto* const proxy = static_cast<Proxy*>(receiver);
    const DWORD incoming = GetLastError();
    auto& state = *proxy->owner;
    auto event = Enter(state, Method::EnableHeartbeats, _ReturnAddress(), proxy);
    event.argument = enabled ? 1 : 0;
    Publish(state, event);
    const auto target = Target<BoolArgumentMethod>(proxy, 39);
    SetLastError(incoming);
    target(proxy->real, enabled);
    const DWORD outgoing = GetLastError();
    Complete(state, event, 0);
    SetLastError(outgoing);
}
__declspec(noinline) void SetHeartbeatInterval(void* receiver, std::int32_t seconds) {
    auto* const proxy = static_cast<Proxy*>(receiver);
    const DWORD incoming = GetLastError();
    auto& state = *proxy->owner;
    auto event = Enter(state, Method::SetHeartbeatInterval, _ReturnAddress(), proxy);
    event.argument = seconds;
    Publish(state, event);
    const auto target = Target<IntMethod>(proxy, 40);
    SetLastError(incoming);
    target(proxy->real, seconds);
    const DWORD outgoing = GetLastError();
    Complete(state, event, 0);
    SetLastError(outgoing);
}
} // namespace

// Addresses only: opaque assembly leaves have no guessed C/C++ call signature.
extern "C" {
extern const unsigned char Rs2ObserverThunk0[];
extern const unsigned char Rs2ObserverThunk1[];
extern const unsigned char Rs2ObserverThunk2[];
extern const unsigned char Rs2ObserverThunk3[];
extern const unsigned char Rs2ObserverThunk4[];
extern const unsigned char Rs2ObserverThunk5[];
extern const unsigned char Rs2ObserverThunk7[];
extern const unsigned char Rs2ObserverThunk9[];
extern const unsigned char Rs2ObserverThunk10[];
extern const unsigned char Rs2ObserverThunk11[];
extern const unsigned char Rs2ObserverThunk13[];
extern const unsigned char Rs2ObserverThunk14[];
extern const unsigned char Rs2ObserverThunk15[];
extern const unsigned char Rs2ObserverThunk16[];
extern const unsigned char Rs2ObserverThunk17[];
extern const unsigned char Rs2ObserverThunk18[];
extern const unsigned char Rs2ObserverThunk19[];
extern const unsigned char Rs2ObserverThunk21[];
extern const unsigned char Rs2ObserverThunk22[];
extern const unsigned char Rs2ObserverThunk23[];
extern const unsigned char Rs2ObserverThunk24[];
extern const unsigned char Rs2ObserverThunk25[];
extern const unsigned char Rs2ObserverThunk26[];
extern const unsigned char Rs2ObserverThunk28[];
extern const unsigned char Rs2ObserverThunk31[];
extern const unsigned char Rs2ObserverThunk32[];
extern const unsigned char Rs2ObserverThunk33[];
extern const unsigned char Rs2ObserverThunk34[];
extern const unsigned char Rs2ObserverThunk35[];
extern const unsigned char Rs2ObserverThunk36[];
extern const unsigned char Rs2ObserverThunk37[];
extern const unsigned char Rs2ObserverThunk38[];
extern const unsigned char Rs2ObserverThunk41[];
extern const unsigned char Rs2ObserverThunk42[];
extern const unsigned char Rs2ObserverThunk43[];
}
const void* const* ProxyVtable() noexcept {
    static const void* const table[kSlotCount] = {
        Rs2ObserverThunk0, // 0
        Rs2ObserverThunk1, // 1
        Rs2ObserverThunk2, // 2
        Rs2ObserverThunk3, // 3
        Rs2ObserverThunk4, // 4
        Rs2ObserverThunk5, // 5
        reinterpret_cast<const void*>(&LogOnAnonymous), // 6
        Rs2ObserverThunk7, // 7
        reinterpret_cast<const void*>(&BLoggedOn), // 8
        Rs2ObserverThunk9, // 9
        Rs2ObserverThunk10, // 10
        Rs2ObserverThunk11, // 11
        reinterpret_cast<const void*>(&SetMaxPlayerCount), // 12
        Rs2ObserverThunk13, // 13
        Rs2ObserverThunk14, // 14
        Rs2ObserverThunk15, // 15
        Rs2ObserverThunk16, // 16
        Rs2ObserverThunk17, // 17
        Rs2ObserverThunk18, // 18
        Rs2ObserverThunk19, // 19
        reinterpret_cast<const void*>(&SetKeyValue), // 20
        Rs2ObserverThunk21, // 21
        Rs2ObserverThunk22, // 22
        Rs2ObserverThunk23, // 23
        Rs2ObserverThunk24, // 24
        Rs2ObserverThunk25, // 25
        Rs2ObserverThunk26, // 26
        reinterpret_cast<const void*>(&BUpdateUserData), // 27
        Rs2ObserverThunk28, // 28
        reinterpret_cast<const void*>(&BeginAuthSession), // 29
        reinterpret_cast<const void*>(&EndAuthSession), // 30
        Rs2ObserverThunk31, // 31
        Rs2ObserverThunk32, // 32
        Rs2ObserverThunk33, // 33
        Rs2ObserverThunk34, // 34
        Rs2ObserverThunk35, // 35
        Rs2ObserverThunk36, // 36
        Rs2ObserverThunk37, // 37
        Rs2ObserverThunk38, // 38
        reinterpret_cast<const void*>(&EnableHeartbeats), // 39
        reinterpret_cast<const void*>(&SetHeartbeatInterval), // 40
        Rs2ObserverThunk41, // 41
        Rs2ObserverThunk42, // 42
        Rs2ObserverThunk43, // 43
    };
    return table;
}
void InitializeDispatch(DispatchState& state, const DispatchConfig& config, EventSink sink) noexcept {
    ZeroMemory(&state, sizeof(state));
    InitializeSRWLock(&state.cacheLock);
    state.config = config;
    state.sink = sink;
    // Preparing has value zero; all storage is unpublished and exclusively owned.
}
bool PublishDispatch(DispatchState& state) noexcept {
    if (!state.config.factory || !state.config.init || !state.config.shutdown ||
        !state.config.validateObject || ReadGate(state) != Gate::Preparing) return false;
    return InterlockedCompareExchangePointer(&g_dispatch, &state, nullptr) == nullptr;
}
Gate ReadGate(DispatchState& state) noexcept {
    return static_cast<Gate>(InterlockedCompareExchange(&state.gate, 0, 0));
}
bool AdmitExternalCall(DispatchState& state) noexcept { return Admit(state, true); }
bool ReadAcceptedBinding(DispatchState& state, const void* object,
    AcceptedBindingSnapshot* output) noexcept {
    if (output) *output = {};
    if (!object || !output || ReadGate(state) != Gate::Armed ||
        InterlockedCompareExchange(&state.unknownLifecycle, 0, 0)) return false;
    const auto before = Read64(state.lifecycle);
    if ((before & kLowMask) || !TryAcquireSRWLockShared(&state.cacheLock)) return false;
    bool found = false, ambiguous = false;
    if (state.bindingCount <= kBindingCapacity) {
        for (std::uint32_t i = 0; i < state.bindingCount; ++i) {
            const auto& item = state.bindings[i];
            if (!item.accepted || item.proxy.owner != &state ||
                item.proxy.bindingSequence != static_cast<std::uint32_t>(before >> 32) ||
                (object != item.proxy.real && object != &item.proxy)) continue;
            if (found) { ambiguous = true; break; }
            *output = {before, item.proxy.bindingId, item.proxy.bindingSequence};
            found = true;
        }
    }
    ReleaseSRWLockShared(&state.cacheLock);
    if (!found || ambiguous || ReadGate(state) != Gate::Armed ||
        !CleanLifecycle(state, before, Read64(state.lifecycle))) {
        *output = {}; return false;
    }
    return true;
}
CounterSnapshot SnapshotCounters(DispatchState& state) noexcept {
    CounterSnapshot result{};
    result.gate = ReadGate(state);
    result.unknownLifecycle = InterlockedCompareExchange(&state.unknownLifecycle, 0, 0) != 0;
    result.lifecycle = Read64(state.lifecycle);
    result.coverageReasons = Read64(state.coverageReasons);
    result.bindingsPublished = static_cast<std::uint32_t>(InterlockedCompareExchange(&state.bindingsPublished, 0, 0));
    result.exhausted = InterlockedCompareExchange(&state.exhausted, 0, 0) != 0;
    for (std::size_t i = 0; i < kMethodCount; ++i) {
        result.entered[i] = Read64(state.counters[i].entered);
        result.completed[i] = Read64(state.counters[i].completed);
    }
    for (std::size_t bucket = 0; bucket < 3; ++bucket)
        for (std::size_t value = 0; value < 2; ++value)
            result.loggedOnResults[bucket][value] = Read64(state.loggedOnResults[bucket][value]);
    return result;
}
__declspec(noinline) void* FactoryEntry(std::int32_t steamUser, const char* version) {
    const DWORD incoming = GetLastError();
    const void* caller = _ReturnAddress();
    auto& state = Current();
    bool known{};
    const auto rva = CallerRva(state, caller, known);
    const bool qualifies = known && rva == state.config.factoryReturnRva && version == state.config.versionLiteral;
    const bool armed = Admit(state, qualifies);
    Event event{};
    if (armed) {
        event = Enter(state, Method::Factory, caller);
        event.argument = steamUser;
        Publish(state, event);
    }
    const auto before = Read64(state.lifecycle);
    SetLastError(incoming);
    void* const real = state.config.factory(steamUser, version);
    const DWORD outgoing = GetLastError();
    const auto after = Read64(state.lifecycle);
    void* result = real;
    if (armed && qualifies && real) {
        if (!CleanLifecycle(state, before, after)) RawCoverage(state, event, Reason::LifecycleCrossing);
        else {
            const auto sequence = static_cast<std::uint32_t>(after >> 32);
            // Potentially fallible object queries stay outside the cache lock.
            // Existing sticky decisions are checked first to avoid needless reads.
            AcquireSRWLockExclusive(&state.cacheLock);
            Binding* binding = FindBinding(state, real, steamUser, sequence);
            const bool existing = binding != nullptr;
            ReleaseSRWLockExclusive(&state.cacheLock);
            const bool valid = existing ? binding->accepted : state.config.validateObject(state.config.validationContext, real);
            bool created = false;
            Reason reason = Reason::None;
            AcquireSRWLockExclusive(&state.cacheLock);
            if (!CleanLifecycle(state, before, Read64(state.lifecycle))) reason = Reason::LifecycleCrossing;
            else {
                binding = FindBinding(state, real, steamUser, sequence);
                if (!binding && !InterlockedCompareExchange(&state.exhausted, 0, 0)) {
                    if (state.bindingCount < kBindingCapacity) {
                        binding = &state.bindings[state.bindingCount++];
                        binding->proxy = {ProxyVtable(), real, &state, state.bindingCount, sequence};
                        binding->steamUser = steamUser;
                        binding->accepted = valid;
                        created = valid;
                    } else InterlockedExchange(&state.exhausted, 1);
                }
                if (!binding) reason = Reason::PoolExhausted;
                else if (!binding->accepted) reason = Reason::InvalidObject;
                else {
                    result = &binding->proxy;
                    event.bindingId = binding->proxy.bindingId;
                    event.bindingSequence = sequence;
                }
            }
            ReleaseSRWLockExclusive(&state.cacheLock);
            if (reason != Reason::None) RawCoverage(state, event, reason);
            if (created) {
                InterlockedIncrement(&state.bindingsPublished); // At most16.
                Event notice = event;
                notice.phase = Phase::Binding;
                Publish(state, notice);
            }
        }
    }
    if (armed) Complete(state, event, real ? 1 : 0);
    SetLastError(outgoing);
    return result;
}
__declspec(noinline) bool InitEntry(std::uint32_t ip, std::uint16_t steamPort, std::uint16_t gamePort,
    std::uint16_t queryPort, std::int32_t mode, const char* version) {
    const DWORD incoming = GetLastError();
    auto& state = Current();
    if (!Admit(state, true)) {
        SetLastError(incoming);
        const bool result = state.config.init(ip, steamPort, gamePort, queryPort, mode, version);
        const DWORD outgoing = GetLastError();
        SetLastError(outgoing);
        return result;
    }
    const bool owned = LifecycleEnter(state);
    if (state.config.lifecycleSink.initEntered)
        state.config.lifecycleSink.initEntered(state.config.lifecycleSink.context,
            Read64(state.lifecycle), owned);
    auto event = Enter(state, Method::Init, _ReturnAddress());
    Publish(state, event);
    return ForwardInit(state, event, owned, incoming, ip, steamPort, gamePort, queryPort, mode, version);
}
__declspec(noinline) void ShutdownEntry() {
    const DWORD incoming = GetLastError();
    auto& state = Current();
    if (state.config.lifecycleSink.shutdownEntered)
        state.config.lifecycleSink.shutdownEntered(state.config.lifecycleSink.context,
            Read64(state.lifecycle));
    if (!Admit(state, true)) {
        SetLastError(incoming);
        state.config.shutdown();
        const DWORD outgoing = GetLastError();
        SetLastError(outgoing);
        return;
    }
    const bool owned = LifecycleEnter(state);
    auto event = Enter(state, Method::Shutdown, _ReturnAddress());
    Publish(state, event);
    ForwardShutdown(state, event, owned, incoming);
}
const char* ReasonName(Reason reason) noexcept {
    switch (reason) {
    case Reason::None: return "none";
    case Reason::OutputPathFailed: return "output_path_failed";
    case Reason::LogFileFailed: return "log_file_failed";
    case Reason::WorkerStartFailed: return "worker_start_failed";
    case Reason::CryptoFailed: return "crypto_failed";
    case Reason::UnsupportedProtection: return "unsupported_protection";
    case Reason::ConfigMissing: return "config_missing";
    case Reason::ConfigDisabled: return "config_disabled";
    case Reason::ConfigInvalid: return "config_invalid";
    case Reason::ReconIneligible: return "recon_ineligible";
    case Reason::CoreMarkerFailed: return "core_marker_failed";
    case Reason::InvalidContext: return "invalid_context";
    case Reason::HostMismatch: return "host_mismatch";
    case Reason::SdkIdentityMismatch: return "sdk_identity_mismatch";
    case Reason::SdkBindingMismatch: return "sdk_binding_mismatch";
    case Reason::AlreadyInitialized: return "already_initialized";
    case Reason::ProfileMismatch: return "profile_mismatch";
    case Reason::PreparationFailed: return "preparation_failed";
    case Reason::Contaminated: return "contaminated";
    case Reason::PageMismatch: return "page_mismatch";
    case Reason::ProtectFailed: return "protect_failed";
    case Reason::CellChanged: return "cell_changed";
    case Reason::VerifyFailed: return "verify_failed";
    case Reason::RollbackFailed: return "rollback_failed";
    case Reason::InvalidObject: return "invalid_object";
    case Reason::PoolExhausted: return "pool_exhausted";
    case Reason::LifecycleCrossing: return "lifecycle_crossing";
    case Reason::LifecycleOverflow: return "lifecycle_overflow";
    case Reason::CounterOverflow: return "counter_overflow";
    case Reason::WriterFailed: return "writer_failed";
    case Reason::LogLimit: return "log_limit";
    case Reason::KeyStoreFailed: return "key_store_failed";
    }
    return "unknown";
}
#if defined(RS2_OBSERVER_TESTING)
void ResetPublishedDispatchForTest() noexcept {
    InterlockedExchangePointer(&g_dispatch, nullptr);
}
#endif
} // namespace rs2fix::observer
