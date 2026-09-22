#include "companion/steam_observer_dispatch.h"
#include "test_framework.h"
#include <array>
#include <thread>
#include <vector>

using namespace rs2fix::observer;
struct AbiRecord { std::uint64_t hits, slot, receiver, rdx, r8, r9, stack1, stack2, xmm1, xmm2, xmm3; };
extern "C" {
AbiRecord Rs2AbiRecord{};
extern const void* Rs2AbiFakeTable[44];
extern const unsigned char Rs2AbiFactoryReturn[], Rs2AbiPublisherReturn[], Rs2AbiAdvertiseReturn[], Rs2AbiHidden[];
std::uint64_t Rs2AbiInvoke(void*, std::uint32_t);
void* Rs2AbiFactoryCall(FactoryFn, std::int32_t, const char*);
bool Rs2AbiLoggedPublisher(void*);
bool Rs2AbiLoggedAdvertise(void*);
void* Rs2AbiHiddenCall(void*, void*, std::uint32_t);
}
namespace {
// Independent ABI witness oracle, cross-checked against abi-evidence.json. This
// is NOT derived from ProxyVtable or the implementation's Method enumeration.
constexpr const char* kSlotNames[44] = {
    "opaque_slot_zero", "SetProduct", "SetGameDescription", "SetModDir", "SetDedicatedServer",
    "LogOn", "LogOnAnonymous", "LogOff", "BLoggedOn", "BSecure", "GetSteamID", "WasRestartRequested",
    "SetMaxPlayerCount", "SetBotPlayerCount", "SetServerName", "SetMapName", "SetPasswordProtected",
    "SetSpectatorPort", "SetSpectatorServerName", "ClearAllKeyValues", "SetKeyValue", "SetGameTags",
    "SetGameData", "SetRegion", "SendUserConnectAndAuthenticate", "CreateUnauthenticatedUserConnection",
    "SendUserDisconnect", "BUpdateUserData", "GetAuthSessionTicket", "BeginAuthSession", "EndAuthSession",
    "CancelAuthTicket", "UserHasLicenseForApp", "RequestUserGroupStatus", "GetGameplayStats",
    "GetServerReputation", "GetPublicIP", "HandleIncomingPacket", "GetNextOutgoingPacket", "EnableHeartbeats",
    "SetHeartbeatInterval", "ForceHeartbeat", "AssociateWithClan", "ComputeNewPlayerCompatibility"
};
constexpr char kVersion[] = "SteamGameServer013";
constexpr DWORD kIncoming = 0x1234, kOutgoing = 0x5678, kNoise = 0x9876;
constexpr std::uint64_t kSteamId = 0x110000102030405ULL;
const char* const kUnreadable = reinterpret_cast<const char*>(1);
struct FakeObject { const void* const* vtable; };
struct Fixture;
Fixture* g_fixture{};
void Hit(void* real, std::uint32_t slot) {
    ++Rs2AbiRecord.hits;
    Rs2AbiRecord.receiver = reinterpret_cast<std::uintptr_t>(real);
    Rs2AbiRecord.slot = slot;
    RS2_CHECK(GetLastError() == kIncoming);
    SetLastError(kOutgoing);
}
void Fake6(void* real) { Hit(real, 6); }
void Fake6Alternate(void* real) { Hit(real, 6); Rs2AbiRecord.rdx = 0xabcde; }
void Fake6Throw(void* real) { Hit(real, 6); throw 19; }
bool Fake8(void* real);
void Fake12(void* real, std::int32_t n) { Hit(real, 12); RS2_CHECK(n == -73); }
void Fake20(void* real, const char* key, const char* value) { Hit(real, 20); RS2_CHECK(key == kUnreadable && value == kUnreadable); }
bool Fake27(void* real, std::uint64_t id, const char* name, std::uint32_t score) {
    Hit(real, 27); RS2_CHECK(id == kSteamId && name == kUnreadable && score == UINT32_MAX); return false;
}
std::int32_t Fake29(void* real, const void* ticket, std::int32_t length, std::uint64_t id) {
    Hit(real, 29); RS2_CHECK(ticket == kUnreadable && length == -17 && id == kSteamId); return -91;
}
void Fake30(void* real, std::uint64_t id) { Hit(real, 30); RS2_CHECK(id == kSteamId); }
void Fake39(void* real, bool value) { Hit(real, 39); RS2_CHECK(value); }
void Fake40(void* real, std::int32_t value) { Hit(real, 40); RS2_CHECK(value == -1); }
void* FakeFactory(std::int32_t, const char*);
bool FakeInit(std::uint32_t, std::uint16_t, std::uint16_t, std::uint16_t, std::int32_t, const char*);
void FakeShutdown();
struct Fixture {
    DispatchState state{};
    std::array<const void*, 44> table{};
    FakeObject real{};
    void* factoryResult{};
    std::vector<Event> events;
    SRWLOCK eventLock = SRWLOCK_INIT;
    volatile LONG factoryCalls{}, initCalls{}, shutdownCalls{}, validations{}, forwardingErrors{};
    bool valid = true, loggedOn = true;
    int throwMode{}, factoryAction{}, validationAction{}, lifecycleAction{};
    void* nestedResult{};
    HANDLE validateEntered{}, validateRelease{};
    HANDLE lifecycleEntered{}, lifecycleRelease{};
    volatile LONG lifecyclePaused{};
    std::int32_t receivedUser{};
    const char* receivedVersion{};
    explicit Fixture(LifecycleSink lifecycle = {}) {
        ResetPublishedDispatchForTest();
        g_fixture = this;
        for (std::size_t i = 0; i < 44; ++i) table[i] = Rs2AbiFakeTable[i];
        table[6] = reinterpret_cast<void*>(&Fake6); table[8] = reinterpret_cast<void*>(&Fake8);
        table[12] = reinterpret_cast<void*>(&Fake12); table[20] = reinterpret_cast<void*>(&Fake20);
        table[27] = reinterpret_cast<void*>(&Fake27); table[29] = reinterpret_cast<void*>(&Fake29);
        table[30] = reinterpret_cast<void*>(&Fake30); table[39] = reinterpret_cast<void*>(&Fake39);
        table[40] = reinterpret_cast<void*>(&Fake40);
        real.vtable = table.data(); factoryResult = &real;
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        DispatchConfig config{base, nt->OptionalHeader.SizeOfImage,
            static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(Rs2AbiFactoryReturn) - base), kVersion,
            static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(Rs2AbiPublisherReturn) - base),
            static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(Rs2AbiAdvertiseReturn) - base),
            FakeFactory, FakeInit, FakeShutdown, this, Validate, lifecycle};
        InitializeDispatch(state, config, {this, Sink});
        RS2_CHECK(PublishDispatch(state));
    }
    ~Fixture() { ResetPublishedDispatchForTest(); g_fixture = nullptr; }
    void Arm() { RS2_CHECK(InterlockedCompareExchange(&state.gate, static_cast<LONG>(Gate::Armed), 0) == 0); }
    void* Factory(int user = 41, const char* version = kVersion) {
        SetLastError(kIncoming);
        auto* result = Rs2AbiFactoryCall(FactoryEntry, user, version);
        RS2_CHECK(GetLastError() == kOutgoing);
        return result;
    }
    Proxy* Bind() { Arm(); auto* result = static_cast<Proxy*>(Factory()); RS2_CHECK(result != reinterpret_cast<Proxy*>(&real)); return result; }
    static bool Validate(void* context, void*) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        InterlockedIncrement(&f.validations);
        if (f.validationAction) { f.validationAction = 0; SetLastError(kIncoming); ShutdownEntry(); }
        if (f.validateEntered) { SetEvent(f.validateEntered); WaitForSingleObject(f.validateRelease, INFINITE); }
        SetLastError(kNoise); return f.valid;
    }
    static void Sink(void* context, const Event& event) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        AcquireSRWLockExclusive(&f.eventLock);
        f.events.push_back(event);
        ReleaseSRWLockExclusive(&f.eventLock);
        SetLastError(kNoise); // Deliberately adversarial bookkeeping seam.
    }
};
bool Fake8(void* real) { Hit(real, 8); return g_fixture->loggedOn; }
void RaiseFake() {
    if (g_fixture->throwMode == 1) throw 73;
    if (g_fixture->throwMode == 2) RaiseException(0xe0424242U, 0, 0, nullptr);
}
void* FakeFactory(std::int32_t user, const char* version) {
    auto& f = *g_fixture;
    InterlockedIncrement(&f.factoryCalls);
    if (!f.validateEntered) { f.receivedUser = user; f.receivedVersion = version; }
    if (GetLastError() != kIncoming) InterlockedIncrement(&f.forwardingErrors);
    if (f.factoryAction) {
        f.factoryAction = 0; SetLastError(kIncoming); ShutdownEntry();
    }
    SetLastError(kOutgoing);
    RaiseFake();
    return f.factoryResult;
}
bool FakeInit(std::uint32_t ip, std::uint16_t steam, std::uint16_t game, std::uint16_t query,
    std::int32_t mode, const char* version) {
    auto& f = *g_fixture;
    InterlockedIncrement(&f.initCalls);
    if (GetLastError() != kIncoming || ip != 0xfedcba98U || steam != 65535 || game != 7777 || query != 27015 ||
        mode != -9 || version != kUnreadable) InterlockedIncrement(&f.forwardingErrors);
    if (f.lifecycleEntered) {
        if (InterlockedIncrement(&f.lifecyclePaused) == 2) SetEvent(f.lifecycleEntered);
        WaitForSingleObject(f.lifecycleRelease, INFINITE);
    }
    if (f.lifecycleAction) f.nestedResult = f.Factory();
    SetLastError(kOutgoing); RaiseFake(); return false;
}
void FakeShutdown() {
    auto& f = *g_fixture;
    InterlockedIncrement(&f.shutdownCalls);
    if (GetLastError() != kIncoming) InterlockedIncrement(&f.forwardingErrors);
    if (f.lifecycleEntered) {
        if (InterlockedIncrement(&f.lifecyclePaused) == 2) SetEvent(f.lifecycleEntered);
        WaitForSingleObject(f.lifecycleRelease, INFINITE);
    }
    if (f.lifecycleAction) f.nestedResult = f.Factory();
    SetLastError(kOutgoing); RaiseFake();
}
bool CallInit() { return InitEntry(0xfedcba98U, 65535, 7777, 27015, -9, kUnreadable); }
template<class Fn> Fn Slot(Proxy* proxy, std::size_t index) { return reinterpret_cast<Fn>(const_cast<void*>(proxy->vtable[index])); }
void MappingAndAbi() {
    Fixture f;
    auto* proxy = f.Bind();
    for (std::uint32_t i = 0; i < 44; ++i) {
        RS2_CHECK(kSlotNames[i][0] != '\0');
        Rs2AbiRecord = {};
        SetLastError(kIncoming);
        bool typed = true;
        switch (i) {
        case 6: Slot<VoidMethod>(proxy, i)(proxy); break;
        case 8: RS2_CHECK(Slot<BoolMethod>(proxy, i)(proxy)); break;
        case 12: Slot<IntMethod>(proxy, i)(proxy, -73); break;
        case 20: Slot<KeyValueMethod>(proxy, i)(proxy, kUnreadable, kUnreadable); break;
        case 27: RS2_CHECK(!Slot<UpdateMethod>(proxy, i)(proxy, kSteamId, kUnreadable, UINT32_MAX)); break;
        case 29: RS2_CHECK(Slot<BeginMethod>(proxy, i)(proxy, kUnreadable, -17, kSteamId) == -91); break;
        case 30: Slot<EndMethod>(proxy, i)(proxy, kSteamId); break;
        case 39: Slot<BoolArgumentMethod>(proxy, i)(proxy, true); break;
        case 40: Slot<IntMethod>(proxy, i)(proxy, -1); break;
        default: typed = false; RS2_CHECK(Rs2AbiInvoke(proxy, i) == 0x1000 + i); break;
        }
        RS2_CHECK(Rs2AbiRecord.hits == 1 && Rs2AbiRecord.slot == i);
        RS2_CHECK(Rs2AbiRecord.receiver == reinterpret_cast<std::uintptr_t>(&f.real));
        RS2_CHECK(GetLastError() == (typed ? kOutgoing : kIncoming));
        if (!typed) {
            RS2_CHECK(Rs2AbiRecord.rdx == 0x1122334455667788ULL && Rs2AbiRecord.r8 == 0x2233445566778899ULL);
            RS2_CHECK(Rs2AbiRecord.r9 == 0x33445566778899aaULL && Rs2AbiRecord.stack1 == 0x12345678 && Rs2AbiRecord.stack2 == 0x23456789);
            RS2_CHECK(Rs2AbiRecord.xmm1 == Rs2AbiRecord.rdx && Rs2AbiRecord.xmm2 == Rs2AbiRecord.r8 && Rs2AbiRecord.xmm3 == Rs2AbiRecord.r9);
        }
    }
    // Swap the REAL table after binding: both opaque and typed dispatch must use
    // its current target, while hidden-return storage remains in member RDX.
    auto alternate = f.table;
    for (unsigned i : {10U, 25U, 36U}) alternate[i] = Rs2AbiHidden;
    alternate[43] = Rs2AbiFakeTable[0];
    f.real.vtable = alternate.data();
    for (unsigned i : {10U, 25U, 36U}) {
        std::uint64_t out[2]{};
        RS2_CHECK(Rs2AbiHiddenCall(proxy, out, i) == out);
        RS2_CHECK(out[0] == 0x13579bdf && out[1] == 0x2468ace0);
    }
    RS2_CHECK(Rs2AbiInvoke(proxy, 43) == 0x1000);
    alternate[6] = reinterpret_cast<void*>(&Fake6Alternate);
    SetLastError(kIncoming); Slot<VoidMethod>(proxy, 6)(proxy);
    RS2_CHECK(Rs2AbiRecord.rdx == 0xabcde);
    const auto snapshot = SnapshotCounters(f.state);
    for (unsigned i : {6U,8U,12U,20U,27U,29U,30U,39U,40U}) RS2_CHECK(snapshot.entered[i] == snapshot.completed[i] && snapshot.entered[i] > 0);
    for (const auto& e : f.events) {
        RS2_CHECK(e.method != Method::SetKeyValue);
        if (e.flags & HasSteamId) RS2_CHECK(e.steamId == kSteamId);
    }
}
void CacheAndAdmission() {
    { Fixture f; RS2_CHECK(f.Factory() == &f.real); RS2_CHECK(ReadGate(f.state) == Gate::Contaminated); RS2_CHECK(f.factoryCalls == 1); }
    { Fixture f; SetLastError(kIncoming); RS2_CHECK(FactoryEntry(41, kVersion) == &f.real); RS2_CHECK(ReadGate(f.state) == Gate::Preparing); }
    { Fixture f; RS2_CHECK(f.Factory(41, kUnreadable) == &f.real); RS2_CHECK(ReadGate(f.state) == Gate::Preparing); }
    { Fixture f; SetLastError(kIncoming); ShutdownEntry(); RS2_CHECK(ReadGate(f.state) == Gate::Contaminated); RS2_CHECK(f.shutdownCalls == 1); }
    { Fixture f; SetLastError(kIncoming); RS2_CHECK(!CallInit()); RS2_CHECK(ReadGate(f.state) == Gate::Contaminated); RS2_CHECK(f.initCalls == 1); }
    { Fixture f; f.Arm(); f.factoryResult = nullptr; RS2_CHECK(f.Factory() == nullptr); RS2_CHECK(f.state.bindingCount == 0); }
    { Fixture f; auto* proxy = f.Bind(); RS2_CHECK(f.Factory() == proxy); RS2_CHECK(f.validations == 1); RS2_CHECK(f.factoryCalls == 2);
      SetLastError(kIncoming); ShutdownEntry(); RS2_CHECK(GetLastError() == kOutgoing);
      SetLastError(kIncoming); Slot<VoidMethod>(proxy, 6)(proxy); // Retained proxy stays functional.
      auto* next = f.Factory(); RS2_CHECK(next != proxy && next != &f.real); RS2_CHECK(f.state.bindingCount == 2); }
    { Fixture f; f.valid = false; f.Arm(); RS2_CHECK(f.Factory() == &f.real); f.valid = true;
      RS2_CHECK(f.Factory() == &f.real); RS2_CHECK(f.validations == 1); }
    { Fixture f; auto* first = f.Bind(); for (int user = 42; user < 57; ++user) RS2_CHECK(f.Factory(user) != &f.real);
      RS2_CHECK(f.state.bindingCount == 16); RS2_CHECK(f.Factory(99) == &f.real);
      RS2_CHECK(f.Factory() == first); RS2_CHECK(f.state.exhausted == 1); }
    { Fixture f; f.Arm(); f.factoryAction = 1; RS2_CHECK(f.Factory() == &f.real); RS2_CHECK(f.state.bindingCount == 0);
      RS2_CHECK(f.Factory() != &f.real); }
    { Fixture f; f.Arm(); f.validationAction = 1; RS2_CHECK(f.Factory() == &f.real); RS2_CHECK(f.state.bindingCount == 0); }
    { Fixture f; f.Arm(); f.lifecycleAction = 1; SetLastError(kIncoming); ShutdownEntry();
      RS2_CHECK(f.nestedResult == &f.real); RS2_CHECK(f.state.bindingCount == 0); }
}
void Coalescing() {
    Fixture f; auto* proxy = f.Bind(); f.events.clear();
    for (int pass = 0; pass < 3; ++pass) {
        SetLastError(kIncoming); RS2_CHECK(Rs2AbiLoggedPublisher(proxy));
        SetLastError(kIncoming); RS2_CHECK(Rs2AbiLoggedAdvertise(proxy));
        SetLastError(kIncoming); RS2_CHECK(Slot<BoolMethod>(proxy,8)(proxy));
    }
    RS2_CHECK(f.events.size() == 3);
    f.loggedOn = false;
    SetLastError(kIncoming); RS2_CHECK(!Rs2AbiLoggedPublisher(proxy));
    const auto snapshot = SnapshotCounters(f.state);
    RS2_CHECK(snapshot.entered[8] == 10 && snapshot.completed[8] == 10);
    RS2_CHECK(snapshot.loggedOnResults[0][1] == 3 && snapshot.loggedOnResults[0][0] == 1);
    RS2_CHECK(snapshot.loggedOnResults[1][1] == 3 && snapshot.loggedOnResults[2][1] == 3);
    RS2_CHECK(f.events.size() == 4);
}
DWORD SehCall(bool init, DWORD* error) {
    __try { if (init) CallInit(); else ShutdownEntry(); }
    __except(GetExceptionCode() == 0xe0424242U ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        *error = GetLastError(); return GetExceptionCode();
    }
    return 0;
}
void LifecycleAndUnwind() {
    for (bool init : {false, true}) for (int mode : {0, 1, 2}) {
        Fixture f; f.Arm(); f.throwMode = mode;
        bool caught = false; DWORD error{};
        SetLastError(kIncoming);
        if (mode == 2) caught = SehCall(init, &error) == 0xe0424242U;
        else {
            try { if (init) RS2_CHECK(!CallInit()); else ShutdownEntry(); }
            catch (int value) { caught = value == 73; }
            error = GetLastError();
        }
        const auto snapshot = SnapshotCounters(f.state);
        RS2_CHECK(caught == (mode != 0)); RS2_CHECK(error == kOutgoing);
        RS2_CHECK(snapshot.lifecycle == (1ULL << 32));
        const auto index = init ? 45U : 46U;
        RS2_CHECK(snapshot.entered[index] == 1 && snapshot.completed[index] == (mode == 0 ? 1U : 0U));
        RS2_CHECK((init ? f.initCalls : f.shutdownCalls) == 1);
        RS2_CHECK(f.forwardingErrors == 0);
        RS2_CHECK(f.events.back().phase == (mode == 0 ? Phase::Complete : Phase::Unwind));
    }
    for (const std::uint64_t seeded : {0xffffffff00000000ULL, 0x00000000ffffffffULL}) {
        Fixture f; f.Arm(); InterlockedExchange64(&f.state.lifecycle, static_cast<LONG64>(seeded));
        SetLastError(kIncoming); ShutdownEntry();
        auto snapshot = SnapshotCounters(f.state);
        RS2_CHECK(snapshot.lifecycle == seeded && snapshot.unknownLifecycle);
        RS2_CHECK(f.shutdownCalls == 1 && snapshot.completed[46] == 1);
        RS2_CHECK(f.Factory() == &f.real && f.state.bindingCount == 0);
    }
    { Fixture f; auto* proxy = f.Bind(); InterlockedExchange64(&f.state.nextCallId, -1);
      InterlockedExchange64(&f.state.counters[6].entered, -1); SetLastError(kIncoming); Slot<VoidMethod>(proxy,6)(proxy);
      const auto s = SnapshotCounters(f.state); RS2_CHECK(s.entered[6] == UINT64_MAX);
      RS2_CHECK(s.coverageReasons & (1ULL << static_cast<unsigned>(Reason::CounterOverflow))); }
    { Fixture f; auto* proxy = f.Bind(); f.table[6] = reinterpret_cast<void*>(&Fake6Throw);
      bool caught = false; SetLastError(kIncoming);
      try { Slot<VoidMethod>(proxy,6)(proxy); } catch (int value) { caught = value == 19; }
      const DWORD error = GetLastError();
      const auto s = SnapshotCounters(f.state);
      RS2_CHECK(caught && error == kOutgoing && s.entered[6] == 1 && s.completed[6] == 0); }
}
void ConcurrentPublication() {
    Fixture f; f.Arm();
    f.validateEntered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    f.validateRelease = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    void* first{}; void* second{}; DWORD firstError{}, secondError{};
    std::thread a([&] { SetLastError(kIncoming); first = Rs2AbiFactoryCall(FactoryEntry, 41, kVersion); firstError = GetLastError(); });
    RS2_CHECK(WaitForSingleObject(f.validateEntered, 10000) == WAIT_OBJECT_0);
    std::thread b([&] { SetLastError(kIncoming); second = Rs2AbiFactoryCall(FactoryEntry, 41, kVersion); secondError = GetLastError(); });
    // The second factory can be admitted while the first validates. Both original
    // calls execute outside the cache lock, and publication double-checks the key.
    SetEvent(f.validateRelease);
    a.join(); b.join();
    RS2_CHECK(first == second && first != &f.real && f.state.bindingCount == 1);
    RS2_CHECK(f.factoryCalls == 2 && f.state.bindingsPublished == 1);
    RS2_CHECK(firstError == kOutgoing && secondError == kOutgoing && f.forwardingErrors == 0);
    CloseHandle(f.validateEntered); CloseHandle(f.validateRelease);
}
void ConcurrentLifecycle() {
    Fixture f; f.Arm();
    f.lifecycleEntered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    f.lifecycleRelease = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    DWORD initError{}, shutdownError{}; bool initResult = true;
    std::thread a([&] { SetLastError(kIncoming); initResult = CallInit(); initError = GetLastError(); });
    std::thread b([&] { SetLastError(kIncoming); ShutdownEntry(); shutdownError = GetLastError(); });
    RS2_CHECK(WaitForSingleObject(f.lifecycleEntered, 10000) == WAIT_OBJECT_0);
    auto snapshot = SnapshotCounters(f.state);
    RS2_CHECK(snapshot.lifecycle == ((2ULL << 32) | 2));
    RS2_CHECK(f.Factory() == &f.real);
    SetEvent(f.lifecycleRelease); a.join(); b.join();
    snapshot = SnapshotCounters(f.state);
    RS2_CHECK(snapshot.lifecycle == (2ULL << 32));
    RS2_CHECK(snapshot.completed[45] == 1 && snapshot.completed[46] == 1);
    RS2_CHECK(!initResult && initError == kOutgoing && shutdownError == kOutgoing && f.forwardingErrors == 0);
    CloseHandle(f.lifecycleEntered); CloseHandle(f.lifecycleRelease);
}
struct LifecycleRecord {
    unsigned entered{}, returned{}, finished{}, stopped{};
    std::uint64_t entryState{}, returnState{}, finishState{};
    bool ownedEntry{}, ownedReturn{}, normal{}, value{};
    static void Entered(void* opaque, std::uint64_t state, bool owned) noexcept {
        auto& r = *static_cast<LifecycleRecord*>(opaque);
        ++r.entered; r.entryState = state; r.ownedEntry = owned; SetLastError(kNoise);
    }
    static void Returned(void* opaque, std::uint64_t state, bool owned, bool result) noexcept {
        auto& r = *static_cast<LifecycleRecord*>(opaque);
        ++r.returned; r.returnState = state; r.ownedReturn = owned; r.value = result;
        SetLastError(kNoise);
    }
    static void Finished(void* opaque, std::uint64_t state, bool normal, bool result) noexcept {
        auto& r = *static_cast<LifecycleRecord*>(opaque);
        ++r.finished; r.finishState = state; r.normal = normal; r.value = result;
        SetLastError(kNoise);
    }
    static void Stopped(void* opaque, std::uint64_t) noexcept {
        ++static_cast<LifecycleRecord*>(opaque)->stopped; SetLastError(kNoise);
    }
    LifecycleSink Sink() { return {this, Entered, Returned, Finished, Stopped}; }
};
void ReportingLifecycleAndLookup() {
    for (int mode : {0, 1, 2}) {
        LifecycleRecord record;
        Fixture f(record.Sink()); f.Arm(); f.throwMode = mode;
        bool caught = false; DWORD error{};
        SetLastError(kIncoming);
        if (mode == 2) caught = SehCall(true, &error) == 0xe0424242U;
        else {
            try { RS2_CHECK(!CallInit()); } catch (int value) { caught = value == 73; }
            error = GetLastError();
        }
        RS2_CHECK(record.entered == 1 && record.ownedEntry);
        RS2_CHECK(record.entryState == ((1ULL << 32) | 1));
        RS2_CHECK(record.returned == (mode == 0 ? 1U : 0U));
        if (mode == 0) RS2_CHECK(record.ownedReturn && record.returnState == ((1ULL << 32) | 1));
        RS2_CHECK(record.finished == 1 && record.finishState == (1ULL << 32));
        RS2_CHECK(record.normal == (mode == 0) && !record.value);
        RS2_CHECK(caught == (mode != 0) && error == kOutgoing && f.forwardingErrors == 0);
        f.throwMode = 0; SetLastError(kIncoming); ShutdownEntry();
        RS2_CHECK(record.stopped == 1 && GetLastError() == kOutgoing && f.shutdownCalls == 1);
    }
    {
        Fixture f; auto* proxy = f.Bind();
        AcceptedBindingSnapshot copy{};
        RS2_CHECK(ReadAcceptedBinding(f.state, proxy, &copy) && copy.bindingId == proxy->bindingId);
        RS2_CHECK(ReadAcceptedBinding(f.state, &f.real, &copy));
        AcquireSRWLockExclusive(&f.state.cacheLock);
        const bool locked = ReadAcceptedBinding(f.state, proxy, &copy);
        ReleaseSRWLockExclusive(&f.state.cacheLock);
        RS2_CHECK(!locked && copy.bindingId == 0);
        RS2_CHECK(!ReadAcceptedBinding(f.state, reinterpret_cast<void*>(1), &copy));
        SetLastError(kIncoming); RS2_CHECK(!CallInit());
        RS2_CHECK(!ReadAcceptedBinding(f.state, proxy, &copy)); // A prior generation cannot qualify.
        auto* current = f.Factory();
        RS2_CHECK(ReadAcceptedBinding(f.state, current, &copy) && copy.lifecycle == (1ULL << 32));
        InterlockedExchange(&f.state.unknownLifecycle, 1);
        RS2_CHECK(!ReadAcceptedBinding(f.state, current, &copy));
    }
    {
        Fixture f;
        RS2_CHECK(!AdmitExternalCall(f.state) && ReadGate(f.state) == Gate::Contaminated);
    }
}
} // namespace
namespace rs2fix::testcases {
void RunObserverDispatchTests() {
    MappingAndAbi(); CacheAndAdmission(); Coalescing(); LifecycleAndUnwind(); ConcurrentPublication(); ConcurrentLifecycle();
    ReportingLifecycleAndLookup();
}
}
#if defined(RS2_OBSERVER_DISPATCH_TEST_MAIN)
int main() {
    rs2fix::testcases::RunObserverDispatchTests();
    std::cout << "checks=" << rs2fix::test::g_checks << " failures=" << rs2fix::test::g_failures << '\n';
    return rs2fix::test::g_failures ? 1 : 0;
}
#endif
