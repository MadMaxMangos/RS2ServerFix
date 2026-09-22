// Disposable own-code host state. No game bytes, Steam SDK or backend objects
// are loaded here. Native layouts are deliberately modelled with owned bytes;
// only the secondary tick receiver is a real C++ multiple-inheritance object.
#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <initializer_list>
#include <limits>
#include "steam_api_fixture.h"
#include "companion/steam_observer_dispatch.h"
#include "shared/steam_reporting_status.h"

#if !defined(RS2_REPORTING_FIXTURE) || !defined(RS2_OBSERVER_FIXTURE)
#error Reporting startup host requires both explicit own-fixture definitions.
#endif

extern "C" {
void FixtureReportEngine();
void FixtureReportSubsystem();
bool FixtureReportBuilder(void*);
extern const std::uintptr_t FixtureReportObjectVtable[];
extern const std::uintptr_t FixtureReportMetadataVtable[];
void* FixtureSteamAccessor();
extern std::uintptr_t FixtureSteamContext[3];
extern void* FixtureSteamPrivate;
extern void* FixtureSteamPublication;
extern FARPROC __imp_SteamInternal_GameServer_Init;
extern FARPROC __imp_SteamGameServer_Shutdown;
bool FixtureReportingPrehookPreserved() noexcept;

alignas(8) std::uintptr_t FixtureReportWorld{};
alignas(8) std::uintptr_t FixtureReportWorldInfoClass{};
alignas(8) std::uintptr_t FixtureReportTickableObject{};
alignas(8) unsigned char FixtureReportTaskPool[128 * 0x78]{};
alignas(4) std::uint32_t FixtureReportSelectedId{};
alignas(4) std::uint32_t FixtureReportInvalidId{};
alignas(4) std::uint32_t FixtureReportCounter{};
alignas(8) std::uintptr_t FixtureReportRegistry{};
alignas(4) std::uint32_t FixtureReportService{};
alignas(8) unsigned char FixtureReportRegistration[32]{};
alignas(8) unsigned char FixtureReportGameMode[32]{};
alignas(4) std::uint32_t FixtureReportMaximum{};
alignas(8) std::uintptr_t FixtureReportMembers[3]{};
alignas(8) unsigned char FixtureReportPublicIp[16]{};
volatile unsigned char FixtureReportFullDirty{};
volatile DWORD FixtureReportCallbackErrors{};
volatile DWORD FixtureReportBuilderErrors{};
volatile DWORD FixtureReportLastBuilderResult{};
volatile DWORD FixtureReportSkipBuilder{};
alignas(8) volatile LONGLONG FixtureReportPumpBefore{};
alignas(8) volatile LONGLONG FixtureReportPumpAfter{};
alignas(8) volatile LONGLONG FixtureReportBuilderBefore{};
alignas(8) volatile LONGLONG FixtureReportBuilderAfter{};
volatile DWORD FixtureReportTimingClockErrors{};
}

class FixtureReportPrimary {
public:
    virtual void UnusedPrimary() {}
    unsigned char padding[88]{};
};
class FixtureReportSecondary {
public:
    virtual void UnusedSecondary() {}
    virtual void Tick() = 0;
};
class FixtureReportTickable final : public FixtureReportPrimary, public FixtureReportSecondary {
public:
    __declspec(noinline) void Tick() override;
};
static_assert(sizeof(FixtureReportPrimary) == 0x60);
// The generated fixture profile must verify this compiled E9 tail jump, not
// assume it. An extra compiler frame must fail qualification, not be skipped.
void FixtureReportTickable::Tick() { FixtureReportSubsystem(); }

namespace {
namespace api = rs2fix::observer;
namespace reporting = rs2fix::reporting;
constexpr std::uint32_t kHolder = (43U << 16) | 17U;
constexpr unsigned kLoops = 5;
constexpr unsigned kTimingSamples = 1024;
constexpr unsigned kMainPumps = 6000;
constexpr unsigned kProtocolIterations = kMainPumps + 1 + kTimingSamples;
constexpr unsigned kPairedPumps = kProtocolIterations - 1;
unsigned char* g_heap{};
DWORD g_builderCalls{}, g_fullBuilds{}, g_falseBuilds{}, g_holderErrors{}, g_producerConsumed{};
LONGLONG g_builderInnerBefore{}, g_builderInnerAfter{};
DWORD g_builderInnerCall{}, g_builderInnerClockErrors{};
bool g_falseFirstFull{}, g_falseAll{};

bool Option(const wchar_t* option) noexcept {
    const wchar_t* cursor = GetCommandLineW();
    const auto length = std::wcslen(option);
    while (*cursor) {
        while (*cursor == L' ' || *cursor == L'\t') ++cursor;
        const auto* start = cursor;
        bool quoted = false;
        while (*cursor && (quoted || (*cursor != L' ' && *cursor != L'\t'))) {
            if (*cursor == L'"') quoted = !quoted;
            ++cursor;
        }
        if (static_cast<std::size_t>(cursor - start) == length && std::wmemcmp(start, option, length) == 0) return true;
    }
    return false;
}
template<class T> void Put(void* destination, const T& value) noexcept { std::memcpy(destination, &value, sizeof(value)); }
template<class T> T Get(const void* source) noexcept { T value{}; std::memcpy(&value, source, sizeof(value)); return value; }
std::uintptr_t Heap(std::size_t offset = 0) noexcept { return reinterpret_cast<std::uintptr_t>(g_heap + offset); }

bool PrepareJson(std::uint32_t count, std::uint32_t bots) noexcept {
    auto* json = reinterpret_cast<char*>(g_heap + 0x8000);
    const auto length = std::snprintf(json, 4096,
        "{\"ip\":\"192.0.2.1\",\"pr\":7777,\"op\":[{\"k\":\"PI_COUNT\",\"v\":\"%u\"},"
        "{\"k\":\"BotPlayerCount\",\"v\":\"%u\"},{\"k\":\"MaxPlayerCount\",\"v\":\"64\"}]}", count, bots);
    if (length <= 0 || length >= 4096) return false;
    Put(FixtureReportGameMode, reinterpret_cast<std::uintptr_t>(json));
    Put(FixtureReportGameMode + 0x10, static_cast<std::uint64_t>(length));
    Put(FixtureReportGameMode + 0x18, std::uint64_t{4095});
    FixtureReportMembers[0] = Heap(0x9000);
    FixtureReportMembers[1] = Heap(0x9000) + static_cast<std::uintptr_t>(count) * 0x20;
    FixtureReportMembers[2] = Heap(0xA000);
    return true;
}
bool SetUp(void* interfaceObject) noexcept {
    g_heap = static_cast<unsigned char*>(VirtualAlloc(nullptr, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!g_heap) return false;
    for (const auto offset : {0U, 0x1000U, 0x3000U, 0x4000U, 0x5000U, 0x5100U})
        Put(g_heap + offset, reinterpret_cast<std::uintptr_t>(FixtureReportObjectVtable));
    FixtureReportWorld = Heap(); FixtureReportWorldInfoClass = Heap(0x5100);
    Put(g_heap + 0x80, Heap(0x1000));
    Put(g_heap + 0x1000 + 0x60, Heap(0x2000));
    Put(g_heap + 0x1000 + 0x68, std::int32_t{64});
    Put(g_heap + 0x1000 + 0x6C, std::int32_t{128});
    Put(g_heap + 0x2000, Heap(0x3000));
    Put(g_heap + 0x3000 + 0x50, Heap(0x5000));
    Put(g_heap + 0x5000 + 0x78, Heap(0x5100));
    Put(g_heap + 0x3000 + 0x5CC, Heap(0x4000));
    Put(g_heap + 0x3000 + 0x398, std::uint32_t{0x100});
    Put(g_heap + 0x3000 + 0x598, std::uint8_t{1});
    Put(g_heap + 0x3000 + 0x4FC, 1000.0F);
    Put(g_heap + 0x4000 + 0x2E4, std::int32_t{64});
    Put(g_heap + 0x4000 + 0x2EC, std::int32_t{40});
    Put(g_heap + 0x4000 + 0x2F0, std::int32_t{24});
    Put(g_heap + 0x6000, reinterpret_cast<std::uintptr_t>(interfaceObject));
    Put(g_heap + 0x6000 + 0x94, std::uint32_t{21});
    Put(g_heap + 0x6000 + 0x98, std::uint32_t{62});
    Put(g_heap + 0x6000 + 0x9C, std::uint32_t{64});
    Put(g_heap + 0x6000 + 0xA4, 12.0F);
    FixtureSteamPrivate = reinterpret_cast<void*>(Heap(0x6000));
    FixtureSteamPublication = FixtureSteamPrivate;
    FixtureSteamContext[1] = 1;
    FixtureSteamContext[2] = reinterpret_cast<std::uintptr_t>(interfaceObject);
    FixtureReportService = 3; FixtureReportMaximum = 64;
    const char registration[] = "fixture";
    std::memcpy(FixtureReportRegistration, registration, sizeof(registration));
    Put(FixtureReportRegistration + 0x10, std::uint64_t{sizeof(registration) - 1});
    Put(FixtureReportRegistration + 0x18, std::uint64_t{15});
    const wchar_t ip[] = L"192.0.2.1";
    std::memcpy(g_heap + 0x7000, ip, sizeof(ip));
    Put(FixtureReportPublicIp, Heap(0x7000));
    Put(FixtureReportPublicIp + 8, std::int32_t{10});
    Put(FixtureReportPublicIp + 12, std::int32_t{16});
    if (!PrepareJson(62, 21)) return false;
    Put(g_heap + 0xB000, reinterpret_cast<std::uintptr_t>(FixtureReportMetadataVtable));
    FixtureReportRegistry = Heap(0xB000);
    FixtureReportSelectedId = 5; FixtureReportCounter = 9;
    Put(FixtureReportTaskPool, std::uint32_t{2});
    Put(FixtureReportTaskPool + 4, FixtureReportSelectedId);
    Put(FixtureReportTaskPool + 8, Heap(0xC000));
    Put(FixtureReportTaskPool + 0x38, kHolder);
    Put(FixtureReportTaskPool + 0x40, reinterpret_cast<std::uintptr_t>(&FixtureReportBuilder));
    Put(FixtureReportTaskPool + 0x60, std::uint64_t{30000});
    return true;
}
void TearDown() noexcept {
    FixtureReportWorld = 0; FixtureReportWorldInfoClass = 0; FixtureReportTickableObject = 0;
    FixtureSteamPublication = nullptr; FixtureSteamPrivate = nullptr;
    FixtureSteamContext[1] = 0; FixtureSteamContext[2] = 0;
    FixtureReportRegistry = 0; FixtureReportSelectedId = 0;
    if (g_heap) VirtualFree(g_heap, 0, MEM_RELEASE);
    g_heap = nullptr;
}
bool ReadExact(const void* address, void* output, std::size_t size) noexcept {
    SIZE_T got{};
    return ReadProcessMemory(GetCurrentProcess(), address, output, size, &got) && got == size;
}
bool ReadStatus(reporting::StatusWire* output) noexcept {
    *output = {};
    // GetProcAddress addresses ONLY the already loaded own-code companion. No
    // function is called through its DATA export and no game module is opened.
    const auto companion = GetModuleHandleW(L"RS2ServerFix.dll");
    const auto* wire = reinterpret_cast<const reporting::StatusWire*>(
        companion ? GetProcAddress(companion, "RS2SteamReport_StatusV2") : nullptr);
    MEMORY_BASIC_INFORMATION region{};
    if (!wire || VirtualQuery(wire, &region, sizeof(region)) != sizeof(region) ||
        region.State != MEM_COMMIT || region.Type != MEM_IMAGE || region.AllocationBase != companion ||
        region.Protect != PAGE_READWRITE) return false;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        std::uint64_t before{}, after{};
        if (!ReadExact(&wire->ownerSequence, &before, sizeof(before)) || (before & 1) ||
            !ReadExact(wire, output, sizeof(*output)) ||
            !ReadExact(&wire->ownerSequence, &after, sizeof(after))) return false;
        if (before != after || output->ownerSequence != before || (after & 1)) continue;
        return output->headerReady == 1 && output->header.magic == reporting::kStatusMagic &&
            output->header.schema == reporting::kStatusSchema && output->header.bytes == sizeof(*output) &&
            output->header.artifactVersion == reporting::kReportingArtifactVersion;
    }
    *output = {}; return false;
}

enum class TimingRole { Warmup, Main, Bridge, Support, Selected };
const char* RoleName(TimingRole role) noexcept {
    switch (role) {
    case TimingRole::Warmup: return "warmup";
    case TimingRole::Main: return "main";
    case TimingRole::Bridge: return "bridge";
    case TimingRole::Support: return "support";
    case TimingRole::Selected: return "selected";
    }
    return "invalid";
}
struct TimingOrdinal {
    TimingRole role{};
    std::uint64_t ordinal{}, call{};
    LONGLONG outerBefore{}, outerAfter{}, innerBefore{}, innerAfter{};
    std::uint64_t own{}, missing{}, durationClass{};
    bool paired{};
};
// Fixture-private custody only. Printing occurs after timing finalization, so
// per-sample output cannot change the next measurement's scheduling or caches.
TimingOrdinal g_timingOrdinals[1 + kProtocolIterations + kTimingSamples]{};
unsigned g_timingOrdinalCount{};
struct TimingResult {
    std::uint64_t pumpSamples{};
    std::uint64_t builderSamples{};
    std::uint64_t builderSelected{};
    std::uint64_t pumpMaximumMissing{};
    std::uint64_t builderMaximumMissing{};
    std::uint64_t frequency{};
    std::uint64_t pumpWindowStart{}, pumpWindowEnd{}, pumpOwn{}, pumpCorrected{};
    std::uint64_t calibrationStart{}, calibrationEnd{};
    reporting::DurationCounters classes[reporting::kStatusDurationClasses]{};
    reporting::DurationCounters mainClasses[reporting::kStatusDurationClasses]{};
    reporting::DurationCounters auxiliaryClasses[reporting::kStatusDurationClasses]{};
    std::uint64_t residualSums[reporting::kStatusDurationClasses]{};
    std::uint64_t residualMaxima[reporting::kStatusDurationClasses]{};
    reporting::StatusHeader identity{};
    std::uint64_t sourceEpoch{}, bindingEpoch{};
    bool haveIdentity{};
    const char* failure{"none"};
};
struct TimingCounters {
    std::uint64_t pumpOwnTicks{};
    std::uint64_t builderOwnTicks{};
    std::uint64_t pumpCalls{};
    std::uint64_t builderCalls{};
};
bool AddCounter(std::uint64_t& total, std::uint64_t value) noexcept {
    if (value > (std::numeric_limits<std::uint64_t>::max)() - total) return false;
    total += value;
    return true;
}
bool Counters(const reporting::StatusWire& wire, TimingCounters* output) noexcept {
    *output = {};
    static_assert(reporting::kStatusDurationClasses == 4);
    for (std::size_t i = 0; i < reporting::kStatusDurationClasses; ++i) {
        if (!AddCounter(i < 2 ? output->pumpOwnTicks : output->builderOwnTicks,
                wire.owner.durations[i].elapsedTicks) ||
            !AddCounter(i < 2 ? output->pumpCalls : output->builderCalls,
                wire.owner.durations[i].calls)) return false;
    }
    return true;
}
bool HealthyTimingStatus(const reporting::StatusWire& wire, std::uint64_t frequency) noexcept {
    return wire.header.validity == reporting::CompleteHeaderIdentity && wire.header.pid == GetCurrentProcessId() &&
        wire.header.configuredMode == 3 && wire.header.qpcFrequency == frequency &&
        wire.owner.phase == static_cast<std::uint64_t>(reporting::ReportPhase::Repairing) &&
        !wire.revokeReasons && !wire.lossReasons && !wire.stopping && wire.owner.fresh == 1;
}
bool Increase(std::uint64_t before, std::uint64_t after, std::uint64_t expected) noexcept {
    return after >= before && after - before == expected;
}
bool AccumulateSample(reporting::DurationCounters& total, std::uint64_t ticks,
    std::uint64_t over) noexcept {
    if (!AddCounter(total.calls, 1) || !AddCounter(total.elapsedTicks, ticks) ||
        !AddCounter(total.overFiveMilliseconds, over)) return false;
    if (ticks > total.maximumTicks) total.maximumTicks = ticks;
    return true;
}
bool RecordTimingSample(const reporting::StatusWire& before, const reporting::StatusWire& after,
    bool builder, TimingOrdinal& ordinal, TimingResult& result) noexcept {
    const std::size_t begin = builder ? 2 : 0;
    std::uint64_t calls{}, own{}, overrun{};
    std::size_t selectedClass = reporting::kStatusDurationClasses;
    for (std::size_t i = begin; i < begin + 2; ++i) {
        const auto& a = before.owner.durations[i]; const auto& b = after.owner.durations[i];
        if (b.calls < a.calls || b.elapsedTicks < a.elapsedTicks ||
            b.overFiveMilliseconds < a.overFiveMilliseconds) return false;
        const auto count = b.calls - a.calls, ticks = b.elapsedTicks - a.elapsedTicks;
        const auto over = b.overFiveMilliseconds - a.overFiveMilliseconds;
        if (count > 1 || (!count && (ticks || over)) || (count && over != (ticks > result.frequency / 200 ? 1U : 0U)) ||
            !AddCounter(calls, count) || !AddCounter(own, ticks)) return false;
        if (count) { selectedClass = i; overrun = over; }
    }
    if (ordinal.paired || ordinal.outerBefore < 0 || ordinal.outerAfter < ordinal.outerBefore ||
        ordinal.innerBefore < ordinal.outerBefore || ordinal.innerAfter < ordinal.innerBefore ||
        ordinal.innerAfter > ordinal.outerAfter || builder != (ordinal.role == TimingRole::Selected)) return false;
    const auto wall = static_cast<std::uint64_t>(ordinal.outerAfter - ordinal.outerBefore);
    const auto inner = static_cast<std::uint64_t>(ordinal.innerAfter - ordinal.innerBefore);
    // Subtraction ordering proves own+inner<=wall without overflowing a sum.
    if (calls != 1 || selectedClass >= reporting::kStatusDurationClasses || own > wall || inner > wall - own ||
        (builder && selectedClass != 3)) return false;
    const auto missing = wall - own - inner;
    ordinal.own = own; ordinal.missing = missing; ordinal.durationClass = selectedClass;
    if (ordinal.role == TimingRole::Warmup) return true; // Retained, deliberately outside this protocol's pairs.
    if (!AccumulateSample(result.classes[selectedClass], own, overrun) ||
        !AddCounter(result.residualSums[selectedClass], missing)) return false;
    if (missing > result.residualMaxima[selectedClass]) result.residualMaxima[selectedClass] = missing;
    if (ordinal.role == TimingRole::Main) {
        if (!AccumulateSample(result.mainClasses[selectedClass], own, overrun) || !AddCounter(result.pumpOwn, own)) return false;
    } else if (!builder && !AccumulateSample(result.auxiliaryClasses[selectedClass], own, overrun)) return false;
    ordinal.paired = true;
    if (builder) {
        ++result.builderSamples; ++result.builderSelected;
        if (missing > result.builderMaximumMissing) result.builderMaximumMissing = missing;
    } else {
        ++result.pumpSamples;
        if (missing > result.pumpMaximumMissing) result.pumpMaximumMissing = missing;
    }
    return true;
}
bool TimingProtocol(TimingResult& result, FixtureSteamSnapshotFn snapshot) noexcept {
    const auto warmup = snapshot();
    g_timingOrdinalCount = 1;
    g_timingOrdinals[0] = {TimingRole::Warmup, 0, warmup.pump,
        FixtureReportPumpBefore, FixtureReportPumpAfter, warmup.pumpInnerBefore, warmup.pumpInnerAfter};
    unsigned previousPump = 0;
    // Every Engine publishes the preceding pump and, when present, its own
    // builder. Keep one uninterrupted ordinal chain across all phase boundaries.
    for (unsigned iteration = 0; iteration < kProtocolIterations; ++iteration) {
        const bool builder = iteration > kMainPumps;
        const auto role = iteration < kMainPumps ? TimingRole::Main :
            (builder ? TimingRole::Support : TimingRole::Bridge);
        FixtureReportSkipBuilder = builder ? 0 : 1;
        // Only this disposable process waits. All pacing and status reads are
        // OUTSIDE the measured wrapper interval; no logging is done per sample.
        Sleep(iteration < kMainPumps ? 50 : 1);
        reporting::StatusWire before{}, after{};
        TimingCounters first{}, last{};
        if (!ReadStatus(&before) || !HealthyTimingStatus(before, result.frequency)) {
            result.failure = "status-before"; return false;
        }
        if (!before.owner.sourceEpoch || !before.owner.bindingEpoch) {
            result.failure = "epoch-unavailable"; return false;
        }
        if (!result.haveIdentity) {
            result.identity = before.header;
            result.sourceEpoch = before.owner.sourceEpoch; result.bindingEpoch = before.owner.bindingEpoch;
            result.haveIdentity = true;
        } else if (std::memcmp(&result.identity, &before.header, sizeof(before.header)) ||
            result.sourceEpoch != before.owner.sourceEpoch || result.bindingEpoch != before.owner.bindingEpoch) {
            result.failure = "calibration-identity-changed"; return false;
        }
        if (!Counters(before, &first)) { result.failure = "counter-sum-before"; return false; }
        const auto nativeBefore = snapshot();
        if (!nativeBefore.pump || first.pumpCalls != nativeBefore.pump - 1 ||
            !g_builderCalls || first.builderCalls != g_builderCalls - 1) {
            result.failure = "publication-lag-before"; return false;
        }
        const auto nativeBuilderBefore = static_cast<std::uint64_t>(g_builderCalls);
        const auto nativeFullBefore = static_cast<std::uint64_t>(g_fullBuilds);
        const auto nativeFalseBefore = static_cast<std::uint64_t>(g_falseBuilds);
        const auto priorBuilderBefore = FixtureReportBuilderBefore;
        const auto priorBuilderAfter = FixtureReportBuilderAfter;
        const auto priorBuilderInnerBefore = g_builderInnerBefore;
        const auto priorBuilderInnerAfter = g_builderInnerAfter;
        const auto priorBuilderInnerCall = g_builderInnerCall;
        LARGE_INTEGER start{}, end{};
        if (!QueryPerformanceCounter(&start) || start.QuadPart < 0) { result.failure = "clock-before"; return false; }
        FixtureReportEngine();
        const bool haveEnd = QueryPerformanceCounter(&end) != FALSE;
        const auto nativeAfter = snapshot();
        // Retain raw ordinals before later validation can reject a sample. A
        // rejected/incomplete protocol is never emitted as calibration evidence.
        const unsigned currentPump = g_timingOrdinalCount++;
        g_timingOrdinals[currentPump] = {role, iteration + 1ULL, nativeAfter.pumpInnerCall,
            FixtureReportPumpBefore, FixtureReportPumpAfter, nativeAfter.pumpInnerBefore, nativeAfter.pumpInnerAfter};
        const unsigned currentBuilder = g_timingOrdinalCount;
        if (builder) {
            g_timingOrdinals[g_timingOrdinalCount++] = {TimingRole::Selected, iteration + 1ULL,
                g_builderInnerCall, FixtureReportBuilderBefore, FixtureReportBuilderAfter,
                g_builderInnerBefore, g_builderInnerAfter};
        }
        if (!haveEnd || end.QuadPart < start.QuadPart) {
            result.failure = "clock-after"; return false;
        }
        if (!ReadStatus(&after) || !HealthyTimingStatus(after, result.frequency) ||
            std::memcmp(&before.header, &after.header, sizeof(before.header)) ||
            before.owner.sourceEpoch != after.owner.sourceEpoch || before.owner.bindingEpoch != after.owner.bindingEpoch) {
            result.failure = "status-after"; return false;
        }
        if (!Counters(after, &last) || last.pumpOwnTicks < first.pumpOwnTicks ||
            last.builderOwnTicks < first.builderOwnTicks) {
            result.failure = "counter-sum-after"; return false;
        }
        // Detect per-class decreases too; a larger different bucket must not
        // conceal a reset or torn cumulative field in the summed total.
        for (std::size_t i = 0; i < reporting::kStatusDurationClasses; ++i) {
            if (after.owner.durations[i].elapsedTicks < before.owner.durations[i].elapsedTicks ||
                after.owner.durations[i].calls < before.owner.durations[i].calls ||
                after.owner.durations[i].overFiveMilliseconds < before.owner.durations[i].overFiveMilliseconds ||
                after.owner.durations[i].maximumTicks < before.owner.durations[i].maximumTicks) {
                result.failure = "counter-decrease"; return false;
            }
        }
        const auto expectedBuilders = builder ? 1ULL : 0ULL;
        if (!Increase(nativeBefore.pump, nativeAfter.pump, 1) ||
            last.pumpCalls != nativeAfter.pump - 1 || last.builderCalls != g_builderCalls - 1 ||
            nativeBefore.init != nativeAfter.init || nativeBefore.factory != nativeAfter.factory ||
            nativeBefore.shutdown != nativeAfter.shutdown || nativeAfter.badArguments || nativeAfter.pumpClockErrors ||
            nativeAfter.pumpInnerCall != nativeAfter.pump || g_builderInnerClockErrors ||
            !Increase(first.pumpCalls, last.pumpCalls, 1) ||
            !Increase(first.builderCalls, last.builderCalls, expectedBuilders) ||
            !Increase(nativeBuilderBefore, g_builderCalls, expectedBuilders) ||
            !Increase(nativeFullBefore, g_fullBuilds, expectedBuilders) ||
            !Increase(nativeFalseBefore, g_falseBuilds, 0) ||
            !Increase(before.owner.fullSelected, after.owner.fullSelected, expectedBuilders) ||
            !Increase(before.owner.selectedTrue, after.owner.selectedTrue, expectedBuilders) ||
            !Increase(before.owner.normalAttempts, after.owner.normalAttempts, expectedBuilders) ||
            FixtureReportCallbackErrors || FixtureReportBuilderErrors || g_holderErrors) {
            result.failure = "exact-selected-path"; return false;
        }
        // The C++ Engine clock is an ordering guard only, never the calibration
        // interval. The host ASM brackets the actual patched IAT/builder call,
        // excluding unrelated fake world, producer and other-wrapper work.
        const auto pumpBefore = FixtureReportPumpBefore;
        const auto pumpAfter = FixtureReportPumpAfter;
        const auto builderBefore = FixtureReportBuilderBefore;
        const auto builderAfter = FixtureReportBuilderAfter;
        if (FixtureReportTimingClockErrors || pumpBefore < start.QuadPart || pumpAfter < pumpBefore ||
            pumpAfter > end.QuadPart || (builder && (builderBefore < start.QuadPart ||
                builderAfter < builderBefore || builderAfter > pumpBefore)) ||
            (!builder && (builderBefore != priorBuilderBefore || builderAfter != priorBuilderAfter))) {
            result.failure = "host-bookend-order"; return false;
        }
        // Only inner ORIGINAL bodies are subtracted. Their prologue/epilogue,
        // QPC bookend cost and host callsite overhead remain conservatively in
        // the residual. No clock is interposed on production store -> original.
        if (nativeAfter.pumpInnerBefore < pumpBefore || nativeAfter.pumpInnerAfter < nativeAfter.pumpInnerBefore ||
            nativeAfter.pumpInnerAfter > pumpAfter ||
            (builder && (g_builderInnerCall != g_builderCalls || g_builderInnerBefore < builderBefore ||
                g_builderInnerAfter < g_builderInnerBefore || g_builderInnerAfter > builderAfter)) ||
            (!builder && (g_builderInnerBefore != priorBuilderInnerBefore ||
                g_builderInnerAfter != priorBuilderInnerAfter || g_builderInnerCall != priorBuilderInnerCall))) {
            result.failure = "inner-original-order-or-identity"; return false;
        }
        auto& previous = g_timingOrdinals[previousPump];
        if (previous.call != nativeBefore.pump || previous.call != nativeBefore.pumpInnerCall ||
            previous.ordinal != iteration || previous.innerBefore != nativeBefore.pumpInnerBefore ||
            previous.innerAfter != nativeBefore.pumpInnerAfter ||
            !RecordTimingSample(before, after, false, previous, result) ||
            (builder && !RecordTimingSample(before, after, true, g_timingOrdinals[currentBuilder], result))) {
            result.failure = "sample-accounting-or-negative-residual"; return false;
        }
        previousPump = currentPump;
        if (!iteration) result.calibrationStart = static_cast<std::uint64_t>(pumpBefore);
        result.calibrationEnd = static_cast<std::uint64_t>(pumpAfter);
        if (iteration < kMainPumps) {
            if (!iteration) result.pumpWindowStart = static_cast<std::uint64_t>(pumpBefore);
            result.pumpWindowEnd = static_cast<std::uint64_t>(pumpAfter);
        }
    }
    return true;
}
bool TimingFixture(FixtureSteamSnapshotFn snapshot) noexcept {
    TimingResult result{};
    LARGE_INTEGER frequency{};
    bool ok = QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0 && frequency.QuadPart <= INT64_MAX / 45;
    if (!ok) result.failure = "clock-frequency";
    else {
        result.frequency = static_cast<std::uint64_t>(frequency.QuadPart);
        ok = TimingProtocol(result, snapshot);
    }
    FixtureReportSkipBuilder = 0;
    const auto window = result.pumpWindowEnd >= result.pumpWindowStart ? result.pumpWindowEnd - result.pumpWindowStart : 0;
    const auto span = result.calibrationEnd >= result.calibrationStart ? result.calibrationEnd - result.calibrationStart : 0;
    if (ok && (!window || !span || result.pumpSamples != kPairedPumps || result.builderSamples != kTimingSamples ||
        result.builderSelected != kTimingSamples || g_timingOrdinalCount != 1 + kProtocolIterations + kTimingSamples)) {
        result.failure = "protocol-count-or-empty-window"; ok = false;
    }
    if (ok) {
        result.pumpCorrected = result.pumpOwn;
        std::uint64_t mainCalls{}, mainTicks{}, auxiliaryCalls{}, auxiliaryTicks{}, allTicks{}, allResidual{};
        for (std::size_t i = 0; i < reporting::kStatusDurationClasses; ++i) {
            const auto& c = result.classes[i];
            const auto& m = result.mainClasses[i];
            const auto& a = result.auxiliaryClasses[i];
            if (!AddCounter(allTicks, c.elapsedTicks) || !AddCounter(allResidual, result.residualSums[i]) ||
                c.maximumTicks > span || result.residualMaxima[i] > span ||
                (i < 2 && (c.calls < m.calls || c.elapsedTicks < m.elapsedTicks ||
                    c.calls - m.calls != a.calls || c.elapsedTicks - m.elapsedTicks != a.elapsedTicks ||
                    !AddCounter(mainCalls, m.calls) || !AddCounter(mainTicks, m.elapsedTicks) ||
                    !AddCounter(auxiliaryCalls, a.calls) || !AddCounter(auxiliaryTicks, a.elapsedTicks) ||
                    (m.calls && result.residualMaxima[i] > UINT64_MAX / m.calls) ||
                    !AddCounter(result.pumpCorrected, result.residualMaxima[i] * m.calls)))) {
                result.failure = "class-reconciliation-or-overflow"; ok = false; break;
            }
        }
        if (ok && (mainCalls != kMainPumps || mainTicks != result.pumpOwn || auxiliaryCalls != kTimingSamples ||
            result.classes[2].calls || result.classes[3].calls != kTimingSamples ||
            mainTicks > window || allTicks > span || allResidual > span - allTicks)) {
            result.failure = "phase-reconciliation-or-span"; ok = false;
        }
    }
    // Integer division preserves strict sum*1000 < window without overflow.
    const bool raw = ok && result.pumpOwn <= (window - 1) / 1000;
    const bool corrected = ok && result.pumpCorrected <= (window - 1) / 1000;
    const bool coverage = result.mainClasses[1].calls >= 64;
    bool classLimits = ok && result.classes[1].calls && result.classes[3].calls;
    for (std::size_t i = 0; i < reporting::kStatusDurationClasses; ++i) {
        const auto& c = result.classes[i];
        const bool pass = i < 2 ? c.overFiveMilliseconds <= c.calls / 100 : c.maximumTicks <= result.frequency / 200;
        classLimits = pass && classLimits;
        const auto& m = result.mainClasses[i]; const auto& a = result.auxiliaryClasses[i];
        std::printf("report_timing_class%zu=%s calls=%llu elapsed_ticks=%llu maximum_ticks=%llu over_five_milliseconds=%llu "
            "residual_sample_count=%llu residual_sum_ticks=%llu residual_maximum_ticks=%llu eligible=%s "
            "main_calls=%llu main_elapsed_ticks=%llu main_maximum_ticks=%llu main_over_five_milliseconds=%llu "
            "auxiliary_calls=%llu auxiliary_elapsed_ticks=%llu limit=%s\n",
            i, c.calls ? "observed" : "unobserved", c.calls, c.elapsedTicks, c.maximumTicks, c.overFiveMilliseconds,
            c.calls, result.residualSums[i], result.residualMaxima[i], ok && c.calls ? "true" : "false",
            m.calls, m.elapsedTicks, m.maximumTicks, m.overFiveMilliseconds, a.calls, a.elapsedTicks,
            pass ? "pass" : "fail");
    }
    for (unsigned i = 0; i < g_timingOrdinalCount; ++i) {
        const auto& o = g_timingOrdinals[i];
        std::printf("report_timing_ordinal=%u role=%s ordinal=%llu native_call=%llu "
            "outer_before=%lld outer_after=%lld inner_before=%lld inner_after=%lld "
            "state=%s reason=%s duration_class=%llu own_ticks=%llu residual_ticks=%llu\n",
            i, RoleName(o.role), o.ordinal, o.call, o.outerBefore, o.outerAfter, o.innerBefore, o.innerAfter,
            o.paired ? "paired" : "unpaired", o.paired ? "none" :
                (o.role == TimingRole::Warmup ? "warmup-outside-protocol" : (ok ? "final-support-not-published" : result.failure)),
            o.durationClass, o.own, o.missing);
    }
    // This artificial pump cadence and separate accelerated-builder phase are
    // calibration smoke, not the real server's all-wrapper qualification window.
    // Preserve the conservative aggregate diagnostic without promoting it into
    // that different gate. The collector still charges MAX overhead to all calls.
    std::printf("report_timing=%s pump_sample_count=%llu builder_sample_count=%llu builder_selected_count=%llu "
        "pump_maximum_missing_ticks=%llu builder_maximum_missing_ticks=%llu qpc_frequency=%llu "
        "measurement_id=rs2-wrapper-own-deferred-v2 protocol_id=rs2-deferred-v2-fixed6000-1024 "
        "main_pump_sample_count=6000 main_management_sample_count=%llu coverage_pass=%s "
        "ordinal_count=%u pump_bridge_calls=1 pump_duration_lag=1 builder_duration_lag=0 "
        "calibration_start_qpc=%llu calibration_end_qpc=%llu calibration_ticks=%llu "
        "pump_window_start_qpc=%llu pump_window_end_qpc=%llu pump_window_ticks=%llu pump_own_ticks=%llu pump_corrected_ticks=%llu "
        "pump_raw_aggregate=%s pump_corrected_aggregate=%s sample_class_limits=%s calibration_candidate=%s "
        "candidate_scope=coverage-raw-main-pump-and-per-class-smoke production_full_window=unqualified "
        "builder_stress_full_window_qualified=false "
        "envelope=outer-wrapper-minus-recorded-own-minus-inner-original builder_includes_pump_envelope=false "
        "inner_original_pairs=exact-call-checked residual_bound=empirical-not-wcrt failure_reason=%s\n",
        ok ? "pass" : "fail", result.pumpSamples, result.builderSamples, result.builderSelected,
        result.pumpMaximumMissing, result.builderMaximumMissing, result.frequency,
        result.mainClasses[1].calls, coverage ? "true" : "false", g_timingOrdinalCount,
        result.calibrationStart, result.calibrationEnd, span,
        result.pumpWindowStart, result.pumpWindowEnd, window, result.pumpOwn, result.pumpCorrected,
        raw ? "pass" : "fail", corrected ? "pass" : "fail", classLimits ? "pass" : "fail",
        coverage && raw && classLimits ? "pass" : "fail", result.failure);
    std::fflush(stdout);
    return ok;
}
void RunId(const reporting::StatusHeader& header, char (&output)[33]) noexcept {
    constexpr char hex[] = "0123456789abcdef";
    for (std::size_t i = 0; i < 16; ++i) {
        output[i * 2] = hex[header.runId[i] >> 4];
        output[i * 2 + 1] = hex[header.runId[i] & 15];
    }
    output[32] = 0;
}
} // namespace

extern "C" bool FixtureReportNativeBuild(void* borrowed) noexcept {
    const DWORD incoming = GetLastError();
    g_builderInnerBefore = 0; g_builderInnerAfter = 0; g_builderInnerCall = 0;
    LARGE_INTEGER before{}, after{};
    const bool started = QueryPerformanceCounter(&before) != FALSE;
    ++g_builderCalls;
    if (incoming != 0x4321 || !borrowed || Get<std::uint32_t>(borrowed) != kHolder) ++g_holderErrors;
    const bool full = FixtureReportFullDirty != 0;
    if (full) { ++g_fullBuilds; FixtureReportFullDirty = 0; }
    const bool result = !g_falseAll && !(g_falseFirstFull && full && g_fullBuilds == 1);
    if (!result) ++g_falseBuilds;
    const bool ended = QueryPerformanceCounter(&after) != FALSE;
    if (started && ended && before.QuadPart >= 0 && after.QuadPart >= before.QuadPart) {
        g_builderInnerBefore = before.QuadPart; g_builderInnerAfter = after.QuadPart;
        g_builderInnerCall = g_builderCalls;
    } else g_builderInnerClockErrors = 1;
    SetLastError(0x5678);
    return result;
}
extern "C" void FixtureReportNativeProduce() noexcept {
    // This is the OWN host's deterministic native producer, not a DLL shortcut.
    // It runs after the native builder and before the callback-pump boundary.
    auto timer = Get<float>(g_heap + 0x6000 + 0xA4);
    if (Get<std::uint8_t>(g_heap + 0x6000 + 0xA0)) {
        ++g_producerConsumed;
        const auto bots = Get<std::uint32_t>(g_heap + 0x6000 + 0x94);
        const auto count = Get<std::uint32_t>(g_heap + 0x4000 + 0x2EC) + bots + 1;
        Put(g_heap + 0x6000 + 0x98, count);
        Put(g_heap + 0x6000 + 0xA0, std::uint8_t{0});
        Put(g_heap + 0x6000 + 0xA1, std::uint8_t{0});
        timer = 0;
        if (!PrepareJson(count, bots)) ++FixtureReportBuilderErrors;
        FixtureReportFullDirty = 1;
    } else timer += 0.26F;
    Put(g_heap + 0x6000 + 0xA4, timer);
    const auto realTime = Get<float>(g_heap + 0x3000 + 0x4FC) + 0.26F;
    Put(g_heap + 0x3000 + 0x4FC, realTime);
}

bool ExerciseReportingFixture() {
    const auto sdk = GetModuleHandleW(L"rs2_test_steam_api.dll");
    const auto snapshot = reinterpret_cast<FixtureSteamSnapshotFn>(sdk ? GetProcAddress(sdk, "FixtureSteamReadSnapshot") : nullptr);
    if (!snapshot) return false;
    const auto before = snapshot();
    if (before.init || before.factory || before.shutdown || before.pump) return false;
    g_falseFirstFull = Option(L"--report-false-first-full");
    g_falseAll = Option(L"--report-builder-false");
    SetLastError(0x4321);
    const bool initialized = reinterpret_cast<api::InitFn>(__imp_SteamInternal_GameServer_Init)(
        0x10203040, 8766, 7777, 27015, 3, reinterpret_cast<const char*>(kFixtureUnreadablePointer));
    bool ok = GetLastError() == 0x5678 && initialized == !Option(L"--report-init-false");
    SetLastError(0x4321);
    void* interfaceObject = FixtureSteamAccessor();
    ok = interfaceObject && GetLastError() == 0x5678 && ok;
    if (!interfaceObject || !SetUp(interfaceObject)) { TearDown(); return false; }
    FixtureReportTickable tickable;
    auto* secondary = static_cast<FixtureReportSecondary*>(&tickable);
    const auto secondaryOffset = reinterpret_cast<std::uintptr_t>(secondary) - reinterpret_cast<std::uintptr_t>(&tickable);
    const auto exportedTable = GetProcAddress(GetModuleHandleW(nullptr), "FixtureReportSecondaryVtable");
    const auto actualTable = Get<std::uintptr_t>(secondary);
    if (secondaryOffset != 0x60 || actualTable != reinterpret_cast<std::uintptr_t>(exportedTable)) {
        TearDown(); return false;
    }
    FixtureReportTickableObject = reinterpret_cast<std::uintptr_t>(secondary);
    for (unsigned iteration = 0; iteration < kLoops; ++iteration) {
        if (iteration) Sleep(260); // Own process only; past the fast floor, idle calls may only forward.
        FixtureReportEngine();
    }
    const bool timing = Option(L"--report-timing-fixture");
    if (timing) ok = TimingFixture(snapshot) && ok;
    const auto active = snapshot();
    const auto expectedBuilders = kLoops + (timing ? kTimingSamples : 0);
    const auto expectedPumps = kLoops + (timing ? kProtocolIterations : 0);
    ok = g_builderCalls == expectedBuilders && active.init == 1 && active.factory == 1 && active.pump == expectedPumps &&
        active.shutdown == 0 && active.badArguments == 0 && !FixtureReportCallbackErrors &&
        !FixtureReportBuilderErrors && !FixtureReportTimingClockErrors && !g_holderErrors &&
        !g_builderInnerClockErrors && !active.pumpClockErrors &&
        g_builderInnerCall == g_builderCalls && active.pumpInnerCall == active.pump && ok;
    const bool prehook = Option(L"--prehook-steam-factory");
    if (prehook) {
        const bool preserved = FixtureReportingPrehookPreserved();
        std::printf("steam_prehook=installed-before-audio preserved=%s\n", preserved ? "true" : "false");
        ok = preserved && active.factoryAlias == 1 && ok;
    } else ok = active.factoryAlias == 0 && ok;
    reporting::StatusWire pre{};
    const bool haveStatus = ReadStatus(&pre);
    char runId[33]{}; RunId(pre.header, runId);
    std::printf("report_fixture=%s status_available=%s pid=%lu run_id=%s process_creation=%llu qpc_frequency=%llu "
        "header_ready=%llu header_validity=%u status_mode=%u phase=%llu reason=%llu revoke=%llu loss=%llu "
        "request=%llu witness=%llu normalAttempts=%llu fullSelected=%llu selectedTrue=%llu "
        "builder_calls=%lu full_builds=%lu false_builds=%lu producer_consumed=%lu callback_errors=%lu holder_errors=%lu clock_errors=%lu "
        "builder_inner_clock_errors=%lu pump_inner_clock_errors=%u "
        "init_result=%s factory_calls=%u factory_alias=%u init_calls=%u pump_calls=%u client_loads=%u client_load_failures=%u secondary_offset=%zu\n",
        ok ? "pass" : "fail", haveStatus ? "true" : "false", GetCurrentProcessId(), runId,
        pre.header.processCreation, pre.header.qpcFrequency, pre.headerReady, pre.header.validity, pre.header.configuredMode,
        pre.owner.phase, pre.owner.reason, pre.revokeReasons, pre.lossReasons, pre.owner.requestSequence,
        pre.owner.witnessSequence, pre.owner.normalAttempts, pre.owner.fullSelected, pre.owner.selectedTrue,
        g_builderCalls, g_fullBuilds, g_falseBuilds, g_producerConsumed, FixtureReportCallbackErrors, g_holderErrors, FixtureReportTimingClockErrors,
        g_builderInnerClockErrors, active.pumpClockErrors,
        initialized ? "true" : "false", active.factory, active.factoryAlias, active.init, active.pump,
        active.clientLoads, active.clientLoadFailures, static_cast<std::size_t>(secondaryOffset));
    std::fflush(stdout);
    SetLastError(0x4321);
    reinterpret_cast<api::ShutdownFn>(__imp_SteamGameServer_Shutdown)();
    const bool shutdownError = GetLastError() == 0x5678;
    const auto after = snapshot();
    ok = shutdownError && after.shutdown == 1 && after.badArguments == 0 &&
        after.clientUnloads == after.clientLoads && ok;
    TearDown();
    Sleep(1200); // Only the disposable host waits for its own bounded writer.
    reporting::StatusWire post{};
    const bool havePost = ReadStatus(&post);
    std::printf("report_shutdown=%s status_available=%s phase=%llu stopping=%llu shutdown_calls=%u client_unloads=%u "
        "records_written=%llu last_flushed_sequence=%llu\n", ok ? "pass" : "fail", havePost ? "true" : "false",
        post.owner.phase, post.stopping, after.shutdown, after.clientUnloads, post.recordsWritten, post.lastFlushedSequence);
    std::fflush(stdout);
    return ok;
}
