#include "companion/steam_reporting_status.h"
#include "test_framework.h"
#include <Windows.h>
#include <atomic>
#include <cstring>
#include <limits>
#include <thread>

using namespace rs2fix::reporting;
namespace {
StatusHeader Header() {
    StatusHeader header{};
    header.pid = GetCurrentProcessId(); header.processCreation = 1234;
    header.qpcFrequency = 10000000; header.runId[0] = 77;
    header.configuredMode = static_cast<std::uint32_t>(Mode::Observe);
    header.validity = CompleteHeaderIdentity;
    return header;
}
StatusPayload Payload(std::uint64_t sequence) {
    StatusPayload payload{};
    payload.phase = static_cast<std::uint64_t>(ReportPhase::Observing);
    payload.sourceEpoch = sequence; payload.bindingEpoch = sequence;
    payload.lastOwnerQpc = sequence; payload.normalAttempts = sequence;
    payload.durations[0].calls = sequence;
    return payload;
}
std::uint64_t GenerationWord(std::uint64_t generation, std::size_t index) {
    return index==0 ? generation :
        (generation*0x9E3779B97F4A7C15ULL) ^ (static_cast<std::uint64_t>(index)*0xD6E8FEB86659FD93ULL);
}
StatusPayload GenerationPayload(std::uint64_t generation) {
    // Exercise every word, including high bits, reserved fields and every
    // duration bucket. This test payload is representation data, not game state.
    StatusPayload payload{};
    for (std::size_t offset=0;offset<sizeof(payload);offset+=sizeof(std::uint64_t)) {
        const auto word=GenerationWord(generation,offset/sizeof(std::uint64_t));
        std::memcpy(reinterpret_cast<unsigned char*>(&payload)+offset,&word,sizeof(word));
    }
    return payload;
}
bool MatchesGeneration(const StatusPayload& payload,std::uint64_t generation) {
    for (std::size_t offset=0;offset<sizeof(payload);offset+=sizeof(std::uint64_t)) {
        std::uint64_t word{};
        std::memcpy(&word,reinterpret_cast<const unsigned char*>(&payload)+offset,sizeof(word));
        if (word!=GenerationWord(generation,offset/sizeof(std::uint64_t))) return false;
    }
    return true;
}
void IdentityAndFaults() {
    StatusWire wire{};
    StatusHeader header{}; StatusPayload payload{};
    RS2_CHECK(!ReadLocalStatus(wire, &header, &payload));
    RS2_CHECK(InitializeStatus(wire, Header(), Payload(1)));
    RS2_CHECK(!InitializeStatus(wire, Header(), Payload(8))); // Never replace a run in place.
    RS2_CHECK(ReadLocalStatus(wire, &header, &payload));
    RS2_CHECK(header.runId[0] == 77 && header.bytes == sizeof(StatusWire) && payload.sourceEpoch == 1);
    RS2_CHECK(PublishStatus(wire, Payload(2)));
    RS2_CHECK(ReadLocalStatus(wire, &header, &payload) && payload.sourceEpoch == 2);
    LoseStatus(wire, Reason::WriterFailed);
    RS2_CHECK(StatusRevoked(wire) && ReadStatusWord(wire.lossReasons));
    RS2_CHECK(PublishStatus(wire, Payload(3))); // Healthy-looking payload cannot clear failure.
    RS2_CHECK(!ReadLocalStatus(wire, &header, &payload) && header.magic == 0);
    RS2_CHECK(ReadStatusWord(wire.revokeReasons));

    StatusWire stopped{};
    RS2_CHECK(InitializeStatus(stopped, Header(), Payload(1)));
    StopStatus(stopped, 123); StopStatus(stopped, 456);
    RS2_CHECK(StatusRevoked(stopped) && ReadStatusWord(stopped.stoppedQpc) == 123);
    RS2_CHECK(ReadStatusWord(stopped.lossReasons) == 0 && ReadStatusWord(stopped.revokeReasons) == 0);
    RS2_CHECK(!ReadLocalStatus(stopped, &header, &payload));

    StatusWire odd{};
    RS2_CHECK(InitializeStatus(odd, Header(), Payload(1)));
    StoreStatusWord(odd.ownerSequence, 3);
    RS2_CHECK(!ReadLocalStatus(odd, &header, &payload));
    RS2_CHECK(!PublishStatus(odd, Payload(2)) && StatusRevoked(odd));
    StatusWire wrap{};
    RS2_CHECK(InitializeStatus(wrap, Header(), Payload(1)));
    StoreStatusWord(wrap.ownerSequence, UINT64_MAX - 1);
    RS2_CHECK(!PublishStatus(wrap, Payload(2)) && StatusRevoked(wrap));

    StatusWire rejected{};
    auto incomplete = Header(); incomplete.validity = ProcessIdentityValid;
    for (auto& byte : incomplete.runId) byte = 0;
    auto failed = Payload(0); failed.phase = static_cast<std::uint64_t>(ReportPhase::Rejected);
    failed.reason = static_cast<std::uint64_t>(Reason::IdentityIncomplete);
    RS2_CHECK(InitializeStatus(rejected, incomplete, failed));
    RS2_CHECK(ReadLocalStatus(rejected, &header, &payload));
    RS2_CHECK(header.validity != CompleteHeaderIdentity && payload.phase == failed.phase);
}
void ConcurrentSnapshot() {
    StatusWire wire{};
    RS2_CHECK(InitializeStatus(wire, Header(), GenerationPayload(0)));
    std::atomic<bool> finished{false}, publishOk{true};
    std::thread producer([&] {
        for (std::uint64_t i = 1; i <= 2000; ++i)
            if (!PublishStatus(wire, GenerationPayload(i))) publishOk.store(false);
        finished.store(true);
    });
    bool coherent = true;
    do {
        StatusHeader header{}; StatusPayload payload{};
        if (ReadLocalStatus(wire, &header, &payload)) {
            // Word zero carries the generation; all other words must belong to
            // it. A reader may reject contention but must not accept a mixture.
            std::uint64_t generation{};
            std::memcpy(&generation,&payload,sizeof(generation));
            coherent = coherent && generation<=2000 && MatchesGeneration(payload,generation);
        }
    } while (!finished.load());
    producer.join();
    RS2_CHECK(coherent && publishOk.load());
    StatusHeader header{}; StatusPayload payload{};
    RS2_CHECK(ReadLocalStatus(wire, &header, &payload) && MatchesGeneration(payload,2000));
}
void DurationAndOverflow() {
    DurationCounters counters{};
    RS2_CHECK(AccountDuration(counters, 5000, 1000000));
    RS2_CHECK(counters.calls == 1 && counters.buckets[3] == 1 && counters.overFiveMilliseconds == 0);
    RS2_CHECK(AccountDuration(counters, 5001, 1000000));
    RS2_CHECK(counters.maximumTicks == 5001 && counters.overFiveMilliseconds == 1 && counters.buckets[4] == 1);
    const auto before = counters;
    RS2_CHECK(!AccountDuration(counters, UINT64_MAX, 1000000));
    RS2_CHECK(counters.calls == before.calls && counters.elapsedTicks == before.elapsedTicks);
    RS2_CHECK(!AccountDuration(counters, 1, 0));
    RS2_CHECK(!AccountDuration(counters, 1, UINT64_MAX));
    DurationCounters coarse{};
    RS2_CHECK(AccountDuration(coarse, 5, 1000));
    RS2_CHECK(AccountDuration(coarse, 6, 1000));
    RS2_CHECK(coarse.overFiveMilliseconds == 1 && coarse.maximumTicks == 6);
    std::uint64_t value = UINT64_MAX;
    RS2_CHECK(!IncrementCounter(value) && value == UINT64_MAX);
}
} // namespace
void ReportingStatusTests() { IdentityAndFaults(); ConcurrentSnapshot(); DurationAndOverflow(); }
