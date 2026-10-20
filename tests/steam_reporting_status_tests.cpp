#include "companion/steam_reporting_status.h"
#include "shared/steam_reporting_status_v3.h"
#include "companion/steam_reporting_status_v3.h"
#include "shared/steam_reporting_snapshot_v3.h"
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
void V3PublicationAndPauseGates() {
    StatusWireV3 wire{};
    RS2_CHECK(InitializeStatusV3(wire, Header(), Payload(1)));
    RS2_CHECK(wire.header.schema == 3 && wire.header.bytes == 3896 && wire.header.artifactVersion == 0x00060200);
    RS2_CHECK(!InitializeStatusV3(wire, Header(), Payload(2)));
    auto owner = Payload(2);
    owner.reportSequence = 10;
    OwnerTransport transport{};
    transport.state = static_cast<std::uint64_t>(TransportState::Running);
    transport.startupSubmitted = 1;
    transport.generatedSequence = 10; transport.submittedSequence = 8; transport.reserved = UINT64_MAX;
    RS2_CHECK(PublishOwnerV3(wire, owner, transport));
    RS2_CHECK(ReadStatusWord(wire.ownerTransport.reserved) == 0);
    WorkerTransport worker{};
    worker.startupObserved = 1; worker.preparedSequence = 12; worker.observedSequence = 8;
    worker.pauseReason = static_cast<std::uint64_t>(TransportReason::ReaderBehind);
    RS2_CHECK(PublishWorkerV3(wire, worker));
    RS2_CHECK(ReadStatusWord(wire.worker.preparedSequence) == 10); // Physical work can lead owner publication.
    RS2_CHECK(ReadStatusWord(wire.workerPauseReason) == worker.pauseReason && !StatusRevoked(wire));
    worker.pauseReason = 0;
    StoreStatusWord(wire.ownerSequence, 5);
    RS2_CHECK(!PublishWorkerV3(wire, worker));
    RS2_CHECK(ReadStatusWord(wire.workerPauseReason) != 0 && !StatusRevoked(wire));
    StoreStatusWord(wire.ownerSequence, 4);
    RS2_CHECK(PublishWorkerV3(wire, worker));
    RS2_CHECK(ReadStatusWord(wire.workerPauseReason) == 0 && !(ReadStatusWord(wire.workerSequence) & 1));
    ConsoleDiagnostics console{}; console.attempts = 1; console.workerState = 2;
    RS2_CHECK(PublishConsoleV3(wire, console));
    RS2_CHECK(!(ReadStatusWord(wire.consoleSequence) & 1)); // Never odd across the future stdout call.
    StoreStatusWord(wire.consoleSequence, 5);
    RS2_CHECK(!PublishConsoleV3(wire, console) && !StatusRevoked(wire));
    StopStatus(wire, 100); StopStatus(wire, 200);
    RS2_CHECK(StatusRevoked(wire) && ReadStatusWord(wire.stoppedQpc) == 100);
    OwnerSnapshotV3 copy{};
    RS2_CHECK(ReadOwnerV3(wire, &copy) && copy.transport.submittedSequence == 8);
    RS2_CHECK(PublishWorkerV3(wire, worker)); // Accepted receipts may finish after stop.
    RS2_CHECK(!ReadStatusWord(wire.lossReasons));

    StatusWireV3 invalid{};
    RS2_CHECK(InitializeStatusV3(invalid, Header(), Payload(0)));
    worker.preparedSequence = worker.observedSequence = 1;
    RS2_CHECK(!PublishWorkerV3(invalid, worker)); // Cannot acknowledge an unsubmitted frame.
    RS2_CHECK(ReadStatusWord(invalid.lossReasons) == (1ULL << static_cast<unsigned>(Reason::RecordLoss)));
}
void V3ImmutableIdentityAndFaultDomains() {
    StatusWireV3 wire{};
    RS2_CHECK(InitializeStatusV3(wire, Header(), Payload(0)));
    LogIdentity identity{};
    constexpr char16_t path[] = u"E:\\logs\\Launch.log";
    std::memcpy(identity.path, path, sizeof(path));
    identity.pathChars = sizeof(path) / sizeof(path[0]) - 1;
    identity.transportKind = 1; identity.utcFiletime = 1;
    identity.calibrationQpcBefore = 10; identity.calibrationQpcAfter = 11;
    identity.fileId[15] = 0xa7; identity.initialEOF = 123;
    RS2_CHECK(PublishLogIdentityV3(wire, identity));
    RS2_CHECK(wire.log.fileId[15] == 0xa7 && wire.log.initialEOF == 123 && ReadStatusWord(wire.logIdentityReady) == 1);
    identity.initialEOF = 999;
    RS2_CHECK(!PublishLogIdentityV3(wire, identity) && wire.log.initialEOF == 123);
    for (unsigned reason = 0; reason <= static_cast<unsigned>(TransportReason::SameFileRequalification); ++reason)
        RS2_CHECK(!LatchTransportFault(wire, static_cast<TransportReason>(reason)) && !StatusRevoked(wire));
    RS2_CHECK(LatchTransportFault(wire, TransportReason::ReceiptGap));
    RS2_CHECK(StatusRevoked(wire));
    RS2_CHECK(LatchTransportFault(wire, TransportReason::NativeLogException));
    RS2_CHECK(ReadStatusWord(wire.fatalTransportReason) == static_cast<std::uint64_t>(TransportReason::ReceiptGap));
    RS2_CHECK(ReadStatusWord(wire.revokeReasons) & (1ULL << static_cast<unsigned>(Reason::NativeUnwind)));
    StatusWireV3 fatalWindow{};
    StoreStatusWord(fatalWindow.fatalTransportReason, static_cast<std::uint64_t>(TransportReason::ProfileUnsafe));
    RS2_CHECK(StatusRevoked(fatalWindow)); // Independent gate before its matching reason-mask store.
}
void V3ConcurrentOwnerPair() {
    StatusWireV3 wire{};
    RS2_CHECK(InitializeStatusV3(wire, Header(), Payload(0)));
    std::atomic<bool> done{false}, good{true};
    std::thread producer([&] {
        for (std::uint64_t generation = 1; generation <= 2000; ++generation) {
            auto owner = Payload(generation); owner.reportSequence = generation;
            OwnerTransport transport{};
            transport.generatedSequence = transport.submittedSequence = generation;
            transport.nativeSubmitCalls = 2 * generation;
            if (!PublishOwnerV3(wire, owner, transport)) good.store(false);
        }
        done.store(true);
    });
    bool coherent = true;
    do {
        OwnerSnapshotV3 copy{};
        if (ReadOwnerV3(wire, &copy)) {
            const auto generation = copy.owner.reportSequence;
            coherent = coherent && copy.owner.lastOwnerQpc == generation &&
                copy.transport.generatedSequence == generation && copy.transport.submittedSequence == generation &&
                copy.transport.nativeSubmitCalls == 2 * generation;
        }
    } while (!done.load());
    producer.join();
    RS2_CHECK(coherent && good.load());
}
struct SnapshotFixtureV3 {
    StatusWireV3 wire{};
    std::size_t failAt = SIZE_MAX;
    unsigned workerSequenceReads{};
    bool closeWorkerGate{}, clearWorkerGate{}, moveOwner{}, alwaysMoveOwner{}, stopDuringConsole{};
    bool changedOwner{};
    SnapshotFixtureV3() {
        auto header = Header(); header.hostDigest[0] = 2; header.qpcFrequency = 1000;
        auto owner = Payload(1);
        owner.ownerThreadId = 7; owner.lastOwnerQpc = owner.readyQpc = 1000; owner.builderBound = 1;
        RS2_CHECK(InitializeStatusV3(wire, header, owner));
        OwnerTransport transport{};
        transport.state = static_cast<std::uint64_t>(TransportState::Running);
        transport.startupSubmitted = 1;
        RS2_CHECK(PublishOwnerV3(wire, owner, transport));
        WorkerTransport worker{}; worker.startupObserved = 1;
        RS2_CHECK(PublishWorkerV3(wire, worker));
        LogIdentity log{};
        constexpr char16_t path[] = u"E:\\logs\\Launch.log";
        std::memcpy(log.path, path, sizeof(path));
        log.pathChars = sizeof(path) / sizeof(path[0]) - 1;
        log.transportKind = 1; log.utcFiletime = 1; log.calibrationQpcBefore = log.calibrationQpcAfter = 100;
        RS2_CHECK(PublishLogIdentityV3(wire, log));
    }
    static bool Read(void* context, std::size_t offset, void* out, std::size_t size) noexcept {
        auto& f = *static_cast<SnapshotFixtureV3*>(context);
        if (offset > sizeof(f.wire) || size > sizeof(f.wire) - offset) return false;
        if (offset == offsetof(StatusWireV3, console) && f.stopDuringConsole) StopStatus(f.wire, 1010);
        if (offset == f.failAt) return false;
        if (offset == offsetof(StatusWireV3, workerSequence) && ++f.workerSequenceReads == 2) {
            if (f.closeWorkerGate) StoreStatusWord(f.wire.workerPauseReason, static_cast<std::uint64_t>(TransportReason::ReaderBehind));
            if (f.clearWorkerGate) StoreStatusWord(f.wire.workerPauseReason, 0);
        }
        if (offset == offsetof(StatusWireV3, worker) && (f.alwaysMoveOwner || (f.moveOwner && !f.changedOwner))) {
            f.changedOwner = true;
            auto owner = f.wire.owner;
            ++owner.lastOwnerQpc;
            PublishOwnerV3(f.wire, owner, f.wire.ownerTransport);
        }
        std::memcpy(out, reinterpret_cast<const unsigned char*>(&f.wire) + offset, size);
        return true;
    }
    SnapshotResultV3 Take(StatusSnapshotV3& out) {
        return ReadStatusSnapshotV3({this, Read}, &out);
    }
};
void V3CoherentReader() {
    SnapshotFixtureV3 f;
    StatusSnapshotV3 snapshot{};
    RS2_CHECK(f.Take(snapshot) == SnapshotResultV3::Coherent);
    RS2_CHECK(SnapshotCurrentlyReadyV3(snapshot, 1010, 1000));
    RS2_CHECK(!SnapshotCurrentlyReadyV3(snapshot, 3001, 1000));
    StoreStatusWord(f.wire.consoleSequence, 3);
    RS2_CHECK(f.Take(snapshot) == SnapshotResultV3::Coherent && !snapshot.consoleDiagnosticsAvailable);
    RS2_CHECK(SnapshotCurrentlyReadyV3(snapshot, 1010, 1000)); // Console cannot revoke core readiness.
    StoreStatusWord(f.wire.consoleSequence, 2);
    f.failAt = offsetof(StatusWireV3, console);
    RS2_CHECK(f.Take(snapshot) == SnapshotResultV3::Coherent && !snapshot.consoleDiagnosticsAvailable);
    RS2_CHECK(SnapshotCurrentlyReadyV3(snapshot, 1010, 1000));
    f.stopDuringConsole = true;
    RS2_CHECK(f.Take(snapshot) == SnapshotResultV3::Coherent && snapshot.wire.stopping);
    RS2_CHECK(!SnapshotCurrentlyReadyV3(snapshot, 1010, 1000));
    {
        SnapshotFixtureV3 moving; moving.moveOwner = true;
        RS2_CHECK(moving.Take(snapshot) == SnapshotResultV3::Coherent && snapshot.attempts == 2);
        RS2_CHECK(SnapshotCurrentlyReadyV3(snapshot, 1010, 1000));
    }
    {
        SnapshotFixtureV3 moving; moving.alwaysMoveOwner = true;
        RS2_CHECK(moving.Take(snapshot) == SnapshotResultV3::Busy && snapshot.attempts == 3);
        RS2_CHECK(!SnapshotCurrentlyReadyV3(snapshot, 1010, 1000));
    }
    {
        SnapshotFixtureV3 invalid; invalid.wire.header.schema = 2;
        RS2_CHECK(invalid.Take(snapshot) == SnapshotResultV3::Invalid);
        RS2_CHECK(!SnapshotCurrentlyReadyV3(snapshot, 1010, 1000));
    }
    {
        SnapshotFixtureV3 partial;
        RevokeStatus(partial.wire, Reason::ForeignThread);
        partial.failAt = offsetof(StatusWireV3, lossReasons);
        RS2_CHECK(partial.Take(snapshot) == SnapshotResultV3::ReadFailure);
        RS2_CHECK(snapshot.wire.revokeReasons == (1ULL << static_cast<unsigned>(Reason::ForeignThread)));
    }
}
void V3ClearableGateRacesStayCoherent() {
    StatusSnapshotV3 snapshot{};
    SnapshotFixtureV3 closing; closing.closeWorkerGate = true;
    RS2_CHECK(closing.Take(snapshot) == SnapshotResultV3::Coherent && snapshot.workerPauseChanged);
    RS2_CHECK(snapshot.coreAvailable && !SnapshotCurrentlyReadyV3(snapshot, 1010, 1000));
    RS2_CHECK(!snapshot.wire.lossReasons && !snapshot.wire.revokeReasons);
    SnapshotFixtureV3 clearing; clearing.clearWorkerGate = true;
    StoreStatusWord(clearing.wire.workerPauseReason, static_cast<std::uint64_t>(TransportReason::ReaderBehind));
    RS2_CHECK(clearing.Take(snapshot) == SnapshotResultV3::Coherent && snapshot.workerPauseChanged);
    RS2_CHECK(snapshot.wire.workerPauseReason != 0 && !SnapshotCurrentlyReadyV3(snapshot, 1010, 1000));
    RS2_CHECK(clearing.Take(snapshot) == SnapshotResultV3::Coherent && !snapshot.workerPauseChanged);
    RS2_CHECK(SnapshotCurrentlyReadyV3(snapshot, 1010, 1000));
    clearing.wire.ownerTransport.state = static_cast<std::uint64_t>(TransportState::Paused);
    RS2_CHECK(clearing.Take(snapshot) == SnapshotResultV3::Coherent);
    RS2_CHECK(!SnapshotCurrentlyReadyV3(snapshot, 1010, 1000));
}
} // namespace
void ReportingStatusTests() {
    IdentityAndFaults(); ConcurrentSnapshot(); DurationAndOverflow();
    V3PublicationAndPauseGates(); V3ImmutableIdentityAndFaultDomains(); V3ConcurrentOwnerPair();
    V3CoherentReader(); V3ClearableGateRacesStayCoherent();
}
