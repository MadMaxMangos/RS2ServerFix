#include "companion/leech_recovery_wire.h"
#include "companion/steam_reporting_status_v3.h"
#include "companion/steam_reporting_records_v3.h"
#include "test_framework.h"
#include <Windows.h>
#include <atomic>
#include <cstring>
#include <initializer_list>
#include <thread>

namespace rs2fix::testcases {
namespace {
using namespace reporting;
StatusHeader Identity() {
    StatusHeader h{};
    h.magic = kStatusMagic; h.schema = kStatusSchemaV3; h.bytes = sizeof(StatusWireV3);
    h.artifactVersion = kReportingArtifactVersionV3; h.configuredMode = 3; h.validity = CompleteHeaderIdentity;
    h.pid = GetCurrentProcessId(); h.processCreation = 123; h.qpcFrequency = 10000000;
    h.runId[0] = 5; h.hostDigest[0] = 7;
    return h;
}
ReportRecoveryPayload Evidence(std::uint64_t generation = 1) {
    ReportRecoveryPayload p{};
    p.phase = static_cast<std::uint64_t>(RecoveryPhase::Failed);
    p.event = static_cast<std::uint64_t>(RecoveryEvent::Final);
    p.reason = static_cast<std::uint64_t>(RecoveryReason::CallbackInvalid);
    p.outcome = static_cast<std::uint64_t>(RecoveryOutcome::Inconclusive);
    p.flags = RecoveryPermissionEnabled | RecoveryCancellationCompleted | RecoveryRestartRequired | RecoveryTerminal |
        RecoveryAttributionValid | RecoveryCreateGuardInstalled | RecoveryCreateCallbackObserved | RecoveryCallbackOwnTimingValid;
    p.operationSequence = 1; p.transitionSequence = generation; p.qpc = 100 + generation;
    p.sourceEpoch = 2; p.sdkEpoch = 3; p.ownerThreadId = GetCurrentThreadId();
    p.resourcePhase = static_cast<std::uint64_t>(ResourcePhase::LocalReleased);
    p.nativeStage = static_cast<std::uint64_t>(NativeStage::CreateGuard);
    p.requestId = p.callbackId = 34; p.callbackResult = static_cast<std::uint64_t>(CallbackResult::True);
    p.oldSdkFingerprint = UINT64_MAX; p.newSdkFingerprint = 0x8000000000000000ULL;
    p.oldCacheFingerprint = UINT64_MAX - 1; p.newCacheFingerprint = generation;
    p.finishDeadlineQpc = 300; p.overallDeadlineQpc = 500; p.recordSequence = generation;
    p.callbackOwnTicks = generation;
    return p;
}
void PayloadAndPublication() {
    const auto identity = Identity();
    RecoveryStatusWireV1 wire{};
    RecoveryStatusSnapshot snapshot{};
    RS2_CHECK(ReadRecoveryStatusSnapshot(wire, identity, &snapshot) == RecoverySnapshotResult::Unavailable);
    RS2_CHECK(snapshot.wire.pid == 0);
    auto incomplete = identity; incomplete.hostDigest[0] = 0;
    RS2_CHECK(!InitializeRecoveryStatus(wire, incomplete) && wire.headerReady == 0);
    RS2_CHECK(InitializeRecoveryStatus(wire, identity));
    RS2_CHECK(!InitializeRecoveryStatus(wire, identity));
    RS2_CHECK(PublishRecoveryStatus(wire, Evidence()));
    RS2_CHECK(ReadRecoveryStatusSnapshot(wire, identity, &snapshot) == RecoverySnapshotResult::Coherent);
    RS2_CHECK(snapshot.wire.ownerSequence == 4 && snapshot.wire.payload.callbackOwnTicks == 1);
    RS2_CHECK(!(snapshot.wire.payload.flags & RecoveryCreateForwardEntered)); // Refusal still has observed own timing.
    auto p = Evidence();
    p.callbackOwnTicks = 0;
    RS2_CHECK(PublishRecoveryStatus(wire, p)); // A measured zero is distinct from unavailable zero.
    p.flags &= ~RecoveryCallbackOwnTimingValid;
    RS2_CHECK(PublishRecoveryStatus(wire, p));
    p.callbackOwnTicks = 1;
    const auto before = wire.ownerSequence;
    RS2_CHECK(!PublishRecoveryStatus(wire, p) && wire.ownerSequence == before);
    p = Evidence(); p.flags &= ~RecoveryCreateCallbackObserved;
    RS2_CHECK(!PublishRecoveryStatus(wire, p));
    p = Evidence(); p.flags |= 1ULL << 15;
    RS2_CHECK(!PublishRecoveryStatus(wire, p));
    for (const auto field : {&ReportRecoveryPayload::phase, &ReportRecoveryPayload::event, &ReportRecoveryPayload::reason,
        &ReportRecoveryPayload::outcome, &ReportRecoveryPayload::resourcePhase, &ReportRecoveryPayload::nativeStage,
        &ReportRecoveryPayload::callbackResult}) {
        p = Evidence(); p.*field = UINT64_MAX;
        RS2_CHECK(!PublishRecoveryStatus(wire, p) && wire.ownerSequence == before);
    }
    p = Evidence(); p.requestId = UINT64_MAX;
    RS2_CHECK(!PublishRecoveryStatus(wire, p));
    p = Evidence(); p.qpc = UINT64_MAX;
    RS2_CHECK(!PublishRecoveryStatus(wire, p));
    StoreStatusWord(wire.ownerSequence, UINT64_MAX - 1);
    RS2_CHECK(!PublishRecoveryStatus(wire, Evidence()) && wire.ownerSequence == UINT64_MAX - 1);
    StoreStatusWord(wire.ownerSequence, 7);
    RS2_CHECK(ReadRecoveryStatusSnapshot(wire, identity, &snapshot) == RecoverySnapshotResult::Busy);
    RS2_CHECK(snapshot.attempts == 3 && snapshot.wire.pid == 0);
    RS2_CHECK(std::strcmp(RecoverySnapshotResultName(RecoverySnapshotResult::Busy), "Busy") == 0);
    StoreStatusWord(wire.ownerSequence, before);
    auto other = identity; other.runId[0]++;
    RS2_CHECK(ReadRecoveryStatusSnapshot(wire, other, &snapshot) == RecoverySnapshotResult::Invalid && !snapshot.wire.pid);
}

struct RemoteRecovery {
    RecoveryStatusWireV1 wire{};
    bool fail{}, move{}, regress{}, alterIdentity{};
    unsigned reads{};
    RemoteRecovery() { RS2_CHECK(InitializeRecoveryStatus(wire, Identity())); RS2_CHECK(PublishRecoveryStatus(wire, Evidence())); }
    static bool Read(void* context, std::size_t offset, void* output, std::size_t bytes) noexcept {
        auto& f = *static_cast<RemoteRecovery*>(context);
        if (f.fail || offset > sizeof(f.wire) || bytes > sizeof(f.wire) - offset) return false;
        if (offset == offsetof(RecoveryStatusWireV1, payload)) {
            if (f.move) StoreStatusWord(f.wire.ownerSequence, f.wire.ownerSequence + 2);
            if (f.regress) StoreStatusWord(f.wire.ownerSequence, f.wire.ownerSequence - 2);
        }
        if (offset == 0 && f.alterIdentity && ++f.reads == 2) ++f.wire.pid;
        std::memcpy(output, reinterpret_cast<const unsigned char*>(&f.wire) + offset, bytes);
        return true;
    }
    RecoverySnapshotResult Take(RecoveryStatusSnapshot& snapshot) { return ReadRecoveryStatusSnapshot(RecoveryReadOps{this, Read}, Identity(), &snapshot); }
};
void BoundedRemoteReader() {
    RecoveryStatusSnapshot snapshot{};
    RemoteRecovery f;
    RS2_CHECK(f.Take(snapshot) == RecoverySnapshotResult::Coherent);
    f.fail = true;
    RS2_CHECK(f.Take(snapshot) == RecoverySnapshotResult::ReadFailure && snapshot.wire.pid == 0);
    f.fail = false; f.move = true;
    RS2_CHECK(f.Take(snapshot) == RecoverySnapshotResult::Busy && snapshot.attempts == 3 && !snapshot.wire.pid);
    RemoteRecovery regressing; regressing.regress = true;
    RS2_CHECK(regressing.Take(snapshot) == RecoverySnapshotResult::Invalid && !snapshot.wire.pid);
    RemoteRecovery changed; changed.alterIdentity = true;
    RS2_CHECK(changed.Take(snapshot) == RecoverySnapshotResult::Invalid && !snapshot.wire.pid);
    RemoteRecovery malformed; malformed.wire.payload.callbackOwnTicks = 10;
    malformed.wire.payload.flags &= ~RecoveryCallbackOwnTimingValid;
    RS2_CHECK(malformed.Take(snapshot) == RecoverySnapshotResult::Invalid && !snapshot.wire.pid);
}
struct ReportingIdentityFixture {
    StatusWireV3 wire{};
    bool failHeader{}, forbiddenRead{}, changeHeader{};
    unsigned headerReads{};
    ReportingIdentityFixture() {
        RS2_CHECK(InitializeStatusV3(wire, Identity(), {}));
        wire.owner.phase = UINT64_MAX; wire.ownerTransport.state = UINT64_MAX;
        wire.worker.preparedSequence = UINT64_MAX;
        StoreStatusWord(wire.ownerSequence, 3); StoreStatusWord(wire.workerSequence, 5);
        RevokeStatus(wire, Reason::RecordLoss);
    }
    static bool Read(void* context, std::size_t offset, void* output, std::size_t bytes) noexcept {
        auto& f = *static_cast<ReportingIdentityFixture*>(context);
        const bool allowed = offset == 0 || offset == offsetof(StatusWireV3, headerReady) ||
            offset == offsetof(StatusWireV3, reserved) ||
            offset == offsetof(StatusWireV3, ownerTransport) + offsetof(OwnerTransport, reserved) ||
            offset == offsetof(StatusWireV3, worker) + offsetof(WorkerTransport, reserved);
        if (!allowed) { f.forbiddenRead = true; return false; }
        if (offset == 0 && f.failHeader) return false;
        if (offset == 0 && f.changeHeader && ++f.headerReads == 2) ++f.wire.header.qpcFrequency;
        std::memcpy(output, reinterpret_cast<const unsigned char*>(&f.wire) + offset, bytes);
        return true;
    }
    SnapshotResultV3 Take(StatusHeader& h) { return ReadReportingIdentityV3({this, Read}, &h); }
};
void IdentitySurvivesCoreFault() {
    StatusHeader header{};
    ReportingIdentityFixture f;
    RS2_CHECK(f.Take(header) == SnapshotResultV3::Coherent && header.pid == Identity().pid && !f.forbiddenRead);
    f.failHeader = true;
    RS2_CHECK(f.Take(header) == SnapshotResultV3::ReadFailure && !header.pid);
    ReportingIdentityFixture changed; changed.changeHeader = true;
    RS2_CHECK(changed.Take(header) == SnapshotResultV3::Invalid && !header.pid);
    ReportingIdentityFixture reserved; reserved.wire.reserved[4] = 1;
    RS2_CHECK(reserved.Take(header) == SnapshotResultV3::Invalid && !header.pid);
    ReportingIdentityFixture oldArtifact; oldArtifact.wire.header.artifactVersion = 0x00050000;
    RS2_CHECK(oldArtifact.Take(header) == SnapshotResultV3::Invalid && !header.pid);
    ReportingIdentityFixture absent; StoreStatusWord(absent.wire.headerReady, 0);
    RS2_CHECK(absent.Take(header) == SnapshotResultV3::Unpublished && !header.pid);
}
void ConcurrentPublication() {
    RecoveryStatusWireV1 wire{};
    RS2_CHECK(InitializeRecoveryStatus(wire, Identity()));
    RS2_CHECK(PublishRecoveryStatus(wire, Evidence(1)));
    std::atomic<bool> done{false}, good{true};
    std::thread owner([&] {
        for (std::uint64_t generation = 2; generation <= 2000; ++generation)
            if (!PublishRecoveryStatus(wire, Evidence(generation))) good.store(false);
        done.store(true);
    });
    bool coherent = true;
    do {
        RecoveryStatusSnapshot snapshot{};
        if (ReadRecoveryStatusSnapshot(wire, Identity(), &snapshot) == RecoverySnapshotResult::Coherent) {
            const auto& p = snapshot.wire.payload;
            coherent = coherent && p.transitionSequence == p.callbackOwnTicks && p.recordSequence == p.callbackOwnTicks &&
                p.newCacheFingerprint == p.callbackOwnTicks && p.qpc == 100 + p.callbackOwnTicks;
        }
    } while (!done.load());
    owner.join();
    RS2_CHECK(coherent && good.load());
}
void RecoveryRingEvidence() {
    StatusWireV3 status{}; ReportRingV3 ring{};
    RS2_CHECK(InitializeReportRing(ring, status, GetCurrentThreadId()));
    ReportRecordV3 input{}; input.header.kind = static_cast<std::uint32_t>(RecordKindV3::Recovery);
    input.header.qpc = 200; input.payload.recovery = Evidence(); input.payload.recovery.recordSequence = 0;
    StoreStatusWord(status.workerPauseReason, static_cast<std::uint64_t>(TransportReason::CreditPressure));
    std::uint64_t accepted{}; ReportRecordV3 output{};
    RS2_CHECK(EnqueueReport(ring, input, &accepted) == ReportWriteResult::Accepted && accepted == 1);
    RS2_CHECK(DequeueReport(ring, &output) == ReportReadResult::Record);
    RS2_CHECK(std::memcmp(&input.payload.recovery, &output.payload.recovery, sizeof(input.payload.recovery)) == 0);
    RS2_CHECK(output.header.qpc == 200 && output.payload.recovery.qpc == 101 && !StatusRevoked(status));
    for (const auto kind : {0U, 1U, 2U, 3U}) {
        StatusWireV3 invalidStatus{}; ReportRingV3 invalidRing{};
        RS2_CHECK(InitializeReportRing(invalidRing, invalidStatus, GetCurrentThreadId()));
        auto invalid = input;
        if (kind == 0) invalid.header.reason = static_cast<std::uint32_t>(Reason::NativeUnwind);
        if (kind == 1) invalid.header.flags = 1;
        if (kind == 2) invalid.payload.recovery.recordSequence = 1;
        if (kind == 3) invalid.payload.recovery.flags |= 1ULL << 15;
        RS2_CHECK(EnqueueReport(invalidRing, invalid, &accepted) == ReportWriteResult::Lost && !accepted);
        RS2_CHECK(ReadStatusWord(invalidRing.reportWriteSequence) == 0 && StatusRevoked(invalidStatus));
    }
    StatusWire old{}; ReportRing oldRing{};
    RS2_CHECK(InitializeReportRing(oldRing, old, GetCurrentThreadId()));
    ReportRecord legacy{}; legacy.header.kind = static_cast<std::uint32_t>(RecordKindV3::Recovery);
    RS2_CHECK(EnqueueReport(oldRing, legacy, &accepted) == ReportWriteResult::Lost && !accepted);
}
}
void RecoveryWireTests() {
    PayloadAndPublication(); BoundedRemoteReader(); IdentitySurvivesCoreFault(); ConcurrentPublication(); RecoveryRingEvidence();
}
} // namespace rs2fix::testcases
