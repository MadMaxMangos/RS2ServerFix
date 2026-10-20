#include "shared/steam_reporting_snapshot_v3.h"
#include <cstring>

namespace rs2fix::reporting {
namespace {
struct Reader {
    const StatusReadOpsV3& ops;
    mutable bool invalidSequence{};
    bool Bytes(std::size_t at, void* out, std::size_t size) const noexcept {
        return at <= sizeof(StatusWireV3) && size <= sizeof(StatusWireV3) - at && ops.read(ops.context, at, out, size);
    }
    template<class T> bool At(std::size_t offset, T& out) const noexcept { return Bytes(offset, &out, sizeof(out)); }
    bool Gates(StatusSnapshotV3& out, std::uint64_t& pause) const noexcept {
        std::uint64_t value{};
        // Accumulate each successful sticky read immediately, including when a
        // later word/read attempt fails. The worker gate is clearable, not ORed
        // into runtime fault masks and not an excuse to throw away core data.
        if (!At(offsetof(StatusWireV3, revokeReasons), value)) return false;
        out.wire.revokeReasons |= value;
        if (!At(offsetof(StatusWireV3, lossReasons), value)) return false;
        out.wire.lossReasons |= value;
        if (!At(offsetof(StatusWireV3, stopping), value)) return false;
        out.wire.stopping |= value;
        if (!At(offsetof(StatusWireV3, stoppedQpc), value)) return false;
        if (value > out.wire.stoppedQpc) out.wire.stoppedQpc = value;
        if (!At(offsetof(StatusWireV3, fatalTransportReason), value)) return false;
        if (!out.wire.fatalTransportReason) out.wire.fatalTransportReason = value;
        if (!At(offsetof(StatusWireV3, workerPauseReason), pause)) return false;
        return true;
    }
    bool Owner(StatusPayload& owner, OwnerTransport& transport, std::uint64_t& sequence,
        bool& stable) const noexcept {
        stable = false;
        std::uint64_t before{}, after{};
        if (!At(offsetof(StatusWireV3, ownerSequence), before)) return false;
        if (before < 2 || (before & 1)) { sequence = before; return true; }
        if (!At(offsetof(StatusWireV3, owner), owner) || !At(offsetof(StatusWireV3, ownerTransport), transport) ||
            !At(offsetof(StatusWireV3, ownerSequence), after)) return false;
        sequence = after;
        if (after < before) invalidSequence = true;
        stable = before == after && !(after & 1);
        return true;
    }
    bool Worker(WorkerTransport& worker, std::uint64_t& sequence, bool& stable) const noexcept {
        stable = false;
        std::uint64_t before{}, after{};
        if (!At(offsetof(StatusWireV3, workerSequence), before)) return false;
        if (before < 2 || (before & 1)) { sequence = before; return true; }
        if (!At(offsetof(StatusWireV3, worker), worker) || !At(offsetof(StatusWireV3, workerSequence), after)) return false;
        sequence = after;
        if (after < before) invalidSequence = true;
        stable = before == after && !(after & 1);
        return true;
    }
    void Console(StatusSnapshotV3& out) const noexcept {
        std::uint64_t before{}, after{};
        ConsoleDiagnostics console{};
        if (!At(offsetof(StatusWireV3, consoleSequence), before) || before < 2 || (before & 1) ||
            !At(offsetof(StatusWireV3, console), console) || !At(offsetof(StatusWireV3, consoleSequence), after) ||
            before != after || (after & 1) || console.workerState > 3 ||
            console.written > console.attempts || console.failures > console.attempts ||
            console.written > console.attempts - console.failures) return;
        out.wire.console = console;
        out.wire.consoleSequence = after;
        out.consoleDiagnosticsAvailable = true;
    }
};
bool HeaderValid(const StatusHeader& header) noexcept {
    if (header.magic != kStatusMagic || header.schema != kStatusSchemaV3 || header.bytes != sizeof(StatusWireV3) ||
        header.artifactVersion != kReportingArtifactVersionV3 || header.configuredMode > 3 ||
        (header.validity & ~CompleteHeaderIdentity)) return false;
    for (auto word : header.reserved) if (word) return false;
    return true;
}
bool IdentityValid(const LogIdentity& log) noexcept {
    if (!log.pathChars || log.pathChars > 1023 || log.path[log.pathChars] || log.prefixMode > 1 ||
        log.transportKind != 1 || log.durability || log.initialAtLineBoundary > 1 ||
        !log.utcFiletime || !log.calibrationQpcBefore || log.calibrationQpcAfter < log.calibrationQpcBefore)
        return false;
    for (std::size_t i = 0; i < 1024; ++i)
        if (i < log.pathChars ? !log.path[i] : log.path[i] != 0) return false;
    return true;
}
bool CoreValid(const StatusWireV3& wire) noexcept {
    const auto& owner = wire.owner;
    const auto& t = wire.ownerTransport;
    const auto& w = wire.worker;
    if (owner.phase > static_cast<std::uint64_t>(ReportPhaseV3::Paused) || owner.reason >= kRuntimeReasonCountV3 ||
        owner.pending > 1 || owner.fresh > 1 || owner.builderBound > 1 || owner.ownerThreadId > UINT32_MAX ||
        t.state > static_cast<std::uint64_t>(TransportState::Stopping) ||
        t.reason >= static_cast<std::uint64_t>(TransportReason::Count) ||
        t.startupSubmitted > 1 || t.actualRepairAdmitted > 1 || t.reserved ||
        t.generatedSequence != owner.reportSequence || t.submittedSequence > t.generatedSequence ||
        w.startupObserved > 1 || w.preparedSequence > t.generatedSequence ||
        w.observedSequence > t.submittedSequence || w.observedSequence > w.preparedSequence ||
        w.pauseReason > static_cast<std::uint64_t>(TransportReason::SameFileRequalification) || w.reserved ||
        wire.workerPauseReason > static_cast<std::uint64_t>(TransportReason::SameFileRequalification) ||
        wire.fatalTransportReason >= static_cast<std::uint64_t>(TransportReason::Count) ||
        (wire.fatalTransportReason && wire.fatalTransportReason < static_cast<std::uint64_t>(TransportReason::ReceiptGap)))
        return false;
    return true;
}
}

SnapshotResultV3 ReadStatusSnapshotV3(const StatusReadOpsV3& ops, StatusSnapshotV3* output) noexcept {
    if (!output) return SnapshotResultV3::Invalid;
    *output = {};
    if (!ops.read) return SnapshotResultV3::Invalid;
    Reader reader{ops};
    std::uint64_t highestOwner{}, highestWorker{};
    LogIdentity seenLog{};
    bool haveSeenLog{};
    for (unsigned attempt = 1; attempt <= 3; ++attempt) {
        output->attempts = attempt;
        std::uint64_t readyBefore{}, readyAfter{}, pauseBefore{}, pauseAfter{};
        if (!reader.At(offsetof(StatusWireV3, headerReady), readyBefore) || !reader.Gates(*output, pauseBefore))
            return SnapshotResultV3::ReadFailure;
        if (readyBefore > 2) return SnapshotResultV3::Invalid;
        if (readyBefore != 1) continue;
        StatusHeader header{}, headerAfter{};
        if (!reader.At(0, header)) return SnapshotResultV3::ReadFailure;
        if (!HeaderValid(header)) return SnapshotResultV3::Invalid;
        if (!reader.At(offsetof(StatusWireV3, reserved), output->wire.reserved)) return SnapshotResultV3::ReadFailure;
        for (auto word : output->wire.reserved) if (word) return SnapshotResultV3::Invalid;
        if (output->headerAvailable && std::memcmp(&output->wire.header, &header, sizeof(header))) return SnapshotResultV3::Invalid;
        output->wire.header = header; output->headerAvailable = true;
        StatusPayload ownerA{}, ownerB{};
        OwnerTransport transportA{}, transportB{};
        WorkerTransport worker{};
        std::uint64_t a{}, b{}, w{}, logBefore{}, logAfter{};
        bool aStable{}, bStable{}, wStable{};
        if (!reader.Owner(ownerA, transportA, a, aStable) || !reader.Worker(worker, w, wStable) ||
            !reader.At(offsetof(StatusWireV3, logIdentityReady), logBefore)) return SnapshotResultV3::ReadFailure;
        LogIdentity log{};
        if (logBefore > 2) return SnapshotResultV3::Invalid;
        if (logBefore == 1 && !reader.At(offsetof(StatusWireV3, log), log)) return SnapshotResultV3::ReadFailure;
        if (!reader.At(offsetof(StatusWireV3, logIdentityReady), logAfter) ||
            !reader.Owner(ownerB, transportB, b, bStable) || !reader.Gates(*output, pauseAfter) ||
            !reader.At(offsetof(StatusWireV3, headerReady), readyAfter) || !reader.At(0, headerAfter))
            return SnapshotResultV3::ReadFailure;
        if (readyAfter > 2 || logAfter > 2 || readyAfter != 1 || std::memcmp(&header, &headerAfter, sizeof(header)))
            return SnapshotResultV3::Invalid;
        if (reader.invalidSequence || a < highestOwner || b < a || w < highestWorker) return SnapshotResultV3::Invalid;
        highestOwner = b; highestWorker = w;
        if ((logBefore == 1 && logAfter != 1) || (logBefore == 2 && logAfter == 0) ||
            (haveSeenLog && (logBefore != 1 || logAfter != 1))) return SnapshotResultV3::Invalid;
        if (logBefore == 1 && logAfter == 1) {
            if (!IdentityValid(log) || (haveSeenLog && std::memcmp(&seenLog, &log, sizeof(log))))
                return SnapshotResultV3::Invalid;
            seenLog = log; haveSeenLog = true;
        }
        if (!aStable || !bStable || !wStable || a != b || logBefore != logAfter) continue;
        if (std::memcmp(&ownerA, &ownerB, sizeof(ownerA)) || std::memcmp(&transportA, &transportB, sizeof(transportA)))
            return SnapshotResultV3::Invalid;
        output->wire.owner = ownerB; output->wire.ownerTransport = transportB;
        output->wire.ownerSequence = b; output->wire.worker = worker; output->wire.workerSequence = w;
        output->wire.log = log; output->wire.logIdentityReady = logBefore;
        output->logIdentityAvailable = logBefore == 1;
        output->workerPauseChanged = pauseBefore != pauseAfter;
        output->wire.workerPauseReason = pauseAfter ? pauseAfter : pauseBefore;
        output->wire.headerReady = 1;
        // Optional diagnostics cannot change whether the core is coherent.
        reader.Console(*output);
        std::uint64_t finalPause{};
        if (!reader.Gates(*output, finalPause)) return SnapshotResultV3::ReadFailure;
        output->workerPauseChanged = output->workerPauseChanged || finalPause != pauseAfter;
        if (finalPause) output->wire.workerPauseReason = finalPause;
        if (!CoreValid(output->wire)) return SnapshotResultV3::Invalid;
        output->coreAvailable = true;
        return SnapshotResultV3::Coherent;
    }
    return output->headerAvailable ? SnapshotResultV3::Busy : SnapshotResultV3::Unpublished;
}

bool SnapshotCurrentlyReadyV3(const StatusSnapshotV3& snapshot, std::uint64_t now, std::uint64_t frequency) noexcept {
    const auto& wire = snapshot.wire;
    const auto& owner = wire.owner;
    const auto& transport = wire.ownerTransport;
    if (!snapshot.coreAvailable || !snapshot.headerAvailable || !snapshot.logIdentityAvailable ||
        snapshot.workerPauseChanged || wire.revokeReasons || wire.lossReasons || wire.stopping ||
        wire.fatalTransportReason || wire.workerPauseReason || wire.worker.pauseReason ||
        !wire.header.pid || !wire.header.processCreation ||
        wire.header.validity != CompleteHeaderIdentity || !frequency || frequency > INT64_MAX / 45 ||
        wire.header.qpcFrequency != frequency || !now || !owner.lastOwnerQpc || now < owner.lastOwnerQpc ||
        now - owner.lastOwnerQpc > 2 * frequency || !owner.readyQpc || owner.readyQpc > now ||
        !owner.ownerThreadId || !owner.sourceEpoch || !owner.bindingEpoch || owner.builderBound != 1 ||
        transport.state != static_cast<std::uint64_t>(TransportState::Running) || transport.reason ||
        transport.startupSubmitted != 1 || wire.worker.startupObserved != 1) return false;
    unsigned runBits{}, hostBits{};
    for (auto byte : wire.header.runId) runBits |= byte;
    for (auto byte : wire.header.hostDigest) hostBits |= byte;
    if (!runBits || !hostBits) return false;
    if (wire.header.configuredMode == 2)
        return owner.phase == static_cast<std::uint64_t>(ReportPhaseV3::Observing) && !transport.actualRepairAdmitted;
    if (wire.header.configuredMode == 3)
        return owner.phase == static_cast<std::uint64_t>(ReportPhaseV3::Repairing) && transport.actualRepairAdmitted == 1;
    return false;
}
} // namespace rs2fix::reporting
