#include "companion/steam_reporting_status_v3.h"
#include <Windows.h>
#include <algorithm>
#include <cstring>

#if !defined(_MSC_VER) || !defined(_M_X64)
#error V3 publication requires the Windows MSVC AMD64 aligned-store contract.
#endif

namespace rs2fix::reporting {
static_assert(kReasonCount == kRuntimeReasonCountV3);
namespace {
volatile LONG64* Atomic(std::uint64_t& word) noexcept {
    return reinterpret_cast<volatile LONG64*>(&word);
}
std::uint64_t Mask(Reason reason) noexcept {
    const auto value = static_cast<std::size_t>(reason);
    return 1ULL << (value && value < kReasonCount ? value : static_cast<std::size_t>(Reason::StatusUnavailable));
}
template<class T> void StoreWords(T& target, const T& source) noexcept {
    static_assert(alignof(T) >= 8 && sizeof(T) % 8 == 0);
    for (std::size_t offset = 0; offset < sizeof(T); offset += 8) {
        std::uint64_t value{};
        std::memcpy(&value, reinterpret_cast<const unsigned char*>(&source) + offset, 8);
        auto* word = reinterpret_cast<std::uint64_t*>(reinterpret_cast<unsigned char*>(&target) + offset);
        WriteRelease64(Atomic(*word), static_cast<LONG64>(value));
    }
}
template<class T> void LoadWords(const T& source, T& target) noexcept {
    static_assert(alignof(T) >= 8 && sizeof(T) % 8 == 0);
    for (std::size_t offset = 0; offset < sizeof(T); offset += 8) {
        const auto* word = reinterpret_cast<const std::uint64_t*>(reinterpret_cast<const unsigned char*>(&source) + offset);
        const auto value = ReadStatusWord(*word);
        std::memcpy(reinterpret_cast<unsigned char*>(&target) + offset, &value, 8);
    }
}
bool StartPublication(std::uint64_t& sequence, std::uint64_t& before) noexcept {
    before = ReadStatusWord(sequence);
    if ((before & 1) || before > UINT64_MAX - 2) return false;
    StoreStatusWord(sequence, before + 1);
    return true;
}
bool HeaderReady(const StatusWireV3& wire) noexcept { return ReadStatusWord(wire.headerReady) == 1; }
}

bool InitializeStatusV3(StatusWireV3& wire, const StatusHeader& header, const StatusPayload& owner) noexcept {
    if (InterlockedCompareExchange64(Atomic(wire.headerReady), 2, 0) != 0) return false;
    wire.header = header;
    wire.header.magic = kStatusMagic;
    wire.header.schema = kStatusSchemaV3;
    wire.header.bytes = sizeof(StatusWireV3);
    wire.header.artifactVersion = kReportingArtifactVersionV3;
    std::memset(wire.header.reserved, 0, sizeof(wire.header.reserved));
    std::memset(wire.reserved, 0, sizeof(wire.reserved));
    OwnerTransport transport{};
    transport.state = static_cast<std::uint64_t>(TransportState::WaitingLogger);
    transport.reason = static_cast<std::uint64_t>(TransportReason::AwaitingLogger);
    transport.generatedSequence = owner.reportSequence;
    StoreStatusWord(wire.ownerSequence, 1);
    StoreWords(wire.owner, owner);
    StoreWords(wire.ownerTransport, transport);
    StoreStatusWord(wire.ownerSequence, 2);
    StoreStatusWord(wire.workerSequence, 1);
    StoreWords(wire.worker, WorkerTransport{});
    StoreStatusWord(wire.workerSequence, 2);
    StoreStatusWord(wire.consoleSequence, 1);
    StoreWords(wire.console, ConsoleDiagnostics{});
    StoreStatusWord(wire.consoleSequence, 2);
    // Never clear sticky/stop gates set by a concurrent terminal failure.
    StoreStatusWord(wire.headerReady, 1);
    return true;
}

bool PublishOwnerV3(StatusWireV3& wire, const StatusPayload& owner, const OwnerTransport& input) noexcept {
    if (!HeaderReady(wire)) return false;
    if (input.state > static_cast<std::uint64_t>(TransportState::Stopping) ||
        input.reason >= static_cast<std::uint64_t>(TransportReason::Count) ||
        input.generatedSequence != owner.reportSequence || input.submittedSequence > input.generatedSequence ||
        input.generatedSequence < ReadStatusWord(wire.ownerTransport.generatedSequence) ||
        input.submittedSequence < ReadStatusWord(wire.ownerTransport.submittedSequence) ||
        input.startupSubmitted > 1 || input.actualRepairAdmitted > 1) {
        RevokeStatus(wire, Reason::StatusUnavailable); return false;
    }
    std::uint64_t sequence{};
    if (!StartPublication(wire.ownerSequence, sequence)) {
        RevokeStatus(wire, Reason::CounterOverflow); return false;
    }
    auto transport = input;
    transport.reserved = 0;
    StoreWords(wire.owner, owner);
    StoreWords(wire.ownerTransport, transport);
    StoreStatusWord(wire.ownerSequence, sequence + 2);
    return true;
}

bool ReadOwnerV3(const StatusWireV3& wire, OwnerSnapshotV3* output) noexcept {
    if (!output) return false;
    *output = {};
    for (unsigned retry = 0; retry < 3; ++retry) {
        if (!HeaderReady(wire)) return false;
        const auto before = ReadStatusWord(wire.ownerSequence);
        if (before < 2 || (before & 1)) continue;
        OwnerSnapshotV3 copy{};
        LoadWords(wire.owner, copy.owner);
        LoadWords(wire.ownerTransport, copy.transport);
        const auto after = ReadStatusWord(wire.ownerSequence);
        if (before != after || (after & 1) || !HeaderReady(wire)) continue;
        copy.sequence = after;
        *output = copy;
        return true;
    }
    return false;
}

bool PublishWorkerV3(StatusWireV3& wire, const WorkerTransport& input) noexcept {
    if (!HeaderReady(wire)) return false;
    if (input.pauseReason > static_cast<std::uint64_t>(TransportReason::SameFileRequalification) ||
        input.startupObserved > 1) {
        RevokeStatus(wire, Reason::StatusUnavailable); return false;
    }
    // Close the independent worker gate before any adverse coherent publication.
    if (input.pauseReason) StoreStatusWord(wire.workerPauseReason, input.pauseReason);
    OwnerSnapshotV3 owner{};
    if (!ReadOwnerV3(wire, &owner)) return false; // A racing owner is not evidence loss.
    if (input.observedSequence > owner.transport.submittedSequence ||
        input.observedSequence > input.preparedSequence ||
        input.observedSequence < ReadStatusWord(wire.worker.observedSequence) ||
        input.preparedSequence < ReadStatusWord(wire.worker.preparedSequence)) {
        LoseStatus(wire, Reason::RecordLoss); return false;
    }
    auto worker = input;
    worker.preparedSequence = (std::min)(worker.preparedSequence, owner.transport.generatedSequence);
    worker.reserved = 0;
    std::uint64_t sequence{};
    if (!StartPublication(wire.workerSequence, sequence)) {
        RevokeStatus(wire, Reason::CounterOverflow); return false;
    }
    StoreWords(wire.worker, worker);
    StoreStatusWord(wire.workerSequence, sequence + 2);
    // Only this writer clears this gate, and only after condition-free state is
    // visible. Owner-local pause/admission remains independently authoritative.
    if (!input.pauseReason) StoreStatusWord(wire.workerPauseReason, 0);
    return true;
}

bool PublishConsoleV3(StatusWireV3& wire, const ConsoleDiagnostics& input) noexcept {
    if (!HeaderReady(wire) || input.workerState > 3 || input.written > input.attempts ||
        input.failures > input.attempts || input.written > input.attempts - input.failures) return false;
    std::uint64_t sequence{};
    if (!StartPublication(wire.consoleSequence, sequence)) return false;
    StoreWords(wire.console, input);
    StoreStatusWord(wire.consoleSequence, sequence + 2);
    // No native/console I/O here. In-flight console writes start only after this
    // even publication, and console publication failure never revokes reporting.
    return true;
}

bool PublishLogIdentityV3(StatusWireV3& wire, const LogIdentity& identity) noexcept {
    if (!HeaderReady(wire) || !identity.pathChars || identity.pathChars > 1023 ||
        identity.path[identity.pathChars] || identity.prefixMode > 1 || identity.transportKind != 1 ||
        identity.durability || identity.initialAtLineBoundary > 1 || !identity.utcFiletime ||
        !identity.calibrationQpcBefore || identity.calibrationQpcAfter < identity.calibrationQpcBefore)
        return false;
    for (std::size_t i = 0; i < identity.pathChars; ++i) if (!identity.path[i]) return false;
    if (InterlockedCompareExchange64(Atomic(wire.logIdentityReady), 2, 0) != 0) return false;
    wire.log = identity;
    std::memset(wire.log.path + identity.pathChars, 0, (1024 - identity.pathChars) * sizeof(wire.log.path[0]));
    StoreStatusWord(wire.logIdentityReady, 1);
    return true;
}

void RevokeStatus(StatusWireV3& wire, Reason reason) noexcept {
    InterlockedOr64(Atomic(wire.revokeReasons), static_cast<LONG64>(Mask(reason)));
}
void LoseStatus(StatusWireV3& wire, Reason reason) noexcept {
    InterlockedOr64(Atomic(wire.lossReasons), static_cast<LONG64>(Mask(reason)));
    RevokeStatus(wire, reason);
}
void StopStatus(StatusWireV3& wire, std::uint64_t qpc) noexcept {
    if (InterlockedCompareExchange64(Atomic(wire.stopping), 1, 0) == 0) StoreStatusWord(wire.stoppedQpc, qpc);
}
bool StatusRevoked(const StatusWireV3& wire) noexcept {
    return ReadStatusWord(wire.revokeReasons) || ReadStatusWord(wire.lossReasons) ||
        ReadStatusWord(wire.stopping) || ReadStatusWord(wire.fatalTransportReason);
}
bool LatchTransportFault(StatusWireV3& wire, TransportReason reason) noexcept {
    if (reason < TransportReason::ReceiptGap || reason >= TransportReason::Count) return false;
    InterlockedCompareExchange64(Atomic(wire.fatalTransportReason), static_cast<LONG64>(reason), 0);
    if (reason <= TransportReason::FileTruncated) LoseStatus(wire, Reason::RecordLoss);
    else RevokeStatus(wire, reason == TransportReason::ProfileUnsafe ? Reason::ProfileMismatch : Reason::NativeUnwind);
    return true;
}
} // namespace rs2fix::reporting
