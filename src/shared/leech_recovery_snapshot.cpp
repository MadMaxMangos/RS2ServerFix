#include "shared/leech_recovery_status.h"
#include <cstring>

namespace rs2fix::reporting {
namespace {
template<class T> bool AnyByte(const T& bytes) noexcept {
    unsigned bits{};
    for (auto byte : bytes) bits |= byte;
    return bits != 0;
}
template<class Ops, class T> bool At(const Ops& ops, std::size_t offset, T& value) noexcept {
    return ops.read(ops.context, offset, &value, sizeof(value));
}
bool RecoveryHeaderValid(const RecoveryStatusWireV1& wire) noexcept {
    return wire.schema == kRecoveryStatusSchemaV1 && wire.bytes == sizeof(wire) &&
        wire.artifactVersion == kRecoveryArtifactVersion && wire.pid && AnyByte(wire.runId);
}
bool SameRecoveryHeader(const RecoveryStatusWireV1& a, const RecoveryStatusWireV1& b) noexcept {
    return std::memcmp(&a, &b, offsetof(RecoveryStatusWireV1, headerReady)) == 0;
}
}

bool ReportingIdentityValidV3(const StatusHeader& h) noexcept {
    if (h.magic != kStatusMagic || h.schema != kStatusSchemaV3 || h.bytes != sizeof(StatusWireV3) ||
        h.artifactVersion != kReportingArtifactVersionV3 || h.artifactVersion != kRecoveryArtifactVersion ||
        h.configuredMode > 3 || h.validity != CompleteHeaderIdentity || !h.pid || !h.processCreation ||
        !h.qpcFrequency || h.qpcFrequency > INT64_MAX / 45 || !AnyByte(h.runId) || !AnyByte(h.hostDigest))
        return false;
    for (auto word : h.reserved) if (word) return false;
    return true;
}

SnapshotResultV3 ReadReportingIdentityV3(const StatusReadOpsV3& ops, StatusHeader* output) noexcept {
    if (!output) return SnapshotResultV3::Invalid;
    *output = {};
    if (!ops.read) return SnapshotResultV3::Invalid;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        std::uint64_t before{}, after{};
        if (!At(ops, offsetof(StatusWireV3, headerReady), before)) return SnapshotResultV3::ReadFailure;
        if (before > 2) return SnapshotResultV3::Invalid;
        if (before != 1) continue;
        StatusHeader a{}, b{};
        std::uint64_t reservedA[5]{}, reservedB[5]{}, ownerReservedA{}, ownerReservedB{}, workerReservedA{}, workerReservedB{};
        if (!At(ops, 0, a) || !At(ops, offsetof(StatusWireV3, reserved), reservedA) ||
            !At(ops, offsetof(StatusWireV3, ownerTransport) + offsetof(OwnerTransport, reserved), ownerReservedA) ||
            !At(ops, offsetof(StatusWireV3, worker) + offsetof(WorkerTransport, reserved), workerReservedA) ||
            !At(ops, 0, b) || !At(ops, offsetof(StatusWireV3, reserved), reservedB) ||
            !At(ops, offsetof(StatusWireV3, ownerTransport) + offsetof(OwnerTransport, reserved), ownerReservedB) ||
            !At(ops, offsetof(StatusWireV3, worker) + offsetof(WorkerTransport, reserved), workerReservedB) ||
            !At(ops, offsetof(StatusWireV3, headerReady), after)) return SnapshotResultV3::ReadFailure;
        if (after != 1 || std::memcmp(&a, &b, sizeof(a)) || !ReportingIdentityValidV3(a) ||
            ownerReservedA || ownerReservedB || workerReservedA || workerReservedB) return SnapshotResultV3::Invalid;
        for (auto word : reservedA) if (word) return SnapshotResultV3::Invalid;
        for (auto word : reservedB) if (word) return SnapshotResultV3::Invalid;
        *output = a;
        return SnapshotResultV3::Coherent;
    }
    return SnapshotResultV3::Unpublished;
}

bool RecoveryPayloadValid(const ReportRecoveryPayload& p) noexcept {
    if (p.phase >= static_cast<std::uint64_t>(RecoveryPhase::Count) ||
        p.event >= static_cast<std::uint64_t>(RecoveryEvent::Count) ||
        p.reason >= static_cast<std::uint64_t>(RecoveryReason::Count) ||
        p.outcome >= static_cast<std::uint64_t>(RecoveryOutcome::Count) ||
        p.resourcePhase >= static_cast<std::uint64_t>(ResourcePhase::Count) ||
        p.nativeStage >= static_cast<std::uint64_t>(NativeStage::Count) ||
        p.callbackResult >= static_cast<std::uint64_t>(CallbackResult::Count) || (p.flags & ~kRecoveryKnownFlags) ||
        p.ownerThreadId > UINT32_MAX || p.exceptionCode > UINT32_MAX || p.requestId > UINT32_MAX ||
        p.callbackId > UINT32_MAX || p.apiReturnedId > UINT32_MAX || p.qpc > INT64_MAX ||
        p.finishDeadlineQpc > INT64_MAX || p.overallDeadlineQpc > INT64_MAX || p.callbackOwnTicks > INT64_MAX)
        return false;
    if ((p.flags & RecoveryCallbackOwnTimingValid) ? !(p.flags & RecoveryCreateCallbackObserved) : p.callbackOwnTicks != 0)
        return false;
    if ((p.flags & RecoveryCreateForwardNormalCompleted) && !(p.flags & RecoveryCreateForwardEntered)) return false;
    if ((p.flags & RecoveryCreateForwardEntered) && !(p.flags & RecoveryCreateCallbackObserved)) return false;
    constexpr auto metadata=RecoveryMetadataAttempted|RecoveryMetadataCoherent|RecoveryMetadataUnverified|RecoveryMetadataDirtyAfter;
    if((p.flags&metadata) && !(p.flags&RecoveryPublishedLocally)) return false;
    if((p.flags&RecoveryMetadataCoherent) && (p.flags&RecoveryMetadataUnverified)) return false;
    if((p.flags&RecoveryMetadataDirtyAfter) && !(p.flags&RecoveryMetadataAttempted)) return false;
    if((p.flags&RecoveryConsoleRequested) && !p.operationSequence) return false;
    if(p.flags&RecoveryPreflightRetryable) {
        constexpr auto allowed=RecoveryPermissionEnabled|RecoveryTerminal|RecoveryConsoleRequested|RecoveryPreflightRetryable;
        if(p.phase!=static_cast<std::uint64_t>(RecoveryPhase::Rejected) || !p.operationSequence ||
            (p.outcome!=static_cast<std::uint64_t>(RecoveryOutcome::MechanicsFailed) &&
                p.outcome!=static_cast<std::uint64_t>(RecoveryOutcome::RecordingUnavailable)) ||
            (p.flags&~allowed) || (p.flags&(RecoveryPermissionEnabled|RecoveryTerminal))!=(RecoveryPermissionEnabled|RecoveryTerminal) ||
            p.nativeStage || p.resourcePhase || p.exceptionCode || p.requestId || p.callbackId || p.callbackResult || p.apiReturnedId) return false;
    }
    return true;
}

RecoverySnapshotResult ReadRecoveryStatusSnapshot(const RecoveryReadOps& ops, RecoveryStatusSnapshot* output) noexcept {
    if (!output) return RecoverySnapshotResult::Invalid;
    *output = {};
    if (!ops.read) return RecoverySnapshotResult::Invalid;
    bool published{};
    std::uint64_t highest{};
    RecoveryStatusWireV1 seen{};
    for (unsigned attempt = 1; attempt <= 3; ++attempt) {
        output->attempts = attempt;
        std::uint64_t readyBefore{}, readyAfter{}, before{}, after{};
        if (!At(ops, offsetof(RecoveryStatusWireV1, headerReady), readyBefore)) return RecoverySnapshotResult::ReadFailure;
        if (readyBefore > 2 || (published && readyBefore != 1)) return RecoverySnapshotResult::Invalid;
        if (readyBefore != 1) continue;
        RecoveryStatusWireV1 copy{}, headerAfter{};
        if (!ops.read(ops.context, 0, &copy, offsetof(RecoveryStatusWireV1, headerReady)) ||
            !At(ops, offsetof(RecoveryStatusWireV1, ownerSequence), before)) return RecoverySnapshotResult::ReadFailure;
        if (!RecoveryHeaderValid(copy) || (published && !SameRecoveryHeader(copy, seen)) || !before || before < highest)
            return RecoverySnapshotResult::Invalid;
        seen = copy; published = true; highest = before;
        if (before & 1) continue;
        if (!At(ops, offsetof(RecoveryStatusWireV1, payload), copy.payload) ||
            !At(ops, offsetof(RecoveryStatusWireV1, ownerSequence), after) ||
            !ops.read(ops.context, 0, &headerAfter, offsetof(RecoveryStatusWireV1, headerReady)) ||
            !At(ops, offsetof(RecoveryStatusWireV1, headerReady), readyAfter)) return RecoverySnapshotResult::ReadFailure;
        if (readyAfter != 1 || !SameRecoveryHeader(copy, headerAfter) || after < before)
            return RecoverySnapshotResult::Invalid;
        highest = after;
        if (before != after || (after & 1)) continue;
        if (!RecoveryPayloadValid(copy.payload)) return RecoverySnapshotResult::Invalid;
        copy.headerReady = 1; copy.ownerSequence = after;
        output->wire = copy;
        return RecoverySnapshotResult::Coherent;
    }
    return published ? RecoverySnapshotResult::Busy : RecoverySnapshotResult::Unavailable;
}

RecoverySnapshotResult ReadRecoveryStatusSnapshot(const RecoveryReadOps& ops,
    const StatusHeader& identity, RecoveryStatusSnapshot* output) noexcept {
    if (!output) return RecoverySnapshotResult::Invalid;
    *output = {};
    if (!ReportingIdentityValidV3(identity)) return RecoverySnapshotResult::Invalid;
    RecoveryStatusSnapshot copy{};
    const auto result = ReadRecoveryStatusSnapshot(ops, &copy);
    output->attempts = copy.attempts;
    if (result != RecoverySnapshotResult::Coherent) return result;
    if (copy.wire.pid != identity.pid || copy.wire.artifactVersion != identity.artifactVersion ||
        std::memcmp(copy.wire.runId, identity.runId, sizeof(identity.runId))) return RecoverySnapshotResult::Invalid;
    *output = copy;
    return result;
}

const char* RecoverySnapshotResultName(RecoverySnapshotResult result) noexcept {
    switch (result) {
    case RecoverySnapshotResult::Coherent: return "Coherent";
    case RecoverySnapshotResult::Busy: return "Busy";
    case RecoverySnapshotResult::Unavailable: return "Unavailable";
    case RecoverySnapshotResult::Invalid: return "Invalid";
    case RecoverySnapshotResult::ReadFailure: return "ReadFailure";
    }
    return "Invalid";
}
} // namespace rs2fix::reporting
