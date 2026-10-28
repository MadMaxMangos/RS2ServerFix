#include "companion/steam_reporting_records.h"
#include "companion/steam_reporting_records_v3.h"
#include "companion/steam_reporting_status_v3.h"
#include <Windows.h>
#include <cstring>
#include <limits>

namespace rs2fix::reporting {
namespace {
template<class Record> constexpr std::uint32_t KindCount() noexcept {
    return std::is_same_v<Record, ReportRecordV3> ? static_cast<std::uint32_t>(RecordKindV3::Count) :
        static_cast<std::uint32_t>(RecordKind::Count);
}
template<class Record> bool ValidHeader(const ReportHeader& header) noexcept {
    return header.sequence==0 && header.kind>=static_cast<std::uint32_t>(RecordKind::State) &&
        header.kind<KindCount<Record>() && header.reason<kReasonCount;
}
template<class Record> bool ValidRecovery(const Record& record) noexcept {
    if constexpr (std::is_same_v<Record, ReportRecordV3>) {
        if (record.header.kind == static_cast<std::uint32_t>(RecordKindV3::Recovery))
            return record.header.reason == 0 && record.header.flags == 0 &&
                record.payload.recovery.recordSequence == 0 && RecoveryPayloadValid(record.payload.recovery);
    }
    return true;
}
template<class Record> void CanonicalRecord(const Record& in, std::uint64_t sequence,
    std::uint32_t owner, Record& out) noexcept {
    // Deliberately do not copy a union/variant wholesale: even a caller's
    // reserved bytes or inactive member contents must never reach the writer.
    out={};
    out.header.sequence=sequence; out.header.qpc=in.header.qpc;
    out.header.sourceEpoch=in.header.sourceEpoch; out.header.bindingEpoch=in.header.bindingEpoch;
    out.header.kind=in.header.kind; out.header.reason=in.header.reason;
    out.header.flags=in.header.flags; out.header.threadId=owner;
    switch (static_cast<RecordKind>(in.header.kind)) {
    case RecordKind::State: {
        const auto& a=in.payload.state; auto& b=out.payload.state;
        b.phase=a.phase; b.requestSequence=a.requestSequence; b.witnessSequence=a.witnessSequence;
        b.buildSequence=a.buildSequence; b.pendingSinceQpc=a.pendingSinceQpc;
        b.freshSinceQpc=a.freshSinceQpc; b.qualificationFlags=a.qualificationFlags;
        b.nativeTaskState=a.nativeTaskState; b.mode=a.mode; b.classification=a.classification;
        b.pi=a.pi; b.bots=a.bots; b.maximum=a.maximum;
        b.pending=a.pending; b.fresh=a.fresh; b.bound=a.bound;
        b.clientQualificationMs=a.clientQualificationMs;
        // Only exact validity=1 admits copied bits. Otherwise all eleven fields
        // remain zero, so an unavailable observation cannot carry stale values.
        if (a.nativeScheduleValid==1) {
            b.nativeScheduleValid=1;
            b.nativeScheduleAnchorBits=a.nativeScheduleAnchorBits;
            b.nativeErrorsBits=a.nativeErrorsBits; b.nativeThrottlesBits=a.nativeThrottlesBits;
            b.nativeExpedite=a.nativeExpedite; b.nativeRetryLimit=a.nativeRetryLimit;
            b.nativeIntervalUnits=a.nativeIntervalUnits;
            b.nativeIntervalOverrideBits=a.nativeIntervalOverrideBits;
            b.nativeRetryOverrideBits=a.nativeRetryOverrideBits;
            b.nativeDelayUnits=a.nativeDelayUnits; b.nativeTier=a.nativeTier;
        }
        break;
    }
    case RecordKind::Request: case RecordKind::Witness: {
        out.payload.request={}; // Explicitly start this trivial union member's lifetime.
        const auto& a=in.payload.request; auto& b=out.payload.request;
        b.requestSequence=a.requestSequence; b.witnessSequence=a.witnessSequence;
        b.stagedQpc=a.stagedQpc; b.previousSampleQpc=a.previousSampleQpc;
        b.observedQpc=a.observedQpc; b.freshSinceQpc=a.freshSinceQpc;
        b.sourceAgeTicks=a.sourceAgeTicks; b.pi=a.pi; b.bots=a.bots; b.maximum=a.maximum;
        b.stagedBots=a.stagedBots; b.humanPlayers=a.humanPlayers; b.worldBots=a.worldBots;
        b.classification=a.classification; b.pending=a.pending;
        break;
    }
    case RecordKind::BuilderEnter: case RecordKind::BuilderReturn: case RecordKind::BuilderUnwind: {
        out.payload.builder={};
        const auto& a=in.payload.builder; auto& b=out.payload.builder;
        b.buildSequence=a.buildSequence; b.requestSequence=a.requestSequence;
        b.witnessSequence=a.witnessSequence; b.sourceAgeTicks=a.sourceAgeTicks;
        b.probeElapsedTicks=a.probeElapsedTicks;
        b.classificationElapsedTicks=a.classificationElapsedTicks;
        b.originalElapsedTicks=a.originalElapsedTicks;
        b.entryQpc=a.entryQpc; b.returnQpc=a.returnQpc;
        b.pi=a.pi; b.bots=a.bots; b.maximum=a.maximum; b.classification=a.classification;
        b.selected=a.selected; b.result=a.result; b.pending=a.pending; b.fresh=a.fresh;
        if constexpr (std::is_same_v<Record, ReportRecordV3>) {
            // No partially validated read or inactive/reserved words reach logs.
            if (a.preparedValid==1 && a.preparedMismatchMask<=31 &&
                a.preparedMembers<=4096 && a.preparedJsonBytes>0 && a.preparedJsonBytes<=kJsonBytes) {
                b.preparedValid=1; b.preparedMismatchMask=a.preparedMismatchMask;
                b.preparedMaximum=a.preparedMaximum; b.preparedMembers=a.preparedMembers;
                b.preparedPi=a.preparedPi; b.preparedBots=a.preparedBots;
                b.preparedJsonMaximum=a.preparedJsonMaximum; b.preparedJsonBytes=a.preparedJsonBytes;
            }
            if (a.preparedDirtyValid==1 && a.preparedDirtyAtEntry<=1) {
                b.preparedDirtyValid=1; b.preparedDirtyAtEntry=a.preparedDirtyAtEntry;
            }
        }
        break;
    }
    case RecordKind::Anchor: {
        out.payload.anchor={};
        const auto& a=in.payload.anchor; auto& b=out.payload.anchor;
        b.normalAttempts=a.normalAttempts; b.fullSelected=a.fullSelected; b.selectedTrue=a.selectedTrue;
        b.normalReturns=a.normalReturns; b.falseReturns=a.falseReturns; b.nativeUnwinds=a.nativeUnwinds;
        b.requestSequence=a.requestSequence; b.witnessSequence=a.witnessSequence;
        b.buildSequence=a.buildSequence; b.distinctSelectedWitnesses=a.distinctSelectedWitnesses;
        for (std::size_t i=0; i<kStatusDurationClasses; ++i) {
            b.durations[i].calls=a.durations[i].calls;
            b.durations[i].elapsedTicks=a.durations[i].elapsedTicks;
            b.durations[i].maximumTicks=a.durations[i].maximumTicks;
            b.durations[i].overFiveMilliseconds=a.durations[i].overFiveMilliseconds;
        }
        break;
    }
    case RecordKind::Count: break; // Legacy sentinel; V3 extras are handled below.
    }
    if constexpr (std::is_same_v<Record, ReportRecordV3>) {
        if (in.header.kind == static_cast<std::uint32_t>(RecordKindV3::TransportSummary)) {
            out.payload.transport = {};
            const auto& a = in.payload.transport; auto& b = out.payload.transport;
            b.anchorSequence = a.anchorSequence; b.nativeSubmitCalls = a.nativeSubmitCalls;
            b.nativeSubmitElapsedTicks = a.nativeSubmitElapsedTicks;
            b.nativeSubmitMaximumTicks = a.nativeSubmitMaximumTicks;
            b.nativeSubmitOverFiveMilliseconds = a.nativeSubmitOverFiveMilliseconds;
            b.forwardedPumpWithoutCapture = a.forwardedPumpWithoutCapture;
            b.forwardedBuilderWithoutCapture = a.forwardedBuilderWithoutCapture;
            b.transportState = a.transportState; b.transportReason = a.transportReason;
            b.pauseEpoch = a.pauseEpoch; b.pauseBoundarySequence = a.pauseBoundarySequence;
            b.submittedSequence = a.submittedSequence; b.observedSequence = a.observedSequence;
            b.timingAccountedThroughQpc = a.timingAccountedThroughQpc;
            b.generatedSequence = a.generatedSequence;
        } else if (in.header.kind == static_cast<std::uint32_t>(RecordKindV3::Control)) {
            out.payload.control = {};
            const auto& a = in.payload.control; auto& b = out.payload.control;
            b.event = a.event; b.transportState = a.transportState; b.transportReason = a.transportReason;
            b.pauseEpoch = a.pauseEpoch; b.pauseBoundarySequence = a.pauseBoundarySequence;
            b.abandonedPendingRequest = a.abandonedPendingRequest; b.abandonedWitness = a.abandonedWitness;
            b.lastRequestQpc = a.lastRequestQpc; b.generatedBefore = a.generatedBefore;
            b.submittedBefore = a.submittedBefore; b.observedBefore = a.observedBefore;
            b.forwardedPumpWithoutCapture = a.forwardedPumpWithoutCapture;
            b.forwardedBuilderWithoutCapture = a.forwardedBuilderWithoutCapture;
            b.timingAccountedThroughQpc = a.timingAccountedThroughQpc;
        } else if (in.header.kind == static_cast<std::uint32_t>(RecordKindV3::Recovery)) {
            out.payload.recovery = {};
            const auto& a = in.payload.recovery; auto& b = out.payload.recovery;
            b.phase = a.phase; b.event = a.event; b.reason = a.reason; b.outcome = a.outcome; b.flags = a.flags;
            b.operationSequence = a.operationSequence; b.transitionSequence = a.transitionSequence;
            b.qpc = a.qpc; b.sourceEpoch = a.sourceEpoch; b.sdkEpoch = a.sdkEpoch; b.ownerThreadId = a.ownerThreadId;
            b.resourcePhase = a.resourcePhase; b.nativeStage = a.nativeStage; b.exceptionCode = a.exceptionCode;
            b.requestId = a.requestId; b.callbackId = a.callbackId; b.callbackResult = a.callbackResult;
            b.apiReturnedId = a.apiReturnedId; b.oldSdkFingerprint = a.oldSdkFingerprint;
            b.newSdkFingerprint = a.newSdkFingerprint; b.oldCacheFingerprint = a.oldCacheFingerprint;
            b.newCacheFingerprint = a.newCacheFingerprint; b.finishDeadlineQpc = a.finishDeadlineQpc;
            b.overallDeadlineQpc = a.overallDeadlineQpc; b.recordSequence = a.recordSequence;
            b.callbackOwnTicks = a.callbackOwnTicks;
        }
    }
}
template<class Status> ReportWriteResult Admission(Status& status) noexcept {
    if (ReadStatusWord(status.stopping)) return ReportWriteResult::Stopping;
    if (StatusRevoked(status)) return ReadStatusWord(status.stopping) ?
        ReportWriteResult::Stopping : ReportWriteResult::Revoked;
    return ReportWriteResult::Accepted;
}
template<class Status> ReportWriteResult WriteLoss(Status& status, Reason reason) noexcept {
    // Initial admission precedes validation: once admitted, a detected failure
    // commits to loss even if stopping races this latch. A later stop must not
    // erase failed required publication. Initial/final admission suppress only
    // work that has not failed; no global lock or stop recheck belongs here.
    LoseStatus(status,reason);
    return ReportWriteResult::Lost;
}
bool SinkEntry(void* context, const ReportRecord& record, std::uint64_t* sequence) noexcept {
    if (!context) { if (sequence) *sequence=0; return false; }
    return EnqueueReport(*static_cast<ReportRing*>(context),record,sequence)==ReportWriteResult::Accepted;
}
bool SinkEntryV3(void* context, const ReportRecordV3& record, std::uint64_t* sequence) noexcept {
    if (!context) { if (sequence) *sequence = 0; return false; }
    return EnqueueReport(*static_cast<ReportRingV3*>(context), record, sequence) == ReportWriteResult::Accepted;
}

template<class Ring, class Status> bool InitializeRing(Ring& ring, Status& status,
    std::uint32_t ownerThreadId) noexcept {
    if (ReadStatusWord(ring.ready)!=0 || !ownerThreadId) return false;
    if (GetCurrentThreadId()!=ownerThreadId) { RevokeStatus(status,Reason::ForeignThread); return false; }
    ring.status=&status; ring.ownerThreadId=ownerThreadId; ring.reserved=0;
    std::memset(ring.slots,0,sizeof(ring.slots));
    StoreStatusWord(ring.reportWriteSequence,0); StoreStatusWord(ring.reportReadSequence,0);
    StoreStatusWord(ring.ready,1);
    return true;
}

template<class Ring, class Record> ReportWriteResult Enqueue(Ring& ring, const Record& input,
    std::uint64_t* acceptedSequence) noexcept {
    if (acceptedSequence) *acceptedSequence=0;
    if (ReadStatusWord(ring.ready)!=1 || !ring.status) return ReportWriteResult::Unavailable;
    auto& status=*ring.status;
    if (GetCurrentThreadId()!=ring.ownerThreadId) {
        RevokeStatus(status,Reason::ForeignThread);
        return ReportWriteResult::Revoked; // No slot or queue-index access.
    }
    const auto admitted=Admission(status);
    if (admitted!=ReportWriteResult::Accepted) return admitted;
    if (!acceptedSequence || !ValidHeader<Record>(input.header) || !ValidRecovery(input)) return WriteLoss(status,Reason::RecordLoss);
    const auto written=ReadStatusWord(ring.reportWriteSequence);
    const auto read=ReadStatusWord(ring.reportReadSequence);
    if (read>written || written-read>kReportRecordCapacity) return WriteLoss(status,Reason::RecordLoss);
    if (written==(std::numeric_limits<std::uint64_t>::max)()) return WriteLoss(status,Reason::CounterOverflow);
    if (written-read==kReportRecordCapacity) return WriteLoss(status,Reason::RecordLoss);
    Record record{};
    CanonicalRecord(input,written+1,ring.ownerThreadId,record);
    const auto finalAdmission=Admission(status);
    if (finalAdmission!=ReportWriteResult::Accepted) return finalAdmission;
    ring.slots[written%kReportRecordCapacity]=record;
    // Interlocked publication is release/acquire (stronger: full barrier on
    // this Windows implementation). Slot ownership transfers only afterwards.
    StoreStatusWord(ring.reportWriteSequence,written+1);
    *acceptedSequence=written+1;
    return ReportWriteResult::Accepted;
}

template<class Ring, class Record> ReportReadResult Dequeue(Ring& ring, Record* output) noexcept {
    if (output) *output={};
    if (ReadStatusWord(ring.ready)!=1 || !ring.status) return ReportReadResult::Unavailable;
    auto& status=*ring.status;
    if (!output) { LoseStatus(status,Reason::RecordLoss); return ReportReadResult::Lost; }
    const auto read=ReadStatusWord(ring.reportReadSequence);
    const auto written=ReadStatusWord(ring.reportWriteSequence);
    if (read>written || written-read>kReportRecordCapacity) {
        LoseStatus(status,Reason::RecordLoss); return ReportReadResult::Lost;
    }
    if (read==written) return ReportReadResult::Empty;
    // read<written means read+1 cannot overflow. Native sequence corruption is
    // not silently skipped, renumbered or turned into an apparently valid log.
    auto& slot=ring.slots[read%kReportRecordCapacity];
    if (slot.header.sequence!=read+1 || slot.header.kind<static_cast<std::uint32_t>(RecordKind::State) ||
        slot.header.kind>=KindCount<Record>() || slot.header.reason>=kReasonCount ||
        slot.header.threadId!=ring.ownerThreadId || !ValidRecovery(slot)) {
        LoseStatus(status,Reason::RecordLoss); return ReportReadResult::Lost;
    }
    *output=slot;
    SecureZeroMemory(&slot,sizeof(slot));
    // Never move this before copy/scrub: producer may reuse this exact slot as
    // soon as readSequence advances. A later scrub would erase a new record.
    StoreStatusWord(ring.reportReadSequence,read+1);
    return ReportReadResult::Record;
}
} // namespace

bool InitializeReportRing(ReportRing& ring, StatusWire& status, std::uint32_t owner) noexcept {
    return InitializeRing(ring, status, owner);
}
bool InitializeReportRing(ReportRingV3& ring, StatusWireV3& status, std::uint32_t owner) noexcept {
    return InitializeRing(ring, status, owner);
}
ReportWriteResult EnqueueReport(ReportRing& ring, const ReportRecord& record, std::uint64_t* sequence) noexcept {
    return Enqueue(ring, record, sequence);
}
ReportWriteResult EnqueueReport(ReportRingV3& ring, const ReportRecordV3& record, std::uint64_t* sequence) noexcept {
    return Enqueue(ring, record, sequence);
}
ReportReadResult DequeueReport(ReportRing& ring, ReportRecord* output) noexcept { return Dequeue(ring, output); }
ReportReadResult DequeueReport(ReportRingV3& ring, ReportRecordV3* output) noexcept { return Dequeue(ring, output); }

ReportSink ReportRingSink(ReportRing& ring) noexcept { return {&ring,SinkEntry}; }
ReportSinkV3 ReportRingSink(ReportRingV3& ring) noexcept { return {&ring,SinkEntryV3}; }
} // namespace rs2fix::reporting
