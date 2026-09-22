#include "companion/steam_reporting_records.h"
#include <Windows.h>
#include <cstring>
#include <limits>

namespace rs2fix::reporting {
namespace {
bool ValidHeader(const ReportHeader& header) noexcept {
    return header.sequence==0 && header.kind>=static_cast<std::uint32_t>(RecordKind::State) &&
        header.kind<static_cast<std::uint32_t>(RecordKind::Count) && header.reason<kReasonCount;
}
void CanonicalRecord(const ReportRecord& in, std::uint64_t sequence,
    std::uint32_t owner, ReportRecord& out) noexcept {
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
    case RecordKind::Count: break; // Rejected before canonicalization.
    }
}
ReportWriteResult Admission(StatusWire& status) noexcept {
    if (ReadStatusWord(status.stopping)) return ReportWriteResult::Stopping;
    if (StatusRevoked(status)) return ReadStatusWord(status.stopping) ?
        ReportWriteResult::Stopping : ReportWriteResult::Revoked;
    return ReportWriteResult::Accepted;
}
ReportWriteResult WriteLoss(StatusWire& status, Reason reason) noexcept {
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
} // namespace

bool InitializeReportRing(ReportRing& ring, StatusWire& status,
    std::uint32_t ownerThreadId) noexcept {
    if (ReadStatusWord(ring.ready)!=0 || !ownerThreadId) return false;
    if (GetCurrentThreadId()!=ownerThreadId) { RevokeStatus(status,Reason::ForeignThread); return false; }
    ring.status=&status; ring.ownerThreadId=ownerThreadId; ring.reserved=0;
    std::memset(ring.slots,0,sizeof(ring.slots));
    StoreStatusWord(ring.reportWriteSequence,0); StoreStatusWord(ring.reportReadSequence,0);
    StoreStatusWord(ring.ready,1);
    return true;
}

ReportWriteResult EnqueueReport(ReportRing& ring, const ReportRecord& input,
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
    if (!acceptedSequence || !ValidHeader(input.header)) return WriteLoss(status,Reason::RecordLoss);
    const auto written=ReadStatusWord(ring.reportWriteSequence);
    const auto read=ReadStatusWord(ring.reportReadSequence);
    if (read>written || written-read>kReportRecordCapacity) return WriteLoss(status,Reason::RecordLoss);
    if (written==(std::numeric_limits<std::uint64_t>::max)()) return WriteLoss(status,Reason::CounterOverflow);
    if (written-read==kReportRecordCapacity) return WriteLoss(status,Reason::RecordLoss);
    ReportRecord record{};
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

ReportReadResult DequeueReport(ReportRing& ring, ReportRecord* output) noexcept {
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
        slot.header.kind>=static_cast<std::uint32_t>(RecordKind::Count) || slot.header.reason>=kReasonCount ||
        slot.header.threadId!=ring.ownerThreadId) {
        LoseStatus(status,Reason::RecordLoss); return ReportReadResult::Lost;
    }
    *output=slot;
    SecureZeroMemory(&slot,sizeof(slot));
    // Never move this before copy/scrub: producer may reuse this exact slot as
    // soon as readSequence advances. A later scrub would erase a new record.
    StoreStatusWord(ring.reportReadSequence,read+1);
    return ReportReadResult::Record;
}

ReportSink ReportRingSink(ReportRing& ring) noexcept { return {&ring,SinkEntry}; }
} // namespace rs2fix::reporting
