#include "companion/steam_reporting_records.h"
#include "test_framework.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <thread>

namespace rs2fix::testcases {
namespace {
using namespace reporting;
struct Fixture {
    StatusWire status{};
    ReportRing ring{};
    Fixture() { RS2_CHECK(InitializeReportRing(ring,status,GetCurrentThreadId())); }
};
ReportRecord StateRecord(std::uint64_t value) {
    ReportRecord record{};
    record.header.qpc=value+100;
    record.header.sourceEpoch=3; record.header.bindingEpoch=4;
    record.header.kind=static_cast<std::uint32_t>(RecordKind::State);
    record.header.threadId=0xFFFFFFFFU; // The queue, not this field, identifies its producer.
    record.payload.state.phase=static_cast<std::uint64_t>(ReportPhase::Observing);
    record.payload.state.requestSequence=value;
    record.payload.state.pi=65; record.payload.state.bots=24; record.payload.state.maximum=64;
    return record;
}
template<class T> bool AllZero(const T& object) {
    const auto* bytes=reinterpret_cast<const std::uint8_t*>(&object);
    for (std::size_t i=0; i<sizeof(object); ++i) if (bytes[i]) return false;
    return true;
}
bool HasLoss(const StatusWire& status, Reason reason) {
    const auto mask=std::uint64_t{1}<<static_cast<std::uint32_t>(reason);
    return (ReadStatusWord(status.lossReasons)&mask)!=0 &&
        (ReadStatusWord(status.revokeReasons)&mask)!=0;
}

void CanonicalVariantsAndSink() {
    Fixture f;
    auto input=StateRecord(11);
    input.payload.state.clientQualificationMs=237;
    input.payload.state.nativeTaskState=3;
    input.payload.state.nativeScheduleValid=1;
    input.payload.state.nativeScheduleAnchorBits=0x8000000000000000ULL;
    input.payload.state.nativeErrorsBits=0x80000000ULL;
    input.payload.state.nativeThrottlesBits=UINT32_MAX;
    input.payload.state.nativeExpedite=255;
    input.payload.state.nativeRetryLimit=3;
    input.payload.state.nativeIntervalUnits=30000;
    input.payload.state.nativeIntervalOverrideBits=UINT64_MAX;
    input.payload.state.nativeRetryOverrideBits=0x8000000000000000ULL;
    input.payload.state.nativeDelayUnits=0; input.payload.state.nativeTier=0;
    for (auto& word:input.payload.state.reserved) word=UINT64_MAX;
    auto sink=ReportRingSink(f.ring);
    std::uint64_t accepted{};
    RS2_CHECK(sink.publish(sink.context,input,&accepted) && accepted==1);
    ReportRecord output{};
    RS2_CHECK(DequeueReport(f.ring,&output)==ReportReadResult::Record);
    RS2_CHECK(output.header.sequence==accepted && output.header.threadId==GetCurrentThreadId());
    RS2_CHECK(output.header.qpc==111 && output.payload.state.requestSequence==11);
    RS2_CHECK(output.payload.state.pi==65 && output.payload.state.maximum==64);
    RS2_CHECK(output.payload.state.clientQualificationMs==237);
    RS2_CHECK(output.payload.state.nativeTaskState==3 && output.payload.state.nativeScheduleValid==1);
    RS2_CHECK(output.payload.state.nativeScheduleAnchorBits==0x8000000000000000ULL);
    RS2_CHECK(output.payload.state.nativeErrorsBits==0x80000000ULL && output.payload.state.nativeThrottlesBits==UINT32_MAX);
    RS2_CHECK(output.payload.state.nativeExpedite==255 && output.payload.state.nativeRetryLimit==3 &&
        output.payload.state.nativeIntervalUnits==30000);
    RS2_CHECK(output.payload.state.nativeIntervalOverrideBits==UINT64_MAX &&
        output.payload.state.nativeRetryOverrideBits==0x8000000000000000ULL);
    RS2_CHECK(output.payload.state.nativeDelayUnits==0 && output.payload.state.nativeTier==0);
    RS2_CHECK(AllZero(output.payload.state.reserved));
    RS2_CHECK(AllZero(f.ring.slots[0]));

    for (const auto kind:{RecordKind::Request,RecordKind::Witness}) {
        input={}; input.header.kind=static_cast<std::uint32_t>(kind);
        input.payload.request.requestSequence=20; input.payload.request.witnessSequence=19;
        input.payload.request.stagedQpc=100; input.payload.request.previousSampleQpc=105;
        input.payload.request.observedQpc=110; input.payload.request.freshSinceQpc=105;
        input.payload.request.sourceAgeTicks=5; input.payload.request.worldBots=24;
        for (auto& word:input.payload.request.reserved) word=UINT64_MAX;
        RS2_CHECK(EnqueueReport(f.ring,input,&accepted)==ReportWriteResult::Accepted);
        RS2_CHECK(DequeueReport(f.ring,&output)==ReportReadResult::Record);
        RS2_CHECK(output.header.sequence==accepted && output.header.kind==static_cast<std::uint32_t>(kind));
        RS2_CHECK(output.payload.request.freshSinceQpc==105 && output.payload.request.worldBots==24);
        RS2_CHECK(AllZero(output.payload.request.reserved));
    }
    for (const auto kind:{RecordKind::BuilderEnter,RecordKind::BuilderReturn,RecordKind::BuilderUnwind}) {
        input={}; input.header.kind=static_cast<std::uint32_t>(kind);
        input.payload.builder.buildSequence=31; input.payload.builder.witnessSequence=19;
        input.payload.builder.entryQpc=200; input.payload.builder.returnQpc=220;
        input.payload.builder.probeElapsedTicks=2; input.payload.builder.classificationElapsedTicks=1;
        input.payload.builder.originalElapsedTicks=18;
        input.payload.builder.selected=1; input.payload.builder.result=1;
        for (auto& word:input.payload.builder.reserved) word=UINT64_MAX;
        RS2_CHECK(EnqueueReport(f.ring,input,&accepted)==ReportWriteResult::Accepted);
        RS2_CHECK(DequeueReport(f.ring,&output)==ReportReadResult::Record);
        RS2_CHECK(output.header.sequence==accepted && output.payload.builder.buildSequence==31);
        RS2_CHECK(output.payload.builder.probeElapsedTicks==2 && output.payload.builder.classificationElapsedTicks==1);
        RS2_CHECK(output.payload.builder.originalElapsedTicks==18 && output.payload.builder.selected==1);
        RS2_CHECK(AllZero(output.payload.builder.reserved));
    }
    input={}; input.header.kind=static_cast<std::uint32_t>(RecordKind::Anchor);
    input.payload.anchor.normalAttempts=40; input.payload.anchor.selectedTrue=30;
    input.payload.anchor.witnessSequence=8; input.payload.anchor.distinctSelectedWitnesses=3;
    for (std::size_t i=0; i<kStatusDurationClasses; ++i) {
        auto& duration=input.payload.anchor.durations[i];
        duration.calls=i+2; duration.elapsedTicks=i+10; duration.maximumTicks=i+5;
        duration.overFiveMilliseconds=i;
    }
    RS2_CHECK(EnqueueReport(f.ring,input,&accepted)==ReportWriteResult::Accepted && accepted==7);
    RS2_CHECK(DequeueReport(f.ring,&output)==ReportReadResult::Record);
    RS2_CHECK(output.payload.anchor.normalAttempts==40 && output.payload.anchor.selectedTrue==30);
    RS2_CHECK(output.payload.anchor.witnessSequence==8 && output.payload.anchor.durations[3].elapsedTicks==13);
    // Diagnostic validity is independent of native task-state knowledge. A
    // cleared/invalid snapshot never republishes residual raw bits from input.
    for (const auto validity:{0ULL,2ULL}) {
        input=StateRecord(12); auto& schedule=input.payload.state;
        schedule.nativeTaskState=3; schedule.nativeScheduleValid=validity;
        schedule.nativeScheduleAnchorBits=UINT64_MAX; schedule.nativeErrorsBits=UINT32_MAX;
        schedule.nativeThrottlesBits=UINT32_MAX; schedule.nativeExpedite=255;
        schedule.nativeRetryLimit=3; schedule.nativeIntervalUnits=30000;
        schedule.nativeIntervalOverrideBits=UINT64_MAX; schedule.nativeRetryOverrideBits=UINT64_MAX;
        schedule.nativeDelayUnits=1800000; schedule.nativeTier=6;
        for (auto& word:schedule.reserved) word=UINT64_MAX;
        RS2_CHECK(EnqueueReport(f.ring,input,&accepted)==ReportWriteResult::Accepted);
        RS2_CHECK(DequeueReport(f.ring,&output)==ReportReadResult::Record);
        const auto& got=output.payload.state;
        RS2_CHECK(got.nativeTaskState==3 && got.nativeScheduleValid==0 && got.nativeScheduleAnchorBits==0);
        RS2_CHECK(got.nativeErrorsBits==0 && got.nativeThrottlesBits==0 && got.nativeExpedite==0);
        RS2_CHECK(got.nativeRetryLimit==0 && got.nativeIntervalUnits==0 && got.nativeIntervalOverrideBits==0);
        RS2_CHECK(got.nativeRetryOverrideBits==0 && got.nativeDelayUnits==0 && got.nativeTier==0);
        RS2_CHECK(AllZero(got.reserved));
    }
    input=StateRecord(13); input.payload.state.nativeTaskState=2;
    input.payload.state.nativeScheduleValid=1; input.payload.state.nativeScheduleAnchorBits=1000;
    input.payload.state.nativeErrorsBits=12; input.payload.state.nativeRetryLimit=3;
    input.payload.state.nativeIntervalUnits=30000; input.payload.state.nativeDelayUnits=30000;
    input.payload.state.nativeTier=1; // State 2 is ordinary poll despite the error counter.
    RS2_CHECK(EnqueueReport(f.ring,input,&accepted)==ReportWriteResult::Accepted);
    RS2_CHECK(DequeueReport(f.ring,&output)==ReportReadResult::Record);
    RS2_CHECK(output.payload.state.nativeDelayUnits==30000 && output.payload.state.nativeTier==1);
    RS2_CHECK(AllZero(f.status.owner)); // Neither queue endpoint publishes owner payload words.
}

void CapacityLossAndDrain() {
    Fixture f;
    std::uint64_t accepted{};
    for (std::size_t i=0; i<kReportRecordCapacity; ++i) {
        const auto record=StateRecord(i);
        RS2_CHECK(EnqueueReport(f.ring,record,&accepted)==ReportWriteResult::Accepted && accepted==i+1);
    }
    const auto extra=StateRecord(999);
    RS2_CHECK(EnqueueReport(f.ring,extra,&accepted)==ReportWriteResult::Lost && accepted==0);
    RS2_CHECK(HasLoss(f.status,Reason::RecordLoss));
    StopStatus(f.status,77);
    RS2_CHECK(EnqueueReport(f.ring,extra,&accepted)==ReportWriteResult::Stopping && accepted==0);
    RS2_CHECK(HasLoss(f.status,Reason::RecordLoss)); // Later stop never clears actual publication loss.
    ReportRecord output{};
    for (std::size_t i=0; i<kReportRecordCapacity; ++i) {
        RS2_CHECK(DequeueReport(f.ring,&output)==ReportReadResult::Record);
        RS2_CHECK(output.header.sequence==i+1 && output.payload.state.requestSequence==i);
    }
    RS2_CHECK(DequeueReport(f.ring,&output)==ReportReadResult::Empty);
    RS2_CHECK(AllZero(f.ring.slots));
}

void ScrubBeforeReuse() {
    Fixture f;
    std::uint64_t accepted{};
    for (std::size_t i=0; i<kReportRecordCapacity; ++i)
        RS2_CHECK(EnqueueReport(f.ring,StateRecord(i+1),&accepted)==ReportWriteResult::Accepted);
    ReportRecord output{};
    for (std::uint64_t expected=1; expected<=1024; ++expected) {
        RS2_CHECK(DequeueReport(f.ring,&output)==ReportReadResult::Record);
        RS2_CHECK(output.header.sequence==expected && output.payload.state.requestSequence==expected);
        const auto slot=(expected-1)%kReportRecordCapacity;
        RS2_CHECK(AllZero(f.ring.slots[slot]));
        RS2_CHECK(EnqueueReport(f.ring,StateRecord(expected+kReportRecordCapacity),&accepted)==ReportWriteResult::Accepted);
        RS2_CHECK(accepted==expected+kReportRecordCapacity && f.ring.slots[slot].header.sequence==accepted);
    }
    RS2_CHECK(ReadStatusWord(f.status.lossReasons)==0);
}

void OverflowAndInvalidSequence() {
    {
        Fixture f;
        const auto maximum=(std::numeric_limits<std::uint64_t>::max)();
        StoreStatusWord(f.ring.reportWriteSequence,maximum-1);
        StoreStatusWord(f.ring.reportReadSequence,maximum-1);
        std::uint64_t accepted{}; ReportRecord output{};
        RS2_CHECK(EnqueueReport(f.ring,StateRecord(1),&accepted)==ReportWriteResult::Accepted && accepted==maximum);
        RS2_CHECK(DequeueReport(f.ring,&output)==ReportReadResult::Record && output.header.sequence==maximum);
        RS2_CHECK(EnqueueReport(f.ring,StateRecord(2),&accepted)==ReportWriteResult::Lost && accepted==0);
        RS2_CHECK(HasLoss(f.status,Reason::CounterOverflow));
        RS2_CHECK(ReadStatusWord(f.ring.reportWriteSequence)==maximum);
    }
    {
        Fixture f; std::uint64_t accepted{};
        auto record=StateRecord(1); record.header.sequence=1;
        RS2_CHECK(EnqueueReport(f.ring,record,&accepted)==ReportWriteResult::Lost && accepted==0);
        RS2_CHECK(HasLoss(f.status,Reason::RecordLoss) && ReadStatusWord(f.ring.reportWriteSequence)==0);
    }
    {
        Fixture f; std::uint64_t accepted{}; ReportRecord output{};
        RS2_CHECK(EnqueueReport(f.ring,StateRecord(1),&accepted)==ReportWriteResult::Accepted);
        f.ring.slots[0].header.sequence=2; // Inert corruption; no concurrent endpoint.
        RS2_CHECK(DequeueReport(f.ring,&output)==ReportReadResult::Lost);
        RS2_CHECK(HasLoss(f.status,Reason::RecordLoss) && ReadStatusWord(f.ring.reportReadSequence)==0);
        RS2_CHECK(AllZero(output));
    }
    {
        Fixture f; std::uint64_t accepted{};
        StoreStatusWord(f.ring.reportReadSequence,1);
        RS2_CHECK(EnqueueReport(f.ring,StateRecord(1),&accepted)==ReportWriteResult::Lost);
        RS2_CHECK(HasLoss(f.status,Reason::RecordLoss) && AllZero(f.ring.slots));
    }
    {
        Fixture f; std::uint64_t accepted{};
        auto record=StateRecord(1); record.header.kind=static_cast<std::uint32_t>(RecordKind::Count);
        RS2_CHECK(EnqueueReport(f.ring,record,&accepted)==ReportWriteResult::Lost);
        RS2_CHECK(HasLoss(f.status,Reason::RecordLoss));
    }
}

void ForeignAndNormalStop() {
    {
        Fixture f; std::uint64_t accepted{};
        RS2_CHECK(EnqueueReport(f.ring,StateRecord(1),&accepted)==ReportWriteResult::Accepted);
        ReportWriteResult foreignResult{}; std::uint64_t foreignSequence=999;
        std::thread foreign([&] {
            auto record=StateRecord(2); record.header.threadId=f.ring.ownerThreadId;
            foreignResult=EnqueueReport(f.ring,record,&foreignSequence);
        });
        foreign.join();
        RS2_CHECK(foreignResult==ReportWriteResult::Revoked && foreignSequence==0);
        RS2_CHECK(ReadStatusWord(f.ring.reportWriteSequence)==1 && f.ring.slots[0].header.sequence==1);
        RS2_CHECK(ReadStatusWord(f.status.lossReasons)==0);
        RS2_CHECK((ReadStatusWord(f.status.revokeReasons)&(1ULL<<static_cast<unsigned>(Reason::ForeignThread)))!=0);
        ReportRecord output{};
        RS2_CHECK(DequeueReport(f.ring,&output)==ReportReadResult::Record); // Fault does not strand prior evidence.
    }
    {
        Fixture f; std::uint64_t accepted{};
        RS2_CHECK(EnqueueReport(f.ring,StateRecord(1),&accepted)==ReportWriteResult::Accepted);
        StopStatus(f.status,77);
        auto invalid=StateRecord(2); invalid.header.sequence=100;
        RS2_CHECK(EnqueueReport(f.ring,invalid,&accepted)==ReportWriteResult::Stopping && accepted==0);
        RS2_CHECK(ReadStatusWord(f.status.lossReasons)==0 && ReadStatusWord(f.status.revokeReasons)==0);
        ReportRecord output{};
        RS2_CHECK(DequeueReport(f.ring,&output)==ReportReadResult::Record && output.header.sequence==1);
        RS2_CHECK(DequeueReport(f.ring,&output)==ReportReadResult::Empty);
    }
}

void ConcurrentSpscOrdering() {
    StatusWire status{}; ReportRing ring{};
    constexpr std::uint64_t count=50000;
    std::atomic<bool> ready{false},done{false},abort{false};
    std::uint64_t consumed{};
    std::thread producer([&] {
        if (!InitializeReportRing(ring,status,GetCurrentThreadId())) abort.store(true);
        ready.store(true,std::memory_order_release);
        for (std::uint64_t i=1; i<=count && !abort.load(); ++i) {
            // Fixture pacing only: product never spins/waits when full.
            while (ReadStatusWord(ring.reportWriteSequence)-ReadStatusWord(ring.reportReadSequence)>=kReportRecordCapacity && !abort.load())
                std::this_thread::yield();
            if (abort.load()) break;
            std::uint64_t accepted{};
            if (EnqueueReport(ring,StateRecord(i),&accepted)!=ReportWriteResult::Accepted || accepted!=i)
                abort.store(true);
        }
        done.store(true,std::memory_order_release);
    });
    std::thread consumer([&] {
        while (!ready.load(std::memory_order_acquire)) std::this_thread::yield();
        while (consumed<count && !abort.load()) {
            ReportRecord output{};
            const auto result=DequeueReport(ring,&output);
            if (result==ReportReadResult::Record) {
                ++consumed;
                if (output.header.sequence!=consumed || output.payload.state.requestSequence!=consumed ||
                    output.header.qpc!=consumed+100 || output.payload.state.pi!=65 ||
                    !AllZero(output.payload.state.reserved)) abort.store(true);
            } else if (result!=ReportReadResult::Empty ||
                (done.load(std::memory_order_acquire) &&
                    ReadStatusWord(ring.reportReadSequence)==ReadStatusWord(ring.reportWriteSequence))) {
                abort.store(true);
            } else std::this_thread::yield();
        }
    });
    producer.join(); consumer.join();
    RS2_CHECK(!abort.load() && consumed==count);
    RS2_CHECK(ReadStatusWord(ring.reportReadSequence)==count && ReadStatusWord(ring.reportWriteSequence)==count);
    RS2_CHECK(ReadStatusWord(status.lossReasons)==0 && ReadStatusWord(status.revokeReasons)==0);
    RS2_CHECK(AllZero(ring.slots));
}
} // namespace
void ReportingRecordTests() {
    CanonicalVariantsAndSink(); CapacityLossAndDrain(); ScrubBeforeReuse();
    OverflowAndInvalidSequence(); ForeignAndNormalStop(); ConcurrentSpscOrdering();
}
} // namespace rs2fix::testcases
