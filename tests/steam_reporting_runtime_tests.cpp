#include "companion/steam_reporting_runtime.h"
#include "test_framework.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <initializer_list>
#include <string>
#include <thread>
#include <vector>

namespace rs2fix::testcases {
namespace {
using namespace reporting;
namespace obs=observer;
constexpr std::uint64_t kIdle=1ULL<<32;
constexpr std::uint32_t kHolder=(43U<<16)|17U;
constexpr std::uint32_t kSlot=3;
volatile LONG qualificationCalls{};
void InertPump() {} // Addresses only; no test calls a forwarding original.
bool InertWrapper(void*) { return true; }
ClientQualification QualifiedClient() noexcept {
    InterlockedIncrement(&qualificationCalls);
    ClientQualification result{};
    result.referenceAcquired=true; result.referenceReleased=true;
    return result;
}
struct Fixture {
    enum class Crossing { None, Stopping, UnknownLifecycle, ChangedLifecycle, DisabledGate };
    // Actual owned addresses are essential: runtime staging/CAS intentionally
    // write these buffers, while MemoryOps supplies a synthetic PE description.
    // The declared executable section is DATA here and is never executed.
    std::vector<unsigned char> image=std::vector<unsigned char>(0x10000);
    std::vector<unsigned char> heap=std::vector<unsigned char>(0x10000);
    StatusWire status{};
    ReportRing ring{};
    obs::DispatchState dispatch{};
    Runtime runtime{};
    SourceLayout source{0x3100,0x3108,0x3110,0x3118};
    PreparedLayout prepared{0x3200,0x3208,0x3228,0x3248,0x3250,0x3270,0x3280};
    TaskLayout task{0x4000,0x3000,0x3004,0x3008,0x3028,0x2120,0x1000,0x3200};
    std::uint32_t holder{kHolder};
    std::int64_t frequency{};
    std::uint64_t reads{};
    volatile LONG readyNotices{},disabledNotices{},lastNoticeReason{};
    bool forbiddenRead{};
    Crossing crossing{};
    bool crossOnQuery{}, crossed{};
    std::uintptr_t crossingAddress{};
    std::uint64_t tableReadsAfterCross{}, tableQueriesAfterCross{};
    bool replaceAfterCandidate{}, candidateReplaced{};
    unsigned candidateScheduleReads{};

    void Cross() noexcept {
        const auto value=crossing;
        crossing=Crossing::None; crossed=true;
        if (value==Crossing::Stopping) StopStatus(status,1);
        else if (value==Crossing::UnknownLifecycle) InterlockedExchange(&dispatch.unknownLifecycle,1);
        else if (value==Crossing::ChangedLifecycle) InterlockedIncrement64(&dispatch.lifecycle);
        else if (value==Crossing::DisabledGate) InterlockedExchange(&dispatch.gate,static_cast<LONG>(obs::Gate::Disabled));
    }

    std::uintptr_t Base() const { return reinterpret_cast<std::uintptr_t>(image.data()); }
    std::uintptr_t Heap(std::size_t offset=0) const { return reinterpret_cast<std::uintptr_t>(heap.data()+offset); }
    std::uintptr_t Slot() const { return Base()+task.poolRva+kSlot*0x78; }
    std::uintptr_t Original() const { return Base()+task.builderRva; }
    std::uintptr_t Wrapper() const { return reinterpret_cast<std::uintptr_t>(&InertWrapper); }
    static bool Contains(std::uintptr_t base,std::size_t size,std::uintptr_t address,std::size_t bytes=1) {
        return address>=base && address-base<=size && bytes<=size-(address-base);
    }
    template<class T> void Put(std::uintptr_t address,const T& value) {
        RS2_CHECK(Contains(Base(),image.size(),address,sizeof(T)) || Contains(Heap(),heap.size(),address,sizeof(T)));
        std::memcpy(reinterpret_cast<void*>(address),&value,sizeof(value));
    }
    template<class T> T Get(std::uintptr_t address) const {
        T value{}; std::memcpy(&value,reinterpret_cast<const void*>(address),sizeof(value)); return value;
    }
    explicit Fixture(Mode mode=Mode::Repair) {
        RS2_CHECK(((Base()|Heap())&7)==0);
        IMAGE_DOS_HEADER dos{}; dos.e_magic=IMAGE_DOS_SIGNATURE; dos.e_lfanew=0x80;
        Put(Base(),dos);
        IMAGE_NT_HEADERS64 nt{};
        nt.Signature=IMAGE_NT_SIGNATURE; nt.FileHeader.Machine=IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections=3; nt.FileHeader.Characteristics=IMAGE_FILE_EXECUTABLE_IMAGE;
        nt.FileHeader.SizeOfOptionalHeader=sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.OptionalHeader.Magic=IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.SizeOfImage=static_cast<DWORD>(image.size()); nt.OptionalHeader.SizeOfHeaders=0x400;
        nt.OptionalHeader.NumberOfRvaAndSizes=IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        Put(Base()+0x80,nt);
        for (unsigned i=0;i<3;++i) {
            IMAGE_SECTION_HEADER section{};
            section.VirtualAddress=(i+1)*0x1000; section.Misc.VirtualSize=i==2 ? 0xD000 : 0x1000;
            section.Characteristics=IMAGE_SCN_MEM_READ |
                (i==0 ? IMAGE_SCN_MEM_EXECUTE : i==2 ? IMAGE_SCN_MEM_WRITE : 0);
            Put(Base()+0x80+sizeof(nt)+i*sizeof(section),section);
        }
        Put(Base()+0x2000,Original());
        for (const auto offset:{0U,0x1000U,0x3000U,0x4000U,0x5000U,0x5100U})
            Put(Heap(offset),Base()+0x2000);
        Put(Base()+source.world,Heap()); Put(Base()+source.worldInfoClass,Heap(0x5100));
        Put(Heap()+0x80,Heap(0x1000));
        Put(Heap(0x1000)+0x60,Heap(0x2000));
        Put(Heap(0x1000)+0x68,std::int32_t{64}); Put(Heap(0x1000)+0x6C,std::int32_t{128});
        Put(Heap(0x2000),Heap(0x3000));
        Put(Heap(0x3000)+0x50,Heap(0x5000)); Put(Heap(0x5000)+0x78,Heap(0x5100));
        Put(Heap(0x3000)+0x5CC,Heap(0x4000));
        Put(Heap(0x3000)+0x398,std::uint32_t{0x100});
        Put(Heap(0x3000)+0x598,std::uint8_t{1}); Put(Heap(0x3000)+0x4FC,1000.0F);
        Put(Heap(0x4000)+0x2E4,std::int32_t{64});
        Put(Heap(0x4000)+0x2EC,std::int32_t{40}); Put(Heap(0x4000)+0x2F0,std::int32_t{24});
        Put(Base()+source.publicWrapper,Heap(0x6000)); Put(Base()+source.privateWrapper,Heap(0x6000));
        Put(Heap(0x6000),Heap(0xC000));
        Put(Heap(0x6000)+0x94,std::uint32_t{24}); Put(Heap(0x6000)+0x98,std::uint32_t{65});
        Put(Heap(0x6000)+0x9C,std::uint32_t{64}); Put(Heap(0x6000)+0xA4,12.0F);
        Put(Base()+prepared.service,std::uint32_t{3});
        Put(Base()+prepared.registration+0x10,std::uint64_t{8});
        Put(Base()+prepared.registration+0x18,std::uint64_t{15});
        Put(Base()+prepared.maximum,std::uint32_t{64});
        Put(Base()+prepared.members,Heap(0x9000)); Put(Base()+prepared.members+8,Heap(0x9000)+65*0x20);
        Put(Base()+prepared.members+16,Heap(0xA000));
        Put(Base()+prepared.publicIp,Heap(0x7000));
        Put(Base()+prepared.publicIp+8,std::int32_t{10}); Put(Base()+prepared.publicIp+12,std::int32_t{16});
        SetJson();
        Put(Heap(0xB000),Base()+task.metadataVtableRva);
        Put(Base()+task.registryRva,Heap(0xB000));
        Put(Base()+task.invalidIdRva,std::uint32_t{0});
        SetTask(5,9);
        LARGE_INTEGER clock{}; RS2_CHECK(QueryPerformanceFrequency(&clock) && clock.QuadPart>0);
        frequency=clock.QuadPart;
        StatusHeader header{}; header.validity=CompleteHeaderIdentity;
        header.configuredMode=static_cast<std::uint32_t>(mode);
        header.qpcFrequency=static_cast<std::uint64_t>(frequency);
        header.pid=GetCurrentProcessId(); header.runId[0]=1;
        RS2_CHECK(InitializeStatus(status,header,{}));
        RS2_CHECK(InitializeReportRing(ring,status,GetCurrentThreadId()));
        obs::InitializeDispatch(dispatch,{},{});
        dispatch.bindingCount=1; dispatch.bindings[0].accepted=true;
        dispatch.bindings[0].proxy.real=reinterpret_cast<void*>(Heap(0xC000));
        dispatch.bindings[0].proxy.owner=&dispatch;
        dispatch.bindings[0].proxy.bindingId=1; dispatch.bindings[0].proxy.bindingSequence=1;
        InterlockedExchange(&dispatch.gate,static_cast<LONG>(obs::Gate::Armed));
        RuntimeConfig config{};
        config.mode=mode; config.ownerThreadId=GetCurrentThreadId(); config.hostBase=Base();
        config.hostSize=static_cast<std::uint32_t>(image.size()); config.memory={this,Query,Read};
        config.dispatch=&dispatch; config.status=&status; config.sink=ReportRingSink(ring);
        config.pumpOriginal=InertPump; config.builderOriginal=reinterpret_cast<BuilderFn>(Original());
        config.builderWrapper=Wrapper(); config.source=source; config.prepared=prepared; config.task=task;
        config.noticeContext=this; config.notice=Notice; config.qualifyClient=QualifiedClient;
        RS2_CHECK(InitializeRuntime(runtime,config,frequency)==Reason::None);
    }
    void SetTask(std::uint32_t id,std::uint32_t counter) {
        std::memset(reinterpret_cast<void*>(Slot()),0,0x78);
        Put(Slot(),std::uint32_t{2}); Put(Slot()+4,id); Put(Slot()+8,Base()+0x3300);
        Put(Slot()+0x38,kHolder); Put(Slot()+0x40,Original()); Put(Slot()+0x60,std::uint64_t{30000});
        Put(Base()+task.selectedIdRva,id); Put(Base()+task.counterRva,counter);
    }
    void SetJson(unsigned count=65) {
        const auto json=std::string("{\"op\":[{\"k\":\"PI_COUNT\",\"v\":\"")+std::to_string(count)+
            "\"},{\"k\":\"BotPlayerCount\",\"v\":\"24\"},{\"k\":\"MaxPlayerCount\",\"v\":\"64\"}]}";
        std::memcpy(reinterpret_cast<void*>(Heap(0x8000)),json.c_str(),json.size()+1);
        Put(Base()+prepared.gameMode,Heap(0x8000));
        Put(Base()+prepared.gameMode+0x10,static_cast<std::uint64_t>(json.size()));
        Put(Base()+prepared.gameMode+0x18,std::uint64_t{4096});
    }
    static bool Query(void* context,std::uintptr_t address,MemoryRegion* out,DWORD* error) noexcept {
        auto& f=*static_cast<Fixture*>(context); *error=ERROR_SUCCESS;
        if (f.crossed && Contains(f.Base()+f.task.poolRva,128*0x78,address)) ++f.tableQueriesAfterCross;
        if (f.crossOnQuery && f.crossing!=Crossing::None && address==f.crossingAddress) f.Cross();
        if (Contains(f.Base(),f.image.size(),address)) {
            const auto rva=address-f.Base();
            const auto start=rva<0x3000 ? rva&~std::uintptr_t{0xFFF} : std::uintptr_t{0x3000};
            const DWORD protection=rva<0x1000 ? PAGE_READONLY : rva<0x2000 ? PAGE_EXECUTE_READ :
                rva<0x3000 ? PAGE_READONLY : PAGE_READWRITE;
            *out={f.Base()+start,f.Base(),start==0x3000 ? 0xD000U : 0x1000U,MEM_COMMIT,MEM_IMAGE,protection};
            return true;
        }
        if (Contains(f.Heap(),f.heap.size(),address)) {
            *out={f.Heap(),f.Heap(),f.heap.size(),MEM_COMMIT,MEM_PRIVATE,PAGE_READWRITE}; return true;
        }
        const auto holder=reinterpret_cast<std::uintptr_t>(&f.holder);
        if (Contains(holder,sizeof(f.holder),address)) {
            *out={holder,holder,sizeof(f.holder),MEM_COMMIT,MEM_PRIVATE,PAGE_READWRITE}; return true;
        }
        *error=ERROR_NOACCESS; return false;
    }
    static bool Read(void* context,std::uintptr_t address,void* output,std::size_t bytes,DWORD* error) noexcept {
        auto& f=*static_cast<Fixture*>(context); ++f.reads;
        if (f.crossed && Contains(f.Base()+f.task.poolRva,128*0x78,address)) ++f.tableReadsAfterCross;
        // The real readers must not copy identities/member elements or other
        // actors. Public-IP access is limited to its terminating UTF-16 NUL.
        if (Contains(f.Heap(0x2000)+8,0x1000-8,address) || Contains(f.Heap(0x9000),0x1000,address) ||
            (Contains(f.Heap(0x7000),0x1000,address) && (address!=f.Heap(0x7000)+18 || bytes!=2)) ||
            Contains(f.Base()+f.prepared.registration,16,address)) {
            f.forbiddenRead=true; *error=ERROR_ACCESS_DENIED; return false;
        }
        MemoryRegion region{};
        if (!Query(context,address,&region,error) || !Contains(region.base,region.size,address,bytes)) {
            *error=ERROR_PARTIAL_COPY; return false;
        }
        std::memcpy(output,reinterpret_cast<const void*>(address),bytes);
        if (!f.crossOnQuery && f.crossing!=Crossing::None && address==f.crossingAddress) f.Cross();
        if (f.replaceAfterCandidate && address==f.Heap(0xB000)+8 && bytes==0x18 &&
            ++f.candidateScheduleReads==2) {
            // Return the final bytes of candidate A, then model native task B
            // existing before Install's independent pre/post observations.
            f.replaceAfterCandidate=false; f.candidateReplaced=true;
            f.SetTask(10,10);
            f.Put(f.Slot(),std::uint32_t{3}); f.Put(f.Slot()+0x58,std::uint64_t{222});
            f.Put(f.Slot()+0x68,std::int32_t{12});
        }
        *error=0; return true;
    }
    static void Notice(void* context,bool ready,Reason reason) noexcept {
        auto& f=*static_cast<Fixture*>(context);
        if (ready) InterlockedIncrement(&f.readyNotices); else InterlockedIncrement(&f.disabledNotices);
        InterlockedExchange(&f.lastNoticeReason,static_cast<LONG>(reason));
    }
    std::int64_t Now() { std::int64_t now{}; RS2_CHECK(RuntimeClock(runtime,&now)); return now; }
    void Init(bool success=true) {
        const auto sink=RuntimeLifecycleSink(runtime);
        InterlockedExchange64(&dispatch.lifecycle,static_cast<LONG64>(kIdle|1));
        sink.initEntered(sink.context,kIdle|1,true);
        sink.initReturned(sink.context,kIdle|1,true,success);
        InterlockedExchange64(&dispatch.lifecycle,static_cast<LONG64>(kIdle));
        sink.initFinished(sink.context,kIdle,true,success);
    }
    void Pump() { ManagePump(runtime,CallerClass::NormalPump,Now()); }
    void Consume() {
        // Simulated native producer transition, not an execution/timing claim.
        Put(Heap(0x6000)+0xA0,std::uint8_t{0}); Put(Heap(0x6000)+0xA1,std::uint8_t{0});
        Put(Heap(0x6000)+0xA4,0.0F); Pump();
    }
    BuilderDecision Builder(CallerClass classification=CallerClass::NormalBuilder) {
        BuilderDecision decision{};
        PrepareBuilder(runtime,classification,&holder,Now(),5,&decision); return decision;
    }
    void Finish(BuilderDecision& decision,bool returned=true,bool result=true,bool selected=false) {
        // Caller-reported outcomes only. No native forwarding/dirty-byte store
        // is executed by this core fixture; the separate entry fixture owns it.
        FinishBuilder(runtime,decision,returned,result,selected,Now(),10);
    }
    bool Revoked(Reason reason) const {
        return (ReadStatusWord(status.revokeReasons)&(1ULL<<static_cast<unsigned>(reason)))!=0;
    }
    std::uint32_t CachedBots() const { return Get<std::uint32_t>(Heap(0x6000)+0x94); }
    std::uint8_t Requested() const { return Get<std::uint8_t>(Heap(0x6000)+0xA0); }
    std::uint8_t Dirty() const { return Get<std::uint8_t>(Base()+prepared.fullDirty); }
};

void ObserveAndKnownSpin() {
    Fixture f(Mode::Observe); f.Init();
    std::array<unsigned char,0x100> before{};
    std::memcpy(before.data(),reinterpret_cast<const void*>(f.Heap(0x6000)),before.size());
    f.Pump();
    RS2_CHECK(f.runtime.sdkReady && f.runtime.sourceReady && ReadTaskPhase(f.runtime.task)==TaskPhase::Armed);
    RS2_CHECK(f.Get<std::uintptr_t>(f.Slot()+0x40)==f.Wrapper());
    auto decision=f.Builder();
    RS2_CHECK(decision.attempted && !decision.eligible && decision.dirtyAddress==0);
    RS2_CHECK(decision.event.header.reason==static_cast<unsigned>(Reason::None));
    RS2_CHECK(decision.event.payload.builder.pi==65 && decision.event.payload.builder.maximum==64);
    f.Finish(decision);
    RS2_CHECK(std::memcmp(before.data(),reinterpret_cast<const void*>(f.Heap(0x6000)),before.size())==0 && f.Dirty()==0);
    RS2_CHECK(f.runtime.producer.requestSequence==0 && !f.runtime.producer.pending.active && !f.runtime.producer.fresh.valid);
    RS2_CHECK(f.runtime.counters.normalReturns==1 && f.runtime.counters.fullSelected==0 && !StatusRevoked(f.status));
    const auto reads=f.reads;
    decision=f.Builder(CallerClass::KnownSpin);
    RS2_CHECK(!decision.attempted && !decision.eligible && f.reads==reads && !StatusRevoked(f.status));
    RS2_CHECK(f.runtime.counters.reasons[static_cast<unsigned>(Reason::KnownSpin)]==1 && !f.forbiddenRead);
}
void InstalledSnapshotOwnsDiagnostics() {
    Fixture f(Mode::Observe); f.Init();
    f.Put(f.Heap(0xB000)+0x0A,std::uint16_t{3});
    f.Put(f.Slot()+0x58,std::uint64_t{111});
    f.replaceAfterCandidate=true;
    f.Pump();
    RS2_CHECK(f.candidateReplaced && ReadTaskPhase(f.runtime.task)==TaskPhase::Armed);
    RS2_CHECK(f.runtime.task.identity.id==10 && f.runtime.task.lastNativeCounter==10);
    RS2_CHECK(f.runtime.nativeTaskState==3 && f.runtime.schedule.valid &&
        f.runtime.schedule.anchorBits==222 && f.runtime.schedule.errors==12);
    RS2_CHECK(f.runtime.schedule.tier==ScheduleTier::Retry30m && f.runtime.schedule.delayUnits==1800000);
    bool boundState{};
    ReportRecord event{};
    while (DequeueReport(f.ring,&event)==ReportReadResult::Record) {
        if (event.header.kind!=static_cast<unsigned>(RecordKind::State) || !event.payload.state.bound) continue;
        boundState=true;
        RS2_CHECK(event.header.sourceEpoch==f.runtime.counters.sourceEpoch &&
            event.header.bindingEpoch==f.runtime.counters.bindingEpoch);
        RS2_CHECK(event.payload.state.nativeTaskState==3 && event.payload.state.nativeScheduleValid==1 &&
            event.payload.state.nativeScheduleAnchorBits==222 && event.payload.state.nativeErrorsBits==12 &&
            event.payload.state.nativeDelayUnits==1800000 && event.payload.state.nativeTier==6);
    }
    RS2_CHECK(boundState && !StatusRevoked(f.status) && !f.forbiddenRead);
}
void RepairWitnessAndPreparedMismatch() {
    Fixture f; f.Init(); f.Put(f.Heap(0x6000)+0x94,std::uint32_t{21}); f.Pump();
    RS2_CHECK(f.CachedBots()==24 && f.Requested()==1 && f.Dirty()==0);
    RS2_CHECK(f.runtime.producer.pending.active && f.runtime.producer.pending.previousSet &&
        f.runtime.producer.requestSequence==1 && !f.runtime.producer.fresh.valid);
    auto pending=f.Builder();
    RS2_CHECK(pending.attempted && !pending.eligible && pending.event.header.reason==static_cast<unsigned>(Reason::FreshnessExpired));
    f.Finish(pending);
    const auto lower=f.runtime.producer.pending.previousSetQpc;
    f.Consume();
    RS2_CHECK(!f.runtime.producer.pending.active && f.runtime.producer.fresh.valid &&
        f.runtime.producer.witnessSequence==1 && f.runtime.producer.fresh.lowerBoundQpc==lower);
    auto selected=f.Builder();
    RS2_CHECK(selected.attempted && selected.eligible && selected.dirtyAddress==f.Base()+f.prepared.fullDirty);
    RS2_CHECK(selected.event.payload.builder.pi==65 && selected.event.payload.builder.bots==24 &&
        selected.event.payload.builder.maximum==64 && f.Dirty()==0);
    f.Finish(selected,true,true,true);
    RS2_CHECK(f.runtime.counters.fullSelected==1 && f.runtime.counters.selectedTrue==1 &&
        f.runtime.counters.distinctSelectedWitnesses==1);
    f.SetJson(64);
    auto mismatch=f.Builder();
    RS2_CHECK(mismatch.attempted && !mismatch.eligible && mismatch.dirtyAddress==0 &&
        mismatch.event.header.reason==static_cast<unsigned>(Reason::PreparedMismatch));
    f.Finish(mismatch,true,false,false);
    RS2_CHECK(f.runtime.counters.falseReturns==1 && !StatusRevoked(f.status) && f.Dirty()==0 && !f.forbiddenRead);
    RS2_CHECK(std::all_of(f.runtime.scratch,f.runtime.scratch+sizeof(f.runtime.scratch),[](char byte) { return byte==0; }));
}
void SelectionUsesWitnessRequest() {
    Fixture f; f.Init(); f.Pump(); f.Consume();
    const auto witnessed=f.runtime.producer.fresh;
    RS2_CHECK(witnessed.valid && witnessed.request==1);
    // Represent a later staged request without a wall-clock wait. The producer
    // state tests separately cover the staging/floor transition; this regression
    // is the real builder record's linkage while that newer request is pending.
    f.runtime.producer.requestSequence=2;
    f.runtime.producer.pending={2,witnessed.sourceEpoch,witnessed.bindingEpoch,
        f.Now(),f.Now(),24,64,12.0F,true,true};
    f.Put(f.Heap(0x6000)+0xA0,std::uint8_t{1});
    auto decision=f.Builder();
    RS2_CHECK(decision.eligible && decision.event.payload.builder.pending==1);
    RS2_CHECK(decision.event.payload.builder.requestSequence==witnessed.request &&
        decision.event.payload.builder.witnessSequence==witnessed.witness && f.runtime.producer.requestSequence==2);
    f.Finish(decision,true,true,true);
    RS2_CHECK(f.runtime.counters.fullSelected==1 && !StatusRevoked(f.status));
}
void EpochInvalidationKeepsRequestFloor() {
    {
        Fixture f; f.Init(); f.Pump(); f.Consume();
        const auto floor=f.runtime.producer.lastRequestQpc;
        const auto sourceEpoch=f.runtime.counters.sourceEpoch;
        const auto bindingEpoch=f.runtime.counters.bindingEpoch;
        f.Put(f.Heap(0x3000)+0x398,std::uint32_t{0}); f.Pump();
        RS2_CHECK(!f.runtime.sourceReady && !f.runtime.producer.fresh.valid && !f.runtime.producer.pending.active);
        RS2_CHECK(f.Get<std::uintptr_t>(f.Slot()+0x40)==f.Original() && f.runtime.producer.lastRequestQpc==floor);
        f.Put(f.Heap(0x3000)+0x398,std::uint32_t{0x100});
        f.Put(f.Heap(0x6000)+0x94,std::uint32_t{21}); f.Pump();
        RS2_CHECK(f.runtime.sourceReady && f.runtime.counters.sourceEpoch>sourceEpoch &&
            f.runtime.counters.bindingEpoch>bindingEpoch && !f.runtime.producer.fresh.valid);
        RS2_CHECK(f.runtime.producer.lastRequestQpc==floor && f.runtime.producer.requestSequence==1 &&
            f.CachedBots()==21 && f.Requested()==0 && f.Dirty()==0);
        RS2_CHECK(f.runtime.counters.reasons[static_cast<unsigned>(Reason::RequestFloor)]>0 && !StatusRevoked(f.status));
    }
    {
        Fixture f; f.Init(); f.Pump(); f.Consume();
        const auto floor=f.runtime.producer.lastRequestQpc;
        const auto sourceEpoch=f.runtime.counters.sourceEpoch;
        const auto bindingEpoch=f.runtime.counters.bindingEpoch;
        f.SetTask(10,10); // Own fixture simulates a native replacement, including stock callback.
        f.Put(f.Heap(0x6000)+0x94,std::uint32_t{21}); f.Pump();
        RS2_CHECK(f.runtime.counters.sourceEpoch==sourceEpoch && f.runtime.counters.bindingEpoch>bindingEpoch);
        RS2_CHECK(f.runtime.task.identity.id==10 && !f.runtime.producer.fresh.valid && !f.runtime.producer.pending.active);
        RS2_CHECK(f.runtime.producer.lastRequestQpc==floor && f.runtime.producer.requestSequence==1 &&
            f.CachedBots()==21 && f.Requested()==0 && !StatusRevoked(f.status));
    }
}
void EvidenceLossPreventsSelection() {
    Fixture f; f.Init(); f.Pump(); f.Consume();
    ReportRecord filler{}; filler.header.kind=static_cast<std::uint32_t>(RecordKind::State);
    const auto used=ReadStatusWord(f.ring.reportWriteSequence)-ReadStatusWord(f.ring.reportReadSequence);
    for (auto i=used;i<kReportRecordCapacity;++i) {
        std::uint64_t sequence{};
        const auto result=EnqueueReport(f.ring,filler,&sequence);
        RS2_CHECK(result==ReportWriteResult::Accepted);
        if (result!=ReportWriteResult::Accepted) break;
    }
    auto decision=f.Builder(); // Required Enter fails after otherwise successful admission.
    RS2_CHECK(decision.attempted && !decision.eligible && f.Revoked(Reason::RecordLoss) && f.Dirty()==0);
    const auto reads=f.reads;
    decision=f.Builder();
    RS2_CHECK(!decision.attempted && !decision.eligible && f.reads==reads);
    RS2_CHECK(RuntimeCleanupAdmission(f.runtime));
    CleanupRevokedRuntime(f.runtime,CallerClass::KnownSpin);
    RS2_CHECK(f.Get<std::uintptr_t>(f.Slot()+0x40)==f.Wrapper() && f.reads==reads);
    CleanupRevokedRuntime(f.runtime,CallerClass::NormalPump);
    RS2_CHECK(f.Get<std::uintptr_t>(f.Slot()+0x40)==f.Original() && ReadTaskPhase(f.runtime.task)==TaskPhase::Inert);
    const auto cleanedReads=f.reads;
    CleanupRevokedRuntime(f.runtime,CallerClass::NormalPump);
    RS2_CHECK(f.reads==cleanedReads && !RuntimeCleanupAdmission(f.runtime) && f.Revoked(Reason::RecordLoss));
}
void CleanupLifecycleCrossing() {
    for (const auto crossing:{Fixture::Crossing::Stopping,Fixture::Crossing::UnknownLifecycle,
        Fixture::Crossing::ChangedLifecycle,Fixture::Crossing::DisabledGate}) {
        for (const bool query:{false,true}) {
            Fixture f; f.Init(); f.Pump();
            LoseStatus(f.status,Reason::RecordLoss);
            f.crossing=crossing; f.crossOnQuery=query; f.crossingAddress=f.Slot()+0x40;
            RS2_CHECK(RuntimeCleanupAdmission(f.runtime));
            CleanupRevokedRuntime(f.runtime,CallerClass::NormalPump);
            RS2_CHECK(f.crossed && f.Get<std::uintptr_t>(f.Slot()+0x40)==f.Wrapper());
            RS2_CHECK(!f.runtime.task.inverseAttempted && ReadTaskPhase(f.runtime.task)==TaskPhase::Inert);
            RS2_CHECK(f.tableReadsAfterCross==0 && f.tableQueriesAfterCross==0 && !RuntimeCleanupAdmission(f.runtime));
            const auto reads=f.reads;
            CleanupRevokedRuntime(f.runtime,CallerClass::NormalPump);
            RS2_CHECK(f.reads==reads && f.Revoked(Reason::RecordLoss));
        }
    }
}
void SameOwnerEntryCrossingReasons() {
    for (const auto crossing:{Fixture::Crossing::Stopping,Fixture::Crossing::UnknownLifecycle,
        Fixture::Crossing::ChangedLifecycle,Fixture::Crossing::DisabledGate}) {
        Fixture f; f.Init(); f.Pump();
        f.crossing=crossing; f.crossingAddress=f.Base()+f.source.world;
        f.Pump(); // Crossing during source observation precedes task entry.
        RS2_CHECK(f.crossed && !f.Revoked(Reason::ForeignThread));
        RS2_CHECK(f.runtime.counters.reasons[static_cast<unsigned>(Reason::ForeignThread)]==0);
        RS2_CHECK(f.runtime.counters.reasons[static_cast<unsigned>(Reason::LifecycleCrossing)]>0);
        RS2_CHECK(f.tableReadsAfterCross==0 && f.tableQueriesAfterCross==0);
        RS2_CHECK(f.Get<std::uintptr_t>(f.Slot()+0x40)==f.Wrapper());
    }
}
void LifecycleFailuresAndShutdown() {
    {
        Fixture f; const auto before=InterlockedCompareExchange(&qualificationCalls,0,0);
        f.Init(false); f.Pump();
        RS2_CHECK(f.Revoked(Reason::InitFailed) && !f.runtime.sdkReady && f.reads==0 &&
            InterlockedCompareExchange(&qualificationCalls,0,0)==before);
        RS2_CHECK(f.Get<std::uintptr_t>(f.Slot()+0x40)==f.Original() && f.Requested()==0);
    }
    {
        Fixture f; f.Init(); f.Pump();
        const auto sink=RuntimeLifecycleSink(f.runtime);
        sink.initEntered(sink.context,(2ULL<<32)|1,true);
        RS2_CHECK(f.Revoked(Reason::UnsupportedReinit) && !RuntimeAdmission(f.runtime));
    }
    {
        Fixture f; f.Init(); f.Pump();
        std::array<unsigned char,sizeof(ProducerState)> producer{};
        std::memcpy(producer.data(),&f.runtime.producer,producer.size());
        const auto counters=f.runtime.counters; const auto reads=f.reads;
        const auto now=f.Now();
        std::thread foreign([&] { ManagePump(f.runtime,CallerClass::NormalPump,now); }); foreign.join();
        RS2_CHECK(f.Revoked(Reason::ForeignThread) && f.reads==reads);
        RS2_CHECK(std::memcmp(producer.data(),&f.runtime.producer,producer.size())==0 &&
            std::memcmp(&counters,&f.runtime.counters,sizeof(counters))==0);
    }
    {
        Fixture f; f.Init(); f.Pump(); f.Consume();
        const auto callback=f.Get<std::uintptr_t>(f.Slot()+0x40); const auto reads=f.reads;
        const auto sink=RuntimeLifecycleSink(f.runtime);
        sink.shutdownEntered(sink.context,kIdle|1);
        RS2_CHECK(ReadStatusWord(f.status.stopping)==1 && ReadStatusWord(f.status.lossReasons)==0);
        RS2_CHECK(!f.runtime.sdkReady && !f.runtime.sourceReady && !f.runtime.producer.fresh.valid &&
            !f.runtime.producer.pending.active && f.reads==reads);
        RS2_CHECK(f.Get<std::uintptr_t>(f.Slot()+0x40)==callback); // No native table cleanup in lifecycle callback.
        const auto decision=f.Builder();
        RS2_CHECK(!decision.attempted && !decision.eligible && f.reads==reads);
        RS2_CHECK(ReadStatusWord(f.status.owner.phase)==static_cast<std::uint64_t>(ReportPhase::Stopping));
    }
}
} // namespace
void ReportingRuntimeTests() {
    ObserveAndKnownSpin(); InstalledSnapshotOwnsDiagnostics();
    RepairWitnessAndPreparedMismatch(); EpochInvalidationKeepsRequestFloor();
    SelectionUsesWitnessRequest();
    EvidenceLossPreventsSelection(); CleanupLifecycleCrossing(); SameOwnerEntryCrossingReasons(); LifecycleFailuresAndShutdown();
}
} // namespace rs2fix::testcases
