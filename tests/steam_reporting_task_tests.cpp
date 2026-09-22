#include "test_framework.h"
#include "companion/steam_reporting_task.h"
#include <array>
#include <cstring>
#include <limits>
#include <thread>

using namespace rs2fix::reporting;
namespace {
using rs2fix::MemoryRegion;
constexpr std::uint32_t kSlot=3;
constexpr std::uint32_t kHolder=(43u<<16)|17u;
constexpr TaskEpoch kEpoch{1,1};
bool Wrapper(void*) { return true; } // Address only; tests never execute native RVAs.

struct Fixture {
    enum class ReadMutation { None,Selected,Sentinel,CounterAdvance,CounterDecrease,
        SlotId,Holder,Component,Metadata,Vtable,Callback,Interval,State };
    enum class PartialReadLoss { None,Owner,Lifecycle,Gate,Stopping };
    alignas(8) std::array<unsigned char,0x8000> image{};
    alignas(8) std::array<unsigned char,32> metadata{};
    alignas(8) std::array<unsigned char,32> metadata2{};
    TaskLayout layout{0x2000,0x1000,0x1004,0x1008,0x1028,0x1500,0x7000,0x1020};
    TaskBinding binding{};
    std::uintptr_t holderAddress{};
    bool owner{true}, admitted{true}, writable{true}, readable{true};
    DWORD ownerThreadId{GetCurrentThreadId()};
    bool sameLifecycle{true}, gateArmed{true}, stopping{};
    bool preparingSeen{}, preparingForwardOnly{}, loseOwner{}, loseAdmission{};
    unsigned reads{}, queries{}, writes{}, failBefore{}, failAfter{}, foreignBefore{}, changeAfter{};
    unsigned identityChange{};
    bool failInverse{}, foreignInverse{}, unreadableAfter{};
    bool changeScheduleAfterRead{}, failScheduleRead{};
    ReadMutation readMutation{};
    std::uint32_t unreadableRva=UINT32_MAX;
    std::uintptr_t partialReadAddress{};
    PartialReadLoss partialReadLoss{};
    unsigned readsAtLoss{}, queriesAtLoss{};
    explicit Fixture(std::uint32_t id=5, std::uint32_t counter=9) {
        const auto table=Base()+layout.metadataVtableRva;
        std::memcpy(metadata.data(),&table,sizeof(table));
        std::memcpy(metadata2.data(),&table,sizeof(table));
        const std::uint16_t retryLimit=3;
        std::memcpy(metadata.data()+0x0A,&retryLimit,sizeof(retryLimit));
        std::memcpy(metadata2.data()+0x0A,&retryLimit,sizeof(retryLimit));
        Put(layout.selectedIdRva,id); Put(layout.counterRva,counter);
        Put(layout.invalidIdRva,std::uint32_t{0}); Put(layout.serviceStateRva,std::uint32_t{3});
        Put(layout.registryRva,reinterpret_cast<std::uintptr_t>(metadata.data()));
        SetTask(kSlot,id);
        RS2_CHECK(InitializeTaskBinding(binding,Original(),reinterpret_cast<std::uintptr_t>(&Wrapper))==Reason::None);
    }
    std::uintptr_t Base() const { return reinterpret_cast<std::uintptr_t>(image.data()); }
    std::uintptr_t Original() const { return Base()+layout.builderRva; }
    std::uint32_t SlotRva(std::uint32_t slot=kSlot) const { return layout.poolRva+slot*0x78; }
    std::uintptr_t Cell(std::uint32_t slot=kSlot) const { return Base()+SlotRva(slot)+0x40; }
    template<class T> void Put(std::uint32_t rva, T value) {
        RS2_CHECK(rva<image.size() && sizeof(T)<=image.size()-rva);
        std::memcpy(image.data()+rva,&value,sizeof(value));
    }
    template<class T> T Get(std::uint32_t rva) const {
        T value{}; std::memcpy(&value,image.data()+rva,sizeof(value)); return value;
    }
    void SetTask(std::uint32_t slot, std::uint32_t id, std::uint32_t state=2) {
        const auto rva=SlotRva(slot);
        std::memset(image.data()+rva,0,0x78);
        Put(rva,state); Put(rva+4,id); Put(rva+8,Base()+0x1600);
        Put(rva+0x38,kHolder); Put(rva+0x40,Original()); Put(rva+0x60,std::uint64_t{30000});
    }
    static bool Contains(std::uintptr_t base, std::size_t size, std::uintptr_t address,
        std::size_t count=1) {
        return address>=base && address-base<=size && count<=size-(address-base);
    }
    static bool Query(void* context, std::uintptr_t address, MemoryRegion* out, DWORD* error) noexcept {
        auto& f=*static_cast<Fixture*>(context);
        ++f.queries;
        *error=ERROR_SUCCESS;
        if (!f.readable) { *error=ERROR_NOACCESS; return false; }
        if (Contains(f.Base(),f.image.size(),address)) {
            const DWORD protection=f.writable ? PAGE_READWRITE : PAGE_READONLY;
            *out={f.Base(),f.Base(),f.image.size(),MEM_COMMIT,MEM_IMAGE,
                protection}; return true;
        }
        for (auto* meta: {f.metadata.data(),f.metadata2.data()}) {
            const auto base=reinterpret_cast<std::uintptr_t>(meta);
            if (Contains(base,32,address)) {
                *out={base,base,32,MEM_COMMIT,MEM_PRIVATE,PAGE_READWRITE}; return true;
            }
        }
        if (f.holderAddress && Contains(f.holderAddress,4,address)) {
            *out={f.holderAddress,f.holderAddress,4,MEM_COMMIT,MEM_PRIVATE,PAGE_READWRITE}; return true;
        }
        *error=ERROR_NOACCESS; return false;
    }
    static bool Read(void* context, std::uintptr_t address, void* output,
        std::size_t count, DWORD* error) noexcept {
        auto& f=*static_cast<Fixture*>(context); ++f.reads;
        if (f.unreadableRva!=UINT32_MAX && Contains(address,count,f.Base()+f.unreadableRva)) {
            *error=ERROR_NOACCESS; return false;
        }
        if (f.failScheduleRead && Contains(address,count,reinterpret_cast<std::uintptr_t>(f.metadata.data())+0x0A)) {
            *error=ERROR_NOACCESS; return false;
        }
        MemoryRegion region{};
        if (!Query(context,address,&region,error) || !Contains(region.base,region.size,address,count))
            return false;
        if (f.partialReadAddress && Contains(address,count,f.partialReadAddress)) {
            // Model RPM reporting failure after copying a prefix. A batched
            // authority/diagnostic read must never accept that partial object.
            const auto copied=count<4 ? count : 4;
            std::memcpy(output,reinterpret_cast<const void*>(address),copied);
            if (address==f.Base()+f.SlotRva()+0x38 && count==0x30 &&
                f.partialReadLoss!=PartialReadLoss::None) {
                switch (f.partialReadLoss) {
                case PartialReadLoss::Owner: f.owner=false; break;
                case PartialReadLoss::Lifecycle: f.sameLifecycle=false; break;
                case PartialReadLoss::Gate: f.gateArmed=false; break;
                case PartialReadLoss::Stopping: f.stopping=true; break;
                case PartialReadLoss::None: break;
                }
                f.readsAtLoss=f.reads; f.queriesAtLoss=f.queries;
            }
            *error=ERROR_PARTIAL_COPY; return false;
        }
        std::memcpy(output,reinterpret_cast<const void*>(address),count);
        if (f.changeScheduleAfterRead && Contains(address,count,reinterpret_cast<std::uintptr_t>(f.metadata.data())+0x18,8)) {
            const std::int64_t replacement=1;
            std::memcpy(f.metadata.data()+0x18,&replacement,sizeof(replacement));
            f.changeScheduleAfterRead=false;
        }
        if (f.readMutation!=ReadMutation::None &&
            Contains(address,count,reinterpret_cast<std::uintptr_t>(f.metadata.data())+0x18,8)) {
            const auto mutation=f.readMutation; f.readMutation=ReadMutation::None;
            switch (mutation) {
            case ReadMutation::Selected: f.Put(f.layout.selectedIdRva,std::uint32_t{6}); break;
            case ReadMutation::Sentinel: f.Put(f.layout.invalidIdRva,std::uint32_t{1}); break;
            case ReadMutation::CounterAdvance:
                f.Put(f.layout.counterRva,f.Get<std::uint32_t>(f.layout.counterRva)+1); break;
            case ReadMutation::CounterDecrease:
                f.Put(f.layout.counterRva,f.Get<std::uint32_t>(f.layout.counterRva)-1); break;
            case ReadMutation::SlotId: f.Put(f.SlotRva()+4,std::uint32_t{6}); break;
            case ReadMutation::Holder: f.Put(f.SlotRva()+0x38,kHolder+1); break;
            case ReadMutation::Component: f.Put(f.SlotRva()+8,f.Base()+0x1610); break;
            case ReadMutation::Metadata:
                f.Put(f.layout.registryRva,reinterpret_cast<std::uintptr_t>(f.metadata2.data())); break;
            case ReadMutation::Vtable: {
                const auto table=f.Base()+0x1510;
                std::memcpy(f.metadata.data(),&table,sizeof(table)); break;
            }
            case ReadMutation::Callback: f.Put(f.SlotRva()+0x48,std::uintptr_t{1}); break;
            case ReadMutation::Interval: f.Put(f.SlotRva()+0x60,std::uint64_t{1}); break;
            case ReadMutation::State: f.Put(f.SlotRva(),std::uint32_t{4}); break;
            case ReadMutation::None: break;
            }
        }
        *error=ERROR_SUCCESS; return true;
    }
    static bool OwnerThread(void* context) noexcept {
        const auto& f=*static_cast<Fixture*>(context);
        return f.owner && GetCurrentThreadId()==f.ownerThreadId;
    }
    static bool Safe(void* context) noexcept {
        const auto& f=*static_cast<Fixture*>(context);
        return OwnerThread(context) && f.sameLifecycle && f.gateArmed && !f.stopping;
    }
    static bool Admit(void* context) noexcept { return static_cast<Fixture*>(context)->admitted; }
    static bool Cas(void* context, std::uintptr_t address, std::uintptr_t expected,
        std::uintptr_t desired, std::uintptr_t* observed, DWORD* error) noexcept {
        auto& f=*static_cast<Fixture*>(context); ++f.writes;
        const bool inverse=expected==f.binding.wrapper;
        if (!inverse) {
            f.preparingSeen=ReadTaskPhase(f.binding)==TaskPhase::Preparing;
            const auto priorReads=f.reads;
            TaskSnapshot unused{};
            const auto skipped=ValidateBuilderTask(f.binding,f.Access(),f.layout,kEpoch,nullptr,&unused);
            f.preparingForwardOnly=skipped==Reason::TaskNotReady && f.reads==priorReads;
        }
        if (f.writes==f.failBefore || (inverse && f.failInverse)) {
            *error=ERROR_NOACCESS; return false;
        }
        if (f.writes==f.foreignBefore || (inverse && f.foreignInverse)) {
            const std::uintptr_t foreign=0x12345678;
            std::memcpy(reinterpret_cast<void*>(address),&foreign,sizeof(foreign));
        }
        std::memcpy(observed,reinterpret_cast<const void*>(address),sizeof(*observed));
        if (*observed==expected) std::memcpy(reinterpret_cast<void*>(address),&desired,sizeof(desired));
        if (f.writes==f.changeAfter) {
            if (f.identityChange==0) {
                f.Put(f.SlotRva()+4,std::uint32_t{6}); f.Put(f.layout.selectedIdRva,std::uint32_t{6});
                f.Put(f.layout.counterRva,std::uint32_t{10});
            } else if (f.identityChange==1) f.Put(f.SlotRva()+0x38,kHolder+1);
            else if (f.identityChange==2) f.Put(f.SlotRva()+8,f.Base()+0x1610);
            else if (f.identityChange==3)
                f.Put(f.layout.registryRva,reinterpret_cast<std::uintptr_t>(f.metadata2.data()));
            else if (f.identityChange==4) f.Put(f.SlotRva(),std::uint32_t{4});
            else if (f.identityChange==5) f.Put(f.SlotRva()+0x48,std::uintptr_t{1});
            else f.Put(f.SlotRva()+0x60,std::uint64_t{1});
        }
        if (!inverse) {
            if (f.loseOwner) f.owner=false;
            if (f.loseAdmission) f.admitted=false;
            if (f.unreadableAfter) f.readable=false;
        }
        if (f.writes==f.failAfter) { *error=ERROR_NOACCESS; return false; }
        *error=ERROR_SUCCESS; return true;
    }
    TaskAccess Access() { return {{this,Query,Read},Base(),static_cast<std::uint32_t>(image.size()),this,Cas,Admit,Safe,OwnerThread}; }
    Reason Install(TaskEpoch epoch=kEpoch,TaskSnapshot* installed=nullptr) { return InstallTaskBinding(binding,Access(),layout,epoch,installed); }
    Reason Retire(Reason fault=Reason::None) { return RetireTaskBinding(binding,Access(),layout,fault); }
    Reason Validate(std::uint32_t& holder, TaskEpoch epoch=kEpoch) {
        holderAddress=reinterpret_cast<std::uintptr_t>(&holder);
        TaskSnapshot snapshot{};
        return ValidateBuilderTask(binding,Access(),layout,epoch,&holder,&snapshot);
    }
    bool Stock() const { return Get<std::uintptr_t>(SlotRva()+0x40)==Original(); }
};

void ReadCases() {
    Fixture f;
    TaskSnapshot snapshot{};
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::None);
    RS2_CHECK(snapshot.identity.slot==kSlot && snapshot.identity.id==5 && snapshot.identity.holder==kHolder);
    RS2_CHECK(snapshot.state==2 && snapshot.nativeCounter==9 && snapshot.builder==f.Original());
    f.SetTask(7,5);
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::TaskAmbiguous);
    RS2_CHECK(snapshot.identity.id==0);
    f.SetTask(7,7); // A different live task is not a false duplicate.
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::None);
    f.Put(f.layout.selectedIdRva,std::uint32_t{0});
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::TaskNotReady);
    f.Put(f.layout.selectedIdRva,std::uint32_t{5}); f.Put(f.layout.invalidIdRva,std::uint32_t{1});
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::TaskMismatch);
    f.Put(f.layout.invalidIdRva,std::uint32_t{0}); f.Put(f.layout.serviceStateRva,std::uint32_t{0});
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::Unregistered);
    f.Put(f.layout.serviceStateRva,std::uint32_t{3}); f.Put(f.SlotRva()+0x38,(44u<<16)|17u);
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::HolderMismatch);
    f.Put(f.SlotRva()+0x38,kHolder); f.Put(f.layout.registryRva,std::uintptr_t{0});
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::TaskNotReady);
    f.Put(f.layout.registryRva,reinterpret_cast<std::uintptr_t>(f.metadata.data()));
    const std::uintptr_t wrongVtable=f.Base()+0x1510;
    std::memcpy(f.metadata.data(),&wrongVtable,sizeof(wrongVtable));
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::TaskMismatch);
    Fixture unsignedIds(0x80000001u,0x80000002u);
    RS2_CHECK(ReadSelectedTask(unsignedIds.Access(),unsignedIds.layout,&snapshot)==Reason::None);
    // High-bit IDs are ordinary unsigned native counter values, not negatives.
    RS2_CHECK(unsignedIds.Install()==Reason::None);
    Fixture malformed;
    malformed.Put(malformed.SlotRva()+8,std::uintptr_t{0});
    RS2_CHECK(ReadSelectedTask(malformed.Access(),malformed.layout,&snapshot)==Reason::TaskMismatch);
}
void ScheduleCases() {
    Fixture f;
    TaskSnapshot snapshot{};
    f.Put(f.SlotRva()+0x68,std::int32_t{12});
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::None && snapshot.schedule.valid);
    RS2_CHECK(snapshot.schedule.tier==ScheduleTier::OrdinaryPoll && snapshot.schedule.delayUnits==30000);
    f.Put(f.SlotRva(),std::uint32_t{3});
    constexpr std::int32_t errors[]{2,3,6,9,12,INT32_MAX};
    constexpr std::uint64_t delays[]{2000,30000,60000,300000,1800000,1800000};
    for (unsigned i=0;i<std::size(errors);++i) {
        f.Put(f.SlotRva()+0x68,errors[i]);
        RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::None && snapshot.schedule.valid);
        RS2_CHECK(snapshot.schedule.delayUnits==delays[i] && snapshot.schedule.tier!=ScheduleTier::Unknown);
    }
    f.Put(f.SlotRva()+0x68,std::int32_t{0}); f.Put(f.SlotRva()+0x6C,std::int32_t{5});
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::None && snapshot.schedule.delayUnits==2000);
    f.Put(f.SlotRva()+0x6C,std::int32_t{6}); f.Put(f.SlotRva()+0x70,std::uint8_t{7});
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::None && snapshot.schedule.delayUnits==30000 && snapshot.schedule.expedite==7);
    f.Put(f.SlotRva(),std::uint32_t{4});
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::None && snapshot.schedule.valid && snapshot.schedule.tier==ScheduleTier::Unknown);
    f.Put(f.SlotRva(),std::uint32_t{3});
    const std::int64_t negative=-1;
    std::memcpy(f.metadata.data()+0x10,&negative,sizeof(negative));
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::None && snapshot.schedule.valid && snapshot.schedule.intervalOverride==-1);
    RS2_CHECK(snapshot.schedule.tier==ScheduleTier::Unknown && snapshot.schedule.delayUnits==0);
    const std::int64_t zero=0;
    std::memcpy(f.metadata.data()+0x10,&zero,sizeof(zero));
    f.changeScheduleAfterRead=true;
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::None && !snapshot.schedule.valid && snapshot.schedule.delayUnits==0);
    f.failScheduleRead=true;
    RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::None && !snapshot.schedule.valid);
    RS2_CHECK(f.writes==0); // Diagnostics never call the scheduler or change its cells.
}
void BoundReadCases() {
    TaskSnapshot snapshot{};
    {
        Fixture f; f.SetTask(7,5);
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::TaskNotReady);
        RS2_CHECK(f.Install()==Reason::TaskAmbiguous && f.Stock());
        RS2_CHECK(ReadTaskPhase(f.binding)==TaskPhase::Empty && !f.binding.haveHistory);
    }
    {
        Fixture f; RS2_CHECK(f.Install()==Reason::None);
        // Unrelated native creations consume globally increasing IDs without
        // changing the proven selected task. This is not heartbeat-ID reuse.
        f.SetTask(7,10); f.Put(f.layout.counterRva,std::uint32_t{10});
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::None);
        RS2_CHECK(snapshot.identity.id==5 && snapshot.identity.slot==kSlot &&
            snapshot.schedule.valid && snapshot.schedule.tier==ScheduleTier::OrdinaryPoll);
        RS2_CHECK(f.binding.lastNativeCounter==10 && f.binding.lastBoundId==5);
        f.SetTask(8,12); f.Put(f.layout.counterRva,std::uint32_t{12});
        auto holder=kHolder;
        RS2_CHECK(f.Validate(holder)==Reason::None && f.binding.lastNativeCounter==12);
        RS2_CHECK(f.Retire()==Reason::None);
        f.SetTask(kSlot,13); f.Put(f.layout.selectedIdRva,std::uint32_t{13});
        f.Put(f.layout.counterRva,std::uint32_t{13});
        RS2_CHECK(f.Install({2,2})==Reason::None && f.binding.identity.id==13);
    }
    {
        Fixture f; RS2_CHECK(f.Install()==Reason::None);
        f.SetTask(7,10); f.Put(f.layout.counterRva,std::uint32_t{10});
        f.Put(f.layout.selectedIdRva,std::uint32_t{10});
        const auto writes=f.writes;
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::TaskMismatch);
        RS2_CHECK(snapshot.identity.id==0 && ReadTaskPhase(f.binding)==TaskPhase::Armed &&
            f.binding.identity.id==5 && f.writes==writes);
        // A management read allows root retirement, but a builder on the old
        // binding retains the old full-reader failure classification.
        auto holder=kHolder;
        RS2_CHECK(f.Validate(holder)==Reason::TaskReused && ReadTaskPhase(f.binding)==TaskPhase::Inert);
        RS2_CHECK(f.Stock() && f.Get<std::uintptr_t>(f.SlotRva(7)+0x40)==f.Original());
    }
    {
        Fixture f; RS2_CHECK(f.Install()==Reason::None);
        f.SetTask(kSlot,10); f.Put(f.layout.selectedIdRva,std::uint32_t{10});
        f.Put(f.layout.counterRva,std::uint32_t{10});
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::TaskMismatch);
        RS2_CHECK(f.Retire()==Reason::None && f.writes==1);
        RS2_CHECK(f.Install({2,2})==Reason::None && f.binding.identity.id==10);
    }
    {
        Fixture f; RS2_CHECK(f.Install()==Reason::None);
        f.Put(f.layout.counterRva,std::uint32_t{8});
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::TaskReused);
        RS2_CHECK(ReadTaskPhase(f.binding)==TaskPhase::Inert && f.Stock() && !snapshot.schedule.valid);
    }
    {
        Fixture f(5,UINT32_MAX); RS2_CHECK(f.Install()==Reason::None);
        f.Put(f.layout.counterRva,std::uint32_t{0});
        auto holder=kHolder;
        RS2_CHECK(f.Validate(holder)==Reason::TaskReused && f.Stock() && f.writes==2);
        RS2_CHECK(f.binding.inverseAttempted); // No duplicate Fault/inverse from the caller.
    }
    for (unsigned changed=0; changed<3; ++changed) {
        Fixture f; RS2_CHECK(f.Install()==Reason::None);
        if (changed==0) f.Put(f.SlotRva()+0x38,kHolder+1);
        else if (changed==1) f.Put(f.SlotRva()+8,f.Base()+0x1610);
        else f.Put(f.layout.registryRva,reinterpret_cast<std::uintptr_t>(f.metadata2.data()));
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::TaskReused);
        RS2_CHECK(ReadTaskPhase(f.binding)==TaskPhase::Inert && f.Stock() && snapshot.identity.id==0);
    }
    {
        Fixture f; RS2_CHECK(f.Install()==Reason::None);
        f.unreadableRva=f.SlotRva()+8;
        auto holder=kHolder;
        RS2_CHECK(f.Validate(holder)==Reason::TaskMismatch && ReadTaskPhase(f.binding)==TaskPhase::Armed);
        RS2_CHECK(f.writes==1); // A failed partial read is not a proven reuse fault.
        f.unreadableRva=UINT32_MAX;
        f.failScheduleRead=true;
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::None && !snapshot.schedule.valid);
        f.failScheduleRead=false;
        f.Put(f.SlotRva(),std::uint32_t{4});
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::None && snapshot.state==4);
        RS2_CHECK(f.Validate(holder)==Reason::TaskNotReady);
    }
}
void BoundRereadCases() {
    TaskSnapshot snapshot{};
    for (const auto mutation:{Fixture::ReadMutation::Selected,Fixture::ReadMutation::Sentinel,
        Fixture::ReadMutation::SlotId,Fixture::ReadMutation::Holder,Fixture::ReadMutation::Component,
        Fixture::ReadMutation::Metadata,Fixture::ReadMutation::Vtable,Fixture::ReadMutation::Callback,
        Fixture::ReadMutation::Interval,Fixture::ReadMutation::State}) {
        Fixture f; RS2_CHECK(f.Install()==Reason::None);
        f.readMutation=mutation;
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::TaskMismatch);
        RS2_CHECK(!snapshot.identity.id && !snapshot.schedule.valid &&
            ReadTaskPhase(f.binding)==TaskPhase::Armed && f.writes==1);
    }
    {
        Fixture f; RS2_CHECK(f.Install()==Reason::None);
        f.readMutation=Fixture::ReadMutation::CounterAdvance;
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::TaskMismatch);
        RS2_CHECK(f.binding.lastNativeCounter==9 && ReadTaskPhase(f.binding)==TaskPhase::Armed);
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::None &&
            f.binding.lastNativeCounter==10);
    }
    {
        Fixture f; RS2_CHECK(f.Install()==Reason::None);
        f.Put(f.layout.counterRva,std::uint32_t{10}); // Prior successful sample was 9.
        f.readMutation=Fixture::ReadMutation::CounterDecrease;
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::TaskReused);
        RS2_CHECK(ReadTaskPhase(f.binding)==TaskPhase::Inert && f.Stock());
    }
    {
        Fixture f; RS2_CHECK(f.Install()==Reason::None);
        f.readMutation=Fixture::ReadMutation::Sentinel;
        RS2_CHECK(ReadSelectedTask(f.Access(),f.layout,&snapshot)==Reason::TaskMismatch);
    }
}
void BatchedPartialReadCases() {
    TaskSnapshot snapshot{};
    for (const std::uint32_t requiredOffset:{0x40u,0x60u}) {
        Fixture f; RS2_CHECK(f.Install()==Reason::None);
        // Neither the builder nor the separately retried interval may be
        // salvaged from a failed combined read or failed fallback read.
        f.partialReadAddress=f.Base()+f.SlotRva()+requiredOffset;
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::TaskMismatch);
        RS2_CHECK(snapshot.identity.id==0 && !snapshot.schedule.valid &&
            ReadTaskPhase(f.binding)==TaskPhase::Armed && f.writes==1);
        auto holder=kHolder;
        RS2_CHECK(f.Validate(holder)==Reason::TaskMismatch && f.writes==1);
        f.partialReadAddress=0;
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::None);
    }
    for (const auto loss:{Fixture::PartialReadLoss::Owner,Fixture::PartialReadLoss::Lifecycle,
        Fixture::PartialReadLoss::Gate,Fixture::PartialReadLoss::Stopping}) {
        Fixture f; RS2_CHECK(f.Install()==Reason::None);
        f.partialReadAddress=f.Base()+f.SlotRva()+0x58;
        f.partialReadLoss=loss;
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::TaskMismatch);
        RS2_CHECK(f.readsAtLoss!=0 && f.reads==f.readsAtLoss && f.queries==f.queriesAtLoss);
        RS2_CHECK(snapshot.identity.id==0 && !snapshot.schedule.valid &&
            ReadTaskPhase(f.binding)==TaskPhase::Armed && f.writes==1);
        auto holder=kHolder;
        const auto blocked=loss==Fixture::PartialReadLoss::Owner ? Reason::ForeignThread : Reason::LifecycleCrossing;
        RS2_CHECK(f.Validate(holder)==blocked && f.reads==f.readsAtLoss && f.queries==f.queriesAtLoss && f.writes==1);
    }
    for (const std::uint32_t optionalOffset:{0x58u,0x6Cu}) {
        Fixture f; RS2_CHECK(f.Install()==Reason::None);
        f.Put(f.SlotRva()+0x58,std::uint64_t{1234});
        f.Put(f.SlotRva()+0x6C,std::int32_t{6});
        f.partialReadAddress=f.Base()+f.SlotRva()+optionalOffset;
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::None);
        RS2_CHECK(snapshot.identity.id==5 && !snapshot.schedule.valid &&
            snapshot.schedule.anchorBits==0 && snapshot.schedule.throttles==0 &&
            snapshot.schedule.tier==ScheduleTier::Unknown && f.writes==1);
    }
    {
        Fixture f; RS2_CHECK(f.Install()==Reason::None);
        f.partialReadAddress=reinterpret_cast<std::uintptr_t>(f.metadata.data())+0x18;
        RS2_CHECK(ReadBoundTask(f.binding,f.Access(),f.layout,&snapshot)==Reason::None);
        RS2_CHECK(!snapshot.schedule.valid && snapshot.schedule.retryLimit==0 &&
            snapshot.schedule.intervalOverride==0 && snapshot.schedule.retryOverride==0 && f.writes==1);
        auto holder=kHolder;
        RS2_CHECK(f.Validate(holder)==Reason::None); // Optional metadata is never an authority gate.
    }
}
void InstallAndHolder() {
    Fixture f;
    TaskSnapshot installed{};
    RS2_CHECK(f.Install(kEpoch,&installed)==Reason::None && ReadTaskPhase(f.binding)==TaskPhase::Armed);
    RS2_CHECK(installed.identity.id==5 && installed.identity.slot==kSlot &&
        installed.builder==f.binding.wrapper && installed.nativeCounter==9 && installed.schedule.valid);
    RS2_CHECK(f.Install(kEpoch,&installed)==Reason::TaskNotReady && installed.identity.id==0 &&
        installed.state==0 && !installed.schedule.valid);
    RS2_CHECK(f.writes==1 && f.preparingSeen && f.preparingForwardOnly);
    RS2_CHECK(f.Get<std::uintptr_t>(f.SlotRva()+0x40)==f.binding.wrapper);
    RS2_CHECK(f.Get<std::uintptr_t>(f.SlotRva()+0x48)==0 && f.Get<std::uintptr_t>(f.SlotRva()+0x50)==0);
    auto holder=kHolder;
    RS2_CHECK(f.Validate(holder)==Reason::None); // Copied local holder, never same stack address as native task.
    ++holder;
    RS2_CHECK(f.Validate(holder)==Reason::HolderMismatch);
    holder=kHolder;
    const auto reads=f.reads;
    RS2_CHECK(f.Validate(holder,{2,1})==Reason::SourceLifetime && f.reads==reads);
    f.owner=false;
    RS2_CHECK(f.Validate(holder)==Reason::ForeignThread && f.reads==reads);
    f.owner=true;
    RS2_CHECK(f.Retire()==Reason::None && f.Stock() && ReadTaskPhase(f.binding)==TaskPhase::Retired);
    RS2_CHECK(f.Install({2,2})==Reason::None); // Same exact continuing native task, fresh source authority.
    RS2_CHECK(f.Validate(holder,{2,2})==Reason::None);
    RS2_CHECK(f.Validate(holder,kEpoch)==Reason::SourceLifetime);
}
void StateAndEpochCases() {
    for (const std::uint32_t state: {1u,4u,5u}) {
        Fixture f; f.Put(f.SlotRva(),state);
        RS2_CHECK(f.Install()==Reason::TaskNotReady && f.writes==0 && f.Stock());
    }
    for (const std::uint32_t state: {2u,3u}) {
        Fixture f; f.Put(f.SlotRva(),state);
        RS2_CHECK(f.Install()==Reason::None);
    }
    Fixture f;
    RS2_CHECK(f.Install()==Reason::None);
    f.Put(f.SlotRva(),std::uint32_t{4});
    const auto writes=f.writes;
    RS2_CHECK(f.Retire()==Reason::TaskNotReady && f.writes==writes && ReadTaskPhase(f.binding)==TaskPhase::Armed);
    auto holder=kHolder;
    const auto reads=f.reads;
    RS2_CHECK(f.Validate(holder,{2,2})==Reason::SourceLifetime && f.reads==reads);
    RS2_CHECK(f.Validate(holder)==Reason::TaskNotReady);
    f.Put(f.SlotRva(),std::uint32_t{5});
    RS2_CHECK(f.Retire()==Reason::TaskNotReady && f.writes==writes);
    f.Put(f.SlotRva(),std::uint32_t{2});
    RS2_CHECK(f.Retire()==Reason::None && f.Stock());
    RS2_CHECK(f.Install({2,2})==Reason::None);
    RS2_CHECK(f.Retire()==Reason::None);
    RS2_CHECK(f.Install({1,2})==Reason::SourceLifetime && ReadTaskPhase(f.binding)==TaskPhase::Inert);
    Fixture ro; ro.writable=false;
    RS2_CHECK(ro.Install()==Reason::WriteFault && ro.writes==0 && ro.Stock());
    Fixture wrongEpoch;
    RS2_CHECK(wrongEpoch.Install({0,1})==Reason::ProfileMismatch && wrongEpoch.writes==0);
}
void MutationFailures() {
    { Fixture f; f.failBefore=1;
      RS2_CHECK(f.Install()==Reason::InstallFailed && f.Stock());
      RS2_CHECK(ReadTaskPhase(f.binding)==TaskPhase::Inert && f.writes==1 && !f.binding.stranded);
      RS2_CHECK(f.Install()==Reason::InstallFailed && f.writes==1); }
    { Fixture f; f.failAfter=1; TaskSnapshot installed{}; installed.state=99;
      RS2_CHECK(f.Install(kEpoch,&installed)==Reason::InstallFailed && f.Stock() && f.writes==2);
      RS2_CHECK(installed.state==0 && installed.identity.id==0 && !installed.schedule.valid);
      RS2_CHECK(f.binding.inverseAttempted && !f.binding.stranded && f.binding.lastError==ERROR_NOACCESS); }
    { Fixture f; f.foreignBefore=1;
      RS2_CHECK(f.Install()==Reason::InstallFailed && f.writes==1);
      RS2_CHECK(f.Get<std::uintptr_t>(f.SlotRva()+0x40)==0x12345678 && !f.binding.stranded); }
    for (unsigned changed=0; changed<7; ++changed) {
        Fixture f; f.changeAfter=1; f.identityChange=changed;
        RS2_CHECK(f.Install()==Reason::PostcheckFailed && ReadTaskPhase(f.binding)==TaskPhase::Inert);
        RS2_CHECK(f.Stock() && f.writes==2 && f.binding.inverseAttempted && !f.binding.stranded);
    }
    { Fixture f; f.changeAfter=1; f.failInverse=true;
      RS2_CHECK(f.Install()==Reason::PostcheckFailed && f.writes==2 && f.binding.stranded);
      const auto writes=f.writes;
      RS2_CHECK(f.Install()==Reason::PostcheckFailed && f.writes==writes); }
    { Fixture f; f.changeAfter=1; f.foreignInverse=true;
      RS2_CHECK(f.Install()==Reason::PostcheckFailed && f.writes==2 && !f.binding.stranded);
      RS2_CHECK(f.Get<std::uintptr_t>(f.SlotRva()+0x40)==0x12345678); }
    { Fixture f; f.loseOwner=true;
      RS2_CHECK(f.Install()==Reason::PostcheckFailed && f.writes==1 && f.binding.stranded);
      RS2_CHECK(ReadTaskPhase(f.binding)==TaskPhase::Inert); }
    { Fixture f; f.loseAdmission=true;
      RS2_CHECK(f.Install()==Reason::PostcheckFailed && f.Stock() && f.writes==2);
      RS2_CHECK(!f.binding.stranded); } // Revocation blocks commit but not independent safe-owner cleanup.
    { Fixture f; f.unreadableAfter=true;
      RS2_CHECK(f.Install()==Reason::PostcheckFailed && f.writes==1 && f.binding.stranded); }
    { Fixture f; RS2_CHECK(f.Install()==Reason::None); f.failBefore=2;
      RS2_CHECK(f.Retire()==Reason::PostcheckFailed && f.writes==2 && f.binding.stranded);
      RS2_CHECK(ReadTaskPhase(f.binding)==TaskPhase::Inert); }
    { Fixture f; RS2_CHECK(f.Install()==Reason::None); f.failAfter=2;
      RS2_CHECK(f.Retire()==Reason::PostcheckFailed && f.writes==2 && f.Stock());
      RS2_CHECK(!f.binding.stranded && f.binding.lastError==ERROR_NOACCESS); }
}
void EntryClassificationCases() {
    Fixture f;
    RS2_CHECK(f.Install()==Reason::None);
    const auto reads=f.reads, queries=f.queries, writes=f.writes;
    bool cleared{};
    const auto probe=[&](const TaskAccess& access) {
        std::array<Reason,5> results{};
        TaskSnapshot sample{}; sample.state=99; sample.identity.id=99;
        cleared=true;
        results[0]=ReadSelectedTask(access,f.layout,&sample);
        cleared=cleared && sample.state==0 && sample.identity.id==0;
        sample.state=99;
        results[1]=ReadBoundTask(f.binding,access,f.layout,&sample);
        cleared=cleared && sample.state==0;
        sample.state=99;
        results[2]=InstallTaskBinding(f.binding,access,f.layout,kEpoch,&sample);
        cleared=cleared && sample.state==0;
        sample.state=99;
        results[3]=ValidateBuilderTask(f.binding,access,f.layout,kEpoch,nullptr,&sample);
        cleared=cleared && sample.state==0;
        results[4]=RetireTaskBinding(f.binding,access,f.layout,Reason::RecordLoss);
        return results;
    };
    std::array<Reason,5> foreign{};
    std::thread thread([&] { foreign=probe(f.Access()); }); thread.join();
    for (const auto reason:foreign) RS2_CHECK(reason==Reason::ForeignThread);
    RS2_CHECK(cleared && f.reads==reads && f.queries==queries && f.writes==writes);
    for (unsigned crossing=0; crossing<3; ++crossing) {
        f.sameLifecycle=crossing!=0; f.gateArmed=crossing!=1; f.stopping=crossing==2;
        const auto results=probe(f.Access());
        for (const auto reason:results) RS2_CHECK(reason==Reason::LifecycleCrossing);
        RS2_CHECK(cleared && f.reads==reads && f.queries==queries && f.writes==writes);
        RS2_CHECK(ReadTaskPhase(f.binding)==TaskPhase::Armed);
    }
    f.sameLifecycle=true; f.gateArmed=true; f.stopping=false;
    for (unsigned missing=0; missing<3; ++missing) {
        auto access=f.Access();
        if (missing==0) access.ownerThread=nullptr;
        else if (missing==1) access.safeOwner=nullptr;
        else access.admission=nullptr;
        for (const auto reason:probe(access)) RS2_CHECK(reason==Reason::ProfileMismatch);
        RS2_CHECK(cleared && f.reads==reads && f.queries==queries && f.writes==writes);
    }
    f.admitted=false; // Diagnostic-only revocation does not destroy safe ownership.
    RS2_CHECK(f.Retire(Reason::RecordLoss)==Reason::RecordLoss && f.Stock());
    RS2_CHECK(ReadTaskPhase(f.binding)==TaskPhase::Inert && f.binding.inverseAttempted);
}
void ReuseCases() {
    Fixture f;
    RS2_CHECK(f.Install()==Reason::None);
    // Native cleanup removes our pointer; later construction owns the slot and
    // initializes a NEW stock builder. Retirement never writes that successor.
    f.SetTask(kSlot,10); f.Put(f.layout.selectedIdRva,std::uint32_t{10});
    f.Put(f.layout.counterRva,std::uint32_t{10});
    RS2_CHECK(f.Retire()==Reason::None && f.writes==1);
    RS2_CHECK(f.Install({2,2})==Reason::None && f.binding.identity.id==10);
    RS2_CHECK(f.Retire()==Reason::None);
    f.SetTask(kSlot,10); f.Put(f.SlotRva()+0x38,kHolder+1);
    RS2_CHECK(f.Install({3,3})==Reason::TaskReused && ReadTaskPhase(f.binding)==TaskPhase::Inert);

    Fixture wrapped(5,(std::numeric_limits<std::uint32_t>::max)());
    RS2_CHECK(wrapped.Install()==Reason::None && wrapped.Retire()==Reason::None);
    wrapped.SetTask(kSlot,6); wrapped.Put(wrapped.layout.selectedIdRva,std::uint32_t{6});
    wrapped.Put(wrapped.layout.counterRva,std::uint32_t{6});
    RS2_CHECK(wrapped.Install({2,2})==Reason::TaskReused && wrapped.Stock());

    Fixture stranded;
    stranded.Put(stranded.SlotRva()+0x40,stranded.binding.wrapper);
    RS2_CHECK(stranded.Install()==Reason::StrandedWrapper && stranded.Stock());
    RS2_CHECK(ReadTaskPhase(stranded.binding)==TaskPhase::Inert && stranded.writes==1);

    Fixture successor;
    RS2_CHECK(successor.Install()==Reason::None);
    successor.Put(successor.SlotRva()+4,std::uint32_t{6});
    successor.Put(successor.layout.selectedIdRva,std::uint32_t{6});
    successor.Put(successor.layout.counterRva,std::uint32_t{10});
    RS2_CHECK(successor.Retire()==Reason::StrandedWrapper && successor.Stock());
    RS2_CHECK(ReadTaskPhase(successor.binding)==TaskPhase::Inert);

    Fixture cleared;
    RS2_CHECK(cleared.Install()==Reason::None);
    std::memset(cleared.image.data()+cleared.SlotRva(),0,0x78);
    cleared.Put(cleared.layout.selectedIdRva,std::uint32_t{0});
    RS2_CHECK(cleared.Retire()==Reason::None && cleared.writes==1);
    cleared.SetTask(8,11); cleared.Put(cleared.layout.selectedIdRva,std::uint32_t{11});
    cleared.Put(cleared.layout.counterRva,std::uint32_t{11});
    RS2_CHECK(cleared.Install({2,2})==Reason::None && cleared.binding.identity.slot==8);

    Fixture repeated;
    RS2_CHECK(repeated.Install()==Reason::None && repeated.Retire()==Reason::None);
    std::memset(repeated.image.data()+repeated.SlotRva(),0,0x78);
    repeated.Put(repeated.layout.selectedIdRva,std::uint32_t{0});
    RS2_CHECK(repeated.Retire()==Reason::None && !repeated.binding.continuingTask);
    repeated.SetTask(kSlot,5); repeated.Put(repeated.layout.selectedIdRva,std::uint32_t{5});
    RS2_CHECK(repeated.Install({2,2})==Reason::TaskReused); // Same bytes after observed destruction != same lifetime.

    Fixture staleEpoch;
    RS2_CHECK(staleEpoch.Install()==Reason::None);
    staleEpoch.SetTask(kSlot,10); staleEpoch.Put(staleEpoch.layout.selectedIdRva,std::uint32_t{10});
    staleEpoch.Put(staleEpoch.layout.counterRva,std::uint32_t{10});
    RS2_CHECK(staleEpoch.Retire()==Reason::None);
    RS2_CHECK(staleEpoch.Install(kEpoch)==Reason::SourceLifetime && staleEpoch.writes==1);

    Fixture oldId;
    RS2_CHECK(oldId.Install()==Reason::None && oldId.Retire()==Reason::None);
    oldId.SetTask(kSlot,6); oldId.Put(oldId.layout.selectedIdRva,std::uint32_t{6});
    oldId.Put(oldId.layout.counterRva,std::uint32_t{10});
    RS2_CHECK(oldId.Install({2,2})==Reason::TaskReused); // Counter 9 was already observed; new construction cannot issue 6.
}
} // namespace

void ReportingTaskTests() {
    ReadCases(); ScheduleCases(); BoundReadCases(); BoundRereadCases(); BatchedPartialReadCases();
    InstallAndHolder(); StateAndEpochCases(); MutationFailures(); EntryClassificationCases(); ReuseCases();
}
