#include "companion/steam_reporting_task.h"
#include "companion/steam_reporting_read_scope.h"
#include <limits>

namespace rs2fix::reporting {
namespace {
constexpr std::uint32_t kStride=0x78;
constexpr std::uint32_t kBuilderOffset=0x40;
constexpr std::uint32_t kHolderType=43;
constexpr std::uint64_t kInterval=30000;
constexpr TaskLayout kProduction{0x17AAC80,0x14AAD8C,0x17AA9C0,0x17AAC78,
    0x179D5A8,0x1276D60,0xBA9FD0,0x14AAD20};

void Phase(TaskBinding& state, TaskPhase phase) noexcept {
    InterlockedExchange(&state.phase,static_cast<LONG>(phase));
}
bool Owner(const TaskAccess& access) noexcept {
    return access.safeOwner && access.safeOwner(access.context);
}
Reason EntryReason(const TaskAccess& access) noexcept {
    if (!access.ownerThread || !access.safeOwner || !access.admission) return Reason::ProfileMismatch;
    if (!access.ownerThread(access.context)) return Reason::ForeignThread;
    return Owner(access) ? Reason::None : Reason::LifecycleCrossing;
}
bool Admit(const TaskAccess& access) noexcept {
    return access.admission && access.admission(access.context);
}
bool Address(const TaskAccess& access, std::uint32_t rva, std::size_t bytes,
    std::uintptr_t* address) noexcept {
    if (!access.hostBase || !bytes || !access.hostImageSize ||
        access.hostImageSize>(std::numeric_limits<std::uintptr_t>::max)()-access.hostBase ||
        rva>=access.hostImageSize || bytes>access.hostImageSize-rva) return false;
    *address=access.hostBase+rva;
    return true;
}
bool LayoutValid(const TaskAccess& access, const TaskLayout& layout) noexcept {
    std::uintptr_t ignored{};
    if (!access.memory.query || !access.memory.read || (access.hostBase&7) ||
        (layout.poolRva&7) || (layout.registryRva&7) || (layout.metadataVtableRva&7) ||
        ((layout.selectedIdRva|layout.invalidIdRva|layout.counterRva|layout.serviceStateRva)&3))
        return false;
    return Address(access,layout.poolRva,kTaskSlots*kStride,&ignored) &&
        Address(access,layout.registryRva,8,&ignored) &&
        Address(access,layout.metadataVtableRva,8,&ignored) &&
        Address(access,layout.builderRva,1,&ignored) &&
        Address(access,layout.selectedIdRva,4,&ignored) &&
        Address(access,layout.invalidIdRva,4,&ignored) &&
        Address(access,layout.counterRva,4,&ignored) &&
        Address(access,layout.serviceStateRva,4,&ignored);
}
// Native data and stack/heap holders must be readable non-executable storage.
// Bound even adversarial query-region fragmentation; never directly dereference.
bool DataRange(const TaskAccess& access, std::uintptr_t address, std::size_t bytes,
    bool image, bool writable, DWORD* error) noexcept {
    if (!Owner(access) || !address || !bytes || !access.memory.query ||
        bytes>(std::numeric_limits<std::uintptr_t>::max)()-address) return false;
    const auto end=address+bytes;
    for (unsigned regions=0; address<end && regions<16; ++regions) {
        MemoryRegion region{};
        if (!Owner(access) || !access.memory.query(access.memory.context,address,&region,error) ||
            !Owner(access) ||
            region.state!=MEM_COMMIT || region.base>address || !region.size ||
            region.size>(std::numeric_limits<std::uintptr_t>::max)()-region.base ||
            region.base+region.size<=address ||
            (region.protect!=PAGE_READONLY && region.protect!=PAGE_READWRITE &&
             region.protect!=PAGE_WRITECOPY) ||
            (writable && region.protect!=PAGE_READWRITE) ||
            (image && (region.type!=MEM_IMAGE || region.allocationBase!=access.hostBase))) return false;
        address=region.base+region.size<end ? region.base+region.size : end;
    }
    return address==end && Owner(access);
}
template<class T> bool DataRead(const TaskAccess& access, std::uintptr_t address,
    T* output, bool image, DWORD* error) noexcept {
    return output && access.memory.read && DataRange(access,address,sizeof(T),image,false,error) &&
        Owner(access) && access.memory.read(access.memory.context,address,output,sizeof(T),error) &&
        Owner(access);
}
template<class T> bool ImageRead(const TaskAccess& access, std::uint32_t rva,
    T* output, DWORD* error) noexcept {
    std::uintptr_t address{};
    return Address(access,rva,sizeof(T),&address) && DataRead(access,address,output,true,error);
}
bool SlotAddress(const TaskAccess& access, const TaskLayout& layout,
    std::uint32_t slot, std::uintptr_t* address) noexcept {
    return slot<kTaskSlots && LayoutValid(access,layout) &&
        Address(access,layout.poolRva+slot*kStride,kStride,address);
}
bool EpochEqual(TaskEpoch a, TaskEpoch b) noexcept {
    return a.source==b.source && a.binding==b.binding;
}
bool Queued(std::uint32_t state) noexcept { return state==2 || state==3; }

struct Header { std::uint32_t state; std::uint32_t id; };
// Fixed, same-object spans only. Deliberately skip slot+10..37, which contains
// unrelated request storage. Padding is never interpreted, retained or logged.
struct SlotHead { Header header; std::uintptr_t component; };
struct SlotParameters {
    std::uint32_t holder;
    std::uint32_t padding;
    std::uintptr_t builder;
    std::uintptr_t callbacks[2];
};
struct SlotAuthorityFields {
    SlotParameters parameters;
    std::uint64_t ignoredAnchor;
    std::uint64_t interval;
};
struct SlotAuthority { std::uintptr_t callbacks[2]; std::uint64_t interval; };
struct SlotSchedule {
    std::uint64_t anchorBits;
    std::uint64_t interval;
    std::int32_t errors;
    std::int32_t throttles;
    std::uint8_t expedite;
    std::uint8_t padding[7];
};
struct MetadataSchedule {
    std::uint16_t unusedFlags;
    std::uint16_t retryLimit;
    std::uint32_t padding;
    std::int64_t intervalOverride;
    std::int64_t retryOverride;
};
static_assert(sizeof(SlotHead)==0x10 && offsetof(SlotHead,component)==8);
static_assert(sizeof(SlotParameters)==0x20 && offsetof(SlotParameters,builder)==8 &&
    offsetof(SlotParameters,callbacks)==0x10);
static_assert(sizeof(SlotAuthorityFields)==0x30 && offsetof(SlotAuthorityFields,ignoredAnchor)==0x20 &&
    offsetof(SlotAuthorityFields,interval)==0x28);
static_assert(sizeof(SlotSchedule)==0x20 && offsetof(SlotSchedule,errors)==0x10 &&
    offsetof(SlotSchedule,expedite)==0x18);
static_assert(sizeof(MetadataSchedule)==0x18 && offsetof(MetadataSchedule,retryLimit)==2 &&
    offsetof(MetadataSchedule,intervalOverride)==8 && offsetof(MetadataSchedule,retryOverride)==0x10);
bool SlotRead(const TaskAccess& access, const TaskLayout& layout, std::uint32_t index,
    TaskSnapshot* snapshot, DWORD* error) noexcept {
    std::uintptr_t slot{};
    Header header{};
    if (!SlotAddress(access,layout,index,&slot) || !DataRead(access,slot,&header,true,error)) return false;
    snapshot->identity.slot=index;
    snapshot->identity.id=header.id; snapshot->state=header.state;
    return DataRead(access,slot+8,&snapshot->identity.component,true,error) &&
        DataRead(access,slot+0x38,&snapshot->identity.holder,true,error) &&
        DataRead(access,slot+kBuilderOffset,&snapshot->builder,true,error) &&
        ImageRead(access,layout.registryRva,&snapshot->identity.metadata,error);
}
bool SlotAuthorityRead(const TaskAccess& access,const TaskLayout& layout,std::uint32_t index,
    TaskSnapshot* snapshot,SlotAuthority* authority,DWORD* error) noexcept {
    std::uintptr_t slot{};
    SlotHead head{}; SlotAuthorityFields fields{};
    if (!SlotAddress(access,layout,index,&slot) || !DataRead(access,slot,&head,true,error)) return false;
    if (!DataRead(access,slot+0x38,&fields,true,error)) {
        // The intervening anchor is diagnostic-only. Discard every byte from
        // a failed combined read and retry only the original required spans.
        // Each fallback retains its own ownership/protection/read guards.
        fields={};
        if (!DataRead(access,slot+0x38,&fields.parameters,true,error) ||
            !DataRead(access,slot+0x60,&fields.interval,true,error)) return false;
    }
    if (!ImageRead(access,layout.registryRva,&snapshot->identity.metadata,error)) return false;
    const auto& parameters=fields.parameters;
    snapshot->identity.slot=index; snapshot->identity.id=head.header.id;
    snapshot->identity.component=head.component; snapshot->identity.holder=parameters.holder;
    snapshot->state=head.header.state; snapshot->builder=parameters.builder;
    authority->callbacks[0]=parameters.callbacks[0]; authority->callbacks[1]=parameters.callbacks[1];
    authority->interval=fields.interval;
    return true;
}
bool SameSnapshot(const TaskSnapshot& a, const TaskSnapshot& b) noexcept {
    return EqualTaskIdentity(a.identity,b.identity) && a.state==b.state &&
        a.nativeCounter==b.nativeCounter && a.builder==b.builder;
}
bool ReadSchedule(const TaskAccess& access,const TaskLayout& layout,
    const TaskIdentity& identity,TaskSchedule* output,DWORD* error) noexcept {
    *output={};
    std::uintptr_t slot{};
    if (!SlotAddress(access,layout,identity.slot,&slot) || !identity.metadata ||
        identity.metadata>(std::numeric_limits<std::uintptr_t>::max)()-0x20) return false;
    // Getter layouts are cold-qualified. Keep these optional, same-object
    // reads separate from authority: one partial diagnostic span invalidates
    // this observation, never the otherwise supported task binding.
    SlotSchedule schedule{}; MetadataSchedule metadata{};
    if (!DataRead(access,slot+0x58,&schedule,true,error) ||
        !DataRead(access,identity.metadata+8,&metadata,false,error)) return false;
    output->anchorBits=schedule.anchorBits; output->interval=schedule.interval;
    output->errors=schedule.errors; output->throttles=schedule.throttles;
    output->expedite=schedule.expedite; output->retryLimit=metadata.retryLimit;
    output->intervalOverride=metadata.intervalOverride; output->retryOverride=metadata.retryOverride;
    return true;
}
void ScheduleDelay(std::uint32_t nativeState,TaskSchedule& schedule) noexcept {
    // Only the supported live-default model is labeled a native tier. Other
    // observed scalars remain available, but no unqualified effective delay is
    // guessed. Poll state 2 never inherits the retry ladder from its counters.
    if (!schedule.valid || schedule.interval!=kInterval || schedule.retryLimit!=3 ||
        schedule.intervalOverride || schedule.retryOverride) return;
    if (nativeState==2) { schedule.tier=ScheduleTier::OrdinaryPoll; schedule.delayUnits=kInterval; return; }
    if (nativeState!=3 || schedule.errors<0 || schedule.throttles<0) return;
    schedule.tier=ScheduleTier::RetryBase; schedule.delayUnits=2000;
    if (schedule.throttles>5 || schedule.errors>=3) { schedule.tier=ScheduleTier::Retry30s; schedule.delayUnits=30000; }
    if (schedule.errors>=6) { schedule.tier=ScheduleTier::Retry60s; schedule.delayUnits=60000; }
    if (schedule.errors>=9) { schedule.tier=ScheduleTier::Retry5m; schedule.delayUnits=300000; }
    if (schedule.errors>=12) { schedule.tier=ScheduleTier::Retry30m; schedule.delayUnits=1800000; }
}
bool Counter(TaskBinding& state, const TaskSnapshot& snapshot) noexcept {
    // BF7E41..4F increments this unsigned DWORD for EACH native task creation.
    // This is the native recipe, not a guessed per-heartbeat sequence number.
    if (!snapshot.nativeCounter || snapshot.identity.id>snapshot.nativeCounter ||
        (state.haveCounter && snapshot.nativeCounter<state.lastNativeCounter)) return false;
    state.haveCounter=true;
    state.lastNativeCounter=snapshot.nativeCounter;
    return true;
}
bool History(TaskBinding& state, const TaskSnapshot& snapshot) noexcept {
    const auto previousCounter=state.lastNativeCounter;
    const bool hadCounter=state.haveCounter;
    if (!Counter(state,snapshot)) return false;
    if (!state.haveHistory) return true;
    if (snapshot.identity.id==state.lastBoundId)
        return state.continuingTask && EqualTaskIdentity(snapshot.identity,state.lastIdentity);
    // Other native operations also consume IDs. A genuinely new task after an
    // observed lifetime must be newer than that observed GLOBAL counter, not
    // merely larger than the previous heartbeat's ID.
    return snapshot.identity.id>state.lastBoundId &&
        (!hadCounter || snapshot.identity.id>previousCounter);
}
// Cleanup does not depend on a live source or on the old tuple still owning the
// slot. It depends ONLY on a safe fixed host table and exact pointer ownership.
void Inverse(TaskBinding& state, const TaskAccess& access, const TaskLayout& layout) noexcept {
    state.inverseAttempted=false; state.stranded=state.haveIdentity;
    if (!state.haveIdentity || !Owner(access) || !access.compareExchange) return;
    std::uintptr_t slot{}, current{};
    if (!SlotAddress(access,layout,state.identity.slot,&slot) ||
        !DataRead(access,slot+kBuilderOffset,&current,true,&state.lastError)) return;
    if (current!=state.wrapper) { state.stranded=false; return; }
    if (!DataRange(access,slot+kBuilderOffset,sizeof(current),true,true,&state.lastError) ||
        !Owner(access)) return;
    state.inverseAttempted=true;
    std::uintptr_t observed{};
    (void)access.compareExchange(access.context,slot+kBuilderOffset,state.wrapper,
        state.original,&observed,&state.lastError);
    const DWORD inverseError=state.lastError;
    // Even an API-reported failure may have performed its write. Re-read once;
    // never retry a CAS with a changed expected pointer and never write foreign.
    if (DataRead(access,slot+kBuilderOffset,&current,true,&state.lastError))
        state.stranded=current==state.wrapper;
    if (inverseError) state.lastError=inverseError;
}
Reason Fault(TaskBinding& state, const TaskAccess& access, const TaskLayout& layout,
    Reason reason, bool inverse=true) noexcept {
    const DWORD failureError=state.lastError;
    if (state.fault==Reason::None) state.fault=reason;
    Phase(state,TaskPhase::Inert);
    if (inverse) Inverse(state,access,layout);
    if (failureError) state.lastError=failureError;
    return state.fault;
}
bool OriginalMatches(const TaskBinding& state, const TaskAccess& access,
    const TaskLayout& layout) noexcept {
    std::uintptr_t expected{};
    return Address(access,layout.builderRva,1,&expected) && state.original==expected &&
        state.wrapper && state.wrapper!=state.original;
}
} // namespace

const TaskLayout& ProductionTaskLayout() noexcept { return kProduction; }
TaskPhase ReadTaskPhase(TaskBinding& state) noexcept {
    return static_cast<TaskPhase>(InterlockedCompareExchange(&state.phase,0,0));
}
bool EqualTaskIdentity(const TaskIdentity& a, const TaskIdentity& b) noexcept {
    return a.slot==b.slot && a.id==b.id && a.holder==b.holder &&
        a.component==b.component && a.metadata==b.metadata;
}
bool EqualTaskSchedule(const TaskSchedule& a,const TaskSchedule& b) noexcept {
    return a.anchorBits==b.anchorBits && a.interval==b.interval &&
        a.intervalOverride==b.intervalOverride && a.retryOverride==b.retryOverride &&
        a.errors==b.errors && a.throttles==b.throttles && a.retryLimit==b.retryLimit &&
        a.expedite==b.expedite && a.valid==b.valid && a.tier==b.tier && a.delayUnits==b.delayUnits;
}
Reason InitializeTaskBinding(TaskBinding& state, std::uintptr_t original,
    std::uintptr_t wrapper) noexcept {
    state={};
    state.original=original; state.wrapper=wrapper;
    if (!original || !wrapper || original==wrapper) {
        state.fault=Reason::PreparationFailed; Phase(state,TaskPhase::Inert); return state.fault;
    }
    return Reason::None;
}
namespace {
Reason ReadTask(const TaskAccess& initialAccess, const TaskLayout& layout,
    const TaskIdentity* bound, std::uint32_t minimumCounter, TaskSnapshot* output) noexcept {
    // Cache only query metadata during this bounded read pass, never task bytes
    // or table lifetime. Install/retire CAS paths keep the uncached caller ops.
    ReadScope scope(initialAccess.memory);
    auto access=initialAccess;
    access.memory=scope.Ops();
    if (output) *output={};
    const auto entry=EntryReason(access);
    if (entry!=Reason::None) return entry;
    if (!output || !LayoutValid(access,layout)) return Reason::ProfileMismatch;
    if (!Admit(access)) return Reason::LifecycleCrossing;
    DWORD error{};
    std::uint32_t selected{}, sentinel{}, counter{}, service{};
    if (!ImageRead(access,layout.selectedIdRva,&selected,&error) ||
        !ImageRead(access,layout.invalidIdRva,&sentinel,&error) ||
        !ImageRead(access,layout.counterRva,&counter,&error) ||
        !ImageRead(access,layout.serviceStateRva,&service,&error)) return Reason::TaskMismatch;
    if (bound && (!counter || counter<minimumCounter || selected>counter)) return Reason::TaskReused;
    if (sentinel!=0) return Reason::TaskMismatch;
    if (!selected) return Reason::TaskNotReady;
    if (service!=3) return Reason::Unregistered;
    if (!counter || selected>counter) return Reason::TaskReused;
    TaskSnapshot value{};
    SlotAuthority authority{};
    if (bound) {
        // The saved token chooses only an in-image fixed slot. Pointer fields
        // used below are freshly resolved from that slot and the fixed registry,
        // never dereferenced from a retained identity token.
        if (selected!=bound->id) return Reason::TaskMismatch;
        if (!SlotAuthorityRead(access,layout,bound->slot,&value,&authority,&error)) return Reason::TaskMismatch;
        if (!value.state) return Reason::TaskNotReady;
        if (value.identity.id!=selected) return Reason::TaskMismatch;
    } else {
        unsigned matches{};
        for (std::uint32_t index=0; index<kTaskSlots; ++index) {
            std::uintptr_t slot{};
            Header header{};
            if (!SlotAddress(access,layout,index,&slot) || !DataRead(access,slot,&header,true,&error))
                return Reason::TaskMismatch;
            if (!header.state || header.id!=selected) continue;
            if (++matches>1) return Reason::TaskAmbiguous;
            if (!SlotAuthorityRead(access,layout,index,&value,&authority,&error) ||
                value.state!=header.state || value.identity.id!=header.id) return Reason::TaskMismatch;
        }
        if (!matches) return Reason::TaskNotReady;
    }
    if (value.state<2 || value.state>5) return Reason::TaskNotReady;
    if (!value.identity.component || !DataRange(access,value.identity.component,1,false,false,&error))
        return Reason::TaskMismatch;
    if ((value.identity.holder>>16)!=kHolderType) return Reason::HolderMismatch;
    if (!value.identity.metadata) return Reason::TaskNotReady;
    std::uintptr_t vtable{};
    if ((value.identity.metadata&7) ||
        !DataRead(access,value.identity.metadata,&vtable,false,&error) ||
        vtable!=access.hostBase+layout.metadataVtableRva) return Reason::TaskMismatch;
    if (authority.callbacks[0] || authority.callbacks[1] || authority.interval!=kInterval || !value.builder)
        return Reason::TaskMismatch;
    TaskSchedule scheduleBefore{},scheduleAfter{};
    const bool scheduleRead=ReadSchedule(access,layout,value.identity,&scheduleBefore,&error);
    TaskSnapshot check{};
    SlotAuthority authorityAgain{};
    std::uintptr_t vtableAgain{};
    std::uint32_t selectedAgain{}, sentinelAgain{}, counterAgain{}, serviceAgain{};
    scope.Reset(); // Independent protection and identity reread, not a cached postcheck.
    if (!SlotAuthorityRead(access,layout,value.identity.slot,&check,&authorityAgain,&error) ||
        !ImageRead(access,layout.selectedIdRva,&selectedAgain,&error) ||
        !ImageRead(access,layout.invalidIdRva,&sentinelAgain,&error) ||
        !ImageRead(access,layout.counterRva,&counterAgain,&error) ||
        !ImageRead(access,layout.serviceStateRva,&serviceAgain,&error)) return Reason::TaskMismatch;
    if (bound && (!counterAgain || counterAgain<counter || counterAgain<minimumCounter ||
        selectedAgain>counterAgain)) return Reason::TaskReused;
    if (authorityAgain.callbacks[0] || authorityAgain.callbacks[1] || authorityAgain.interval!=authority.interval ||
        !DataRead(access,value.identity.metadata,&vtableAgain,false,&error) || vtableAgain!=vtable ||
        selectedAgain!=selected || sentinelAgain!=sentinel || counterAgain!=counter || serviceAgain!=service ||
        !EqualTaskIdentity(value.identity,check.identity) || value.state!=check.state ||
        value.builder!=check.builder || !Owner(access) || !Admit(access)) return Reason::TaskMismatch;
    // A fully rechecked replacement tuple with the SAME issued ID is not a
    // normal native lifetime transition. Keep the original permanent reuse
    // failure; transient/partial reads above remain only mismatches.
    if (bound && !EqualTaskIdentity(value.identity,*bound)) return Reason::TaskReused;
    // Diagnostics do not grant task authority or become an installation gate.
    // A racing/unsupported observation is explicitly unavailable, never stale.
    if (scheduleRead && ReadSchedule(access,layout,check.identity,&scheduleAfter,&error) &&
        EqualTaskSchedule(scheduleBefore,scheduleAfter)) {
        value.schedule=scheduleAfter; value.schedule.valid=true;
        ScheduleDelay(value.state,value.schedule);
    }
    if (!Owner(access) || !Admit(access)) return Reason::LifecycleCrossing;
    value.nativeCounter=counter;
    *output=value;
    return Reason::None;
}
} // namespace
Reason ReadSelectedTask(const TaskAccess& access, const TaskLayout& layout,
    TaskSnapshot* output) noexcept {
    return ReadTask(access,layout,nullptr,0,output);
}
Reason ReadBoundTask(TaskBinding& state, const TaskAccess& access,
    const TaskLayout& layout, TaskSnapshot* output) noexcept {
    if (output) *output={};
    const auto entry=EntryReason(access);
    if (entry!=Reason::None) return entry;
    if (ReadTaskPhase(state)==TaskPhase::Inert) return state.fault;
    if (ReadTaskPhase(state)!=TaskPhase::Armed) return Reason::TaskNotReady;
    if (!output || !OriginalMatches(state,access,layout)) return Reason::ProfileMismatch;
    // Armed publication follows both complete scans around installation. These
    // owner-only history predicates preserve that proof rather than allowing an
    // arbitrary slot hint to bypass initial/rebind uniqueness qualification.
    if (!state.haveIdentity || !state.haveHistory || !state.haveCounter || state.continuingTask ||
        !state.lastNativeCounter || !state.lastBoundId || state.identity.id!=state.lastBoundId ||
        !EqualTaskIdentity(state.identity,state.lastIdentity)) return Reason::TaskMismatch;
    TaskSnapshot current{};
    const auto read=ReadTask(access,layout,&state.identity,state.lastNativeCounter,&current);
    if (read!=Reason::None) return read==Reason::TaskReused ? Fault(state,access,layout,read) : read;
    if (ReadTaskPhase(state)!=TaskPhase::Armed || !state.haveIdentity ||
        !EqualTaskIdentity(current.identity,state.identity)) return Reason::TaskMismatch;
    if (!Counter(state,current)) return Fault(state,access,layout,Reason::TaskReused);
    *output=current;
    return Reason::None;
}
Reason InstallTaskBinding(TaskBinding& state, const TaskAccess& access,
    const TaskLayout& layout, TaskEpoch epoch, TaskSnapshot* installed) noexcept {
    if (installed) *installed={};
    const auto entry=EntryReason(access);
    if (entry!=Reason::None) return entry;
    if (ReadTaskPhase(state)==TaskPhase::Inert) return state.fault;
    if (ReadTaskPhase(state)==TaskPhase::Armed) return Reason::TaskNotReady;
    if (ReadTaskPhase(state)==TaskPhase::Preparing)
        return Fault(state,access,layout,Reason::Reentry);
    if (!epoch.source || !epoch.binding || !LayoutValid(access,layout) ||
        !OriginalMatches(state,access,layout) || !access.compareExchange) return Reason::ProfileMismatch;
    if (epoch.source<state.epoch.source || epoch.binding<state.epoch.binding)
        return Fault(state,access,layout,Reason::SourceLifetime);
    TaskSnapshot before{};
    const auto read=ReadSelectedTask(access,layout,&before);
    if (read!=Reason::None) return read==Reason::TaskReused ? Fault(state,access,layout,read) : read;
    if (!Queued(before.state)) return Reason::TaskNotReady;
    if (before.builder==state.wrapper) {
        // Remember ONLY the fixed cell needed for the owned inverse, never
        // acquire active authority over an unexpected/successor wrapper.
        state.identity=before.identity; state.haveIdentity=true;
        return Fault(state,access,layout,Reason::StrandedWrapper);
    }
    if (before.builder!=state.original) return Reason::BuilderChanged;
    if (!History(state,before)) return Fault(state,access,layout,Reason::TaskReused);
    if (state.haveHistory && !EqualTaskIdentity(before.identity,state.lastIdentity) &&
        epoch.binding<=state.epoch.binding)
        return Fault(state,access,layout,Reason::SourceLifetime);
    std::uintptr_t slot{};
    if (!SlotAddress(access,layout,before.identity.slot,&slot) ||
        !DataRange(access,slot+kBuilderOffset,sizeof(std::uintptr_t),true,true,&state.lastError))
        return Reason::WriteFault;
    if (!Admit(access)) return Reason::LifecycleCrossing;
    state.identity=before.identity; state.epoch=epoch; state.haveIdentity=true;
    state.inverseAttempted=false; state.stranded=false;
    Phase(state,TaskPhase::Preparing);
    std::uintptr_t observed{};
    if (!Owner(access) || !Admit(access) ||
        !access.compareExchange(access.context,slot+kBuilderOffset,state.original,state.wrapper,
            &observed,&state.lastError) || observed!=state.original)
        return Fault(state,access,layout,Reason::InstallFailed);
    TaskSnapshot after{};
    before.builder=state.wrapper;
    if (ReadSelectedTask(access,layout,&after)!=Reason::None ||
        !SameSnapshot(before,after) || !Queued(after.state) || !Owner(access) || !Admit(access))
        return Fault(state,access,layout,Reason::PostcheckFailed);
    state.lastIdentity=after.identity; state.lastBoundId=after.identity.id;
    state.haveHistory=true; state.continuingTask=false;
    if (InterlockedCompareExchange(&state.phase,static_cast<LONG>(TaskPhase::Armed),
        static_cast<LONG>(TaskPhase::Preparing))!=static_cast<LONG>(TaskPhase::Preparing))
        return Fault(state,access,layout,Reason::InstallFailed);
    if (installed) *installed=after;
    return Reason::None;
}
Reason ValidateBuilderTask(TaskBinding& state, const TaskAccess& access,
    const TaskLayout& layout, TaskEpoch epoch, const void* borrowedHolder,
    TaskSnapshot* output) noexcept {
    if (output) *output={};
    const auto entry=EntryReason(access);
    if (entry!=Reason::None) return entry;
    if (ReadTaskPhase(state)==TaskPhase::Inert) return state.fault;
    if (ReadTaskPhase(state)!=TaskPhase::Armed) return Reason::TaskNotReady;
    if (!EpochEqual(epoch,state.epoch)) return Reason::SourceLifetime;
    if (!output || !OriginalMatches(state,access,layout)) return Reason::ProfileMismatch;
    if (!Admit(access)) return Reason::LifecycleCrossing;
    std::uint32_t holder{};
    DWORD error{};
    if (!DataRead(access,reinterpret_cast<std::uintptr_t>(borrowedHolder),&holder,false,&error) ||
        holder!=state.identity.holder) return Reason::HolderMismatch;
    TaskSnapshot current{};
    const auto read=ReadBoundTask(state,access,layout,&current);
    if (read!=Reason::None) {
        // The ordinary unchanged binding is scan-free. Only a mismatch needs
        // the old full selection semantics to distinguish a validated different
        // task from a partial/torn read. Never adopt this fallback observation.
        if (read==Reason::TaskMismatch && ReadTaskPhase(state)==TaskPhase::Armed) {
            TaskSnapshot changed{};
            const auto classified=ReadSelectedTask(access,layout,&changed);
            if (classified==Reason::TaskReused || (classified==Reason::None &&
                (changed.nativeCounter<state.lastNativeCounter ||
                 !EqualTaskIdentity(changed.identity,state.identity))))
                return Fault(state,access,layout,Reason::TaskReused);
        }
        return read; // ReadBoundTask already latched any permanent counter/reuse fault.
    }
    if (!EqualTaskIdentity(current.identity,state.identity))
        return Fault(state,access,layout,Reason::TaskReused);
    if (!Queued(current.state)) return Reason::TaskNotReady;
    if (current.builder!=state.wrapper)
        return Fault(state,access,layout,Reason::BuilderChanged);
    *output=current;
    return Reason::None;
}
Reason RetireTaskBinding(TaskBinding& state, const TaskAccess& access,
    const TaskLayout& layout, Reason fault) noexcept {
    const auto entry=EntryReason(access);
    if (entry!=Reason::None) return entry;
    if (ReadTaskPhase(state)==TaskPhase::Inert) return state.fault;
    if (fault!=Reason::None) return Fault(state,access,layout,fault);
    if (!state.haveIdentity) {
        // A second management visit may observe native destruction after an
        // earlier healthy restoration. That is no longer the same continuing
        // lifetime, even if the slot/holder values later happen to repeat.
        if (state.continuingTask) {
            TaskSnapshot current{};
            if (!SlotRead(access,layout,state.lastIdentity.slot,&current,&state.lastError) ||
                !current.state || !EqualTaskIdentity(current.identity,state.lastIdentity) ||
                current.builder!=state.original) state.continuingTask=false;
        }
        Phase(state,TaskPhase::Retired); return Reason::None;
    }
    if (!OriginalMatches(state,access,layout)) return Fault(state,access,layout,Reason::ProfileMismatch);
    TaskSnapshot current{};
    if (!SlotRead(access,layout,state.identity.slot,&current,&state.lastError))
        return Fault(state,access,layout,Reason::TaskMismatch);
    if (current.builder!=state.wrapper) {
        // A native destructor/constructor can have reused the fixed slot. It
        // owns those new contents; absence of our pointer permits retirement,
        // but never writes or adopts the successor. Same-ID replacement is not
        // normal reclamation and must not silently restore active authority.
        if (current.state && current.identity.id==state.identity.id)
            return Fault(state,access,layout,Reason::BuilderChanged);
        state.haveIdentity=false; state.continuingTask=false;
        Phase(state,TaskPhase::Retired); return Reason::None;
    }
    if (!EqualTaskIdentity(current.identity,state.identity))
        return Fault(state,access,layout,Reason::StrandedWrapper);
    if (current.state==4 || current.state==5) return Reason::TaskNotReady;
    if (!Queued(current.state)) return Fault(state,access,layout,Reason::TaskMismatch);
    std::uintptr_t slot{};
    if (!SlotAddress(access,layout,state.identity.slot,&slot) ||
        !DataRange(access,slot+kBuilderOffset,sizeof(std::uintptr_t),true,true,&state.lastError))
        return Fault(state,access,layout,Reason::WriteFault);
    Phase(state,TaskPhase::Retired);
    state.inverseAttempted=true;
    std::uintptr_t observed{};
    const bool ok=Owner(access) && access.compareExchange &&
        access.compareExchange(access.context,slot+kBuilderOffset,state.wrapper,state.original,
            &observed,&state.lastError) && observed==state.wrapper;
    const DWORD mutationError=state.lastError;
    TaskSnapshot after{};
    const bool checked=SlotRead(access,layout,state.identity.slot,&after,&state.lastError);
    if (!ok && mutationError) state.lastError=mutationError;
    state.stranded=!checked || after.builder==state.wrapper;
    if (!ok || !checked || !EqualTaskIdentity(current.identity,after.identity) ||
        current.state!=after.state || after.builder!=state.original || !Owner(access))
        return Fault(state,access,layout,Reason::PostcheckFailed,false);
    state.haveIdentity=false; state.continuingTask=true;
    return Reason::None;
}
} // namespace rs2fix::reporting
