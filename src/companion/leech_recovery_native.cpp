#include "companion/leech_recovery_native.h"
#include "companion/steam_reporting_read_scope.h"
#include <algorithm>
#include <cstring>
#include <iterator>
#include <limits>
#include <climits>
#include <bcrypt.h>

namespace rs2fix::reporting {
namespace {
#include "companion/leech_recovery_native_profile_data.inc"
#include "companion/leech_recovery_metadata_profile_data.inc"
constexpr RecoveryNativeLayout kLayout{
    0x17AAC80,0x17AAC78,0x17AA9C0,0x14AAD8C,0x179D450,
    0x14AAD20,0x14AAD28,0x14A4A08,0x1798800,0x17AEA18,0x14AAD70,
    0x14AAB70,0x17AEB88,0x179D228,0x17AEA10,0x17AEB78,0x17AA9F8,
    0x17AA9D0,0x17AA9D1,0x17AA9D2,0x179D3C8,
    0x14CC240,0x11CE340,0x14AF2C0,0x14AF2C8,
    0x14AACB0,0x14AAEE0,0x14AAED8,0x14AAE20,0x14AAE18,
    0x1276F80,0x1276B20,0x1276D60,0x127B988,
    0x14AAB78
};
struct ComponentRecipe { const char* name; std::uint32_t start, stop, status, policy; };
constexpr ComponentRecipe kComponents[]{
    {"AsyncDeferOperationsComponent",0xBA4C40,0xBA4C90,0xBA4CE0,1},
    {"AuthorizationComponent",0xBFBB70,0xBFC4E0,0xBFC510,1},
    {"FactComponent",0xBAE3E0,0xBAE400,0xBAE420,2},
    {"StandaloneServer",0xBAB210,0xBAB230,0xBAB350,3},
    {"Presence",0xBFAA50,0xBFAC40,0xBFAD60,3},
    {"UserHeartbeatComponent",0xC09A30,0xC09BA0,0xC09C60,3},
    {"MessagingComponent",0xC0A7F0,0xC0AB20,0xC0AE60,3},
    {"GlobalEssentialComponentHack",0xBF60A0,0xBF60A0,0xBF6090,4}
};
bool Add(std::uintptr_t base,std::size_t size,std::uintptr_t* out) noexcept {
    if (!base || size>(std::numeric_limits<std::uintptr_t>::max)()-base) return false;
    *out=base+size;return true;
}
class Reader {
public:
    Reader(const RecoveryNativeContext& context,DWORD* error) noexcept : c_(context),e_(error),
        l_(context.layout?*context.layout:kLayout),scope_(context.memory),
        sections_(context.hostBase,context.hostImageSize,scope_.Ops()) {}
    void Reset() const noexcept {scope_.Reset();sections_.Reset();totalVectorElements_=0;}
    bool Range(std::uintptr_t address,std::size_t bytes,bool writable=false,bool heap=false) const noexcept {
        std::uintptr_t end{};
        if (!bytes || !Add(address,bytes,&end)) return false;
        std::size_t regions{};
        for (auto at=address;at<end;) {
            MemoryRegion r{};
            const auto& memory=scope_.Ops();
            if (++regions>32 || !memory.query(memory.context,at,&r,e_) ||
                r.state!=MEM_COMMIT || (r.protect&(PAGE_GUARD|PAGE_NOACCESS)) ||
                (r.protect!=PAGE_READONLY && r.protect!=PAGE_READWRITE) ||
                (writable && r.protect!=PAGE_READWRITE) ||
                (heap && r.type!=MEM_PRIVATE) ||
                (r.type!=MEM_PRIVATE && !(r.type==MEM_IMAGE && r.allocationBase==c_.hostBase)) ||
                !r.size || r.base>at || r.size>(std::numeric_limits<std::uintptr_t>::max)()-r.base ||
                at>=r.base+r.size) return false;
            at=(std::min)(end,r.base+r.size);
        }
        return true;
    }
    bool Read(std::uintptr_t address,void* out,std::size_t bytes,bool writable=false,bool heap=false) const noexcept {
        const auto& memory=scope_.Ops();
        return Range(address,bytes,writable,heap) && memory.read(memory.context,address,out,bytes,e_);
    }
    template<class T> bool Field(std::uintptr_t object,std::size_t offset,T& out) const noexcept {
        std::uintptr_t address{};
        return Add(object,offset,&address) && Read(address,&out,sizeof(out));
    }
    template<class T> bool Global(std::uint32_t rva,T& out) const noexcept {
        return rva<c_.hostImageSize && sizeof(out)<=c_.hostImageSize-rva &&
            Read(c_.hostBase+rva,&out,sizeof(out));
    }
    bool ConstName(std::uintptr_t pointer,const char* expected) const noexcept {
        const auto bytes=std::strlen(expected)+1;
        if (pointer<c_.hostBase || pointer-c_.hostBase>UINT32_MAX) return false;
        const auto rva=static_cast<std::uint32_t>(pointer-c_.hostBase);
        char data[64]{};
        const auto& memory=scope_.Ops();
        return bytes<=sizeof(data) && ImageRangeProtection(c_.hostBase,c_.hostImageSize,rva,bytes,PAGE_READONLY,memory,e_) &&
            sections_.Matches(rva,bytes,IMAGE_SCN_MEM_READ,
                IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_DISCARDABLE) &&
            memory.read(memory.context,pointer,data,bytes,e_) && !std::memcmp(data,expected,bytes);
    }
    bool Interval(RecoveryNativeSnapshot& snapshot,std::uintptr_t begin,std::size_t bytes) const noexcept {
        std::uintptr_t end{};
        if (!bytes) return true;
        if (!Add(begin,bytes,&end) || snapshot.intervalCount==kRecoveryOwnedIntervals) return false;
        for (std::uint32_t i=0;i<snapshot.intervalCount;++i) {
            const auto& other=snapshot.intervals[i];
            if (begin<other.end && other.begin<end) return false;
        }
        snapshot.intervals[snapshot.intervalCount++]={begin,end};return true;
    }
    RecoveryNativeResult String(std::uintptr_t object,RecoveryNativeString& out,
        RecoveryNativeSnapshot* owner=nullptr) const noexcept {
        out={};out.object=object;
        if (!object || (object&7) || !Read(object,out.header,sizeof(out.header))) return RecoveryNativeResult::Unreadable;
        std::memcpy(&out.size,out.header+0x10,8);std::memcpy(&out.capacity,out.header+0x18,8);
        if (out.size>out.capacity) return RecoveryNativeResult::Shape;
        if (out.capacity>kRecoveryStringCapacity) return RecoveryNativeResult::Budget;
        if (out.capacity<16) {
            if (out.capacity!=15 || out.size>=16) return RecoveryNativeResult::Shape;
            out.data=object;
        } else {
            std::memcpy(&out.data,out.header,8);
            if (!out.data || (out.data&15) || !Range(out.data,static_cast<std::size_t>(out.capacity)+1,true,true))
                return RecoveryNativeResult::Shape;
            if (owner && !Interval(*owner,out.data,static_cast<std::size_t>(out.capacity)+1)) return RecoveryNativeResult::Alias;
        }
        std::uint8_t nul{};
        std::uintptr_t endpoint{};
        if (!Add(out.data,static_cast<std::size_t>(out.size),&endpoint) || !Read(endpoint,&nul,1) || nul)
            return RecoveryNativeResult::Shape;
        return RecoveryNativeResult::Ready;
    }
    RecoveryNativeResult AppendString(std::uintptr_t object,RecoveryNativeSnapshot& snapshot) const noexcept {
        if (snapshot.stringCount==kRecoveryStringWitnesses) return RecoveryNativeResult::Budget;
        auto result=String(object,snapshot.strings[snapshot.stringCount],&snapshot);
        if (result==RecoveryNativeResult::Ready) ++snapshot.stringCount;
        return result;
    }
    RecoveryNativeResult Vector(std::uintptr_t object,RecoveryNativeVector& out,
        RecoveryNativeSnapshot& snapshot) const noexcept {
        out={};out.object=object;
        std::uintptr_t fields[3]{};
        if (!Read(object,fields,sizeof(fields))) return RecoveryNativeResult::Unreadable;
        out.begin=fields[0];out.end=fields[1];out.capacity=fields[2];
        out.firstString=snapshot.stringCount;
        if (!out.begin) return (!out.end && !out.capacity)?RecoveryNativeResult::Ready:RecoveryNativeResult::Shape;
        if ((out.begin&15) || out.begin>out.end || out.end>out.capacity ||
            (out.end-out.begin)%32 || (out.capacity-out.begin)%32) return RecoveryNativeResult::Shape;
        const auto elements=(out.end-out.begin)/32, capacity=(out.capacity-out.begin)/32;
        if (elements>kRecoveryVectorElements || capacity>kRecoveryVectorCapacity ||
            totalVectorElements_>kRecoveryAllVectorElements-elements) return RecoveryNativeResult::Budget;
        if (!capacity || !Range(out.begin,capacity*32,true,true)) return RecoveryNativeResult::Shape;
        if (!Interval(snapshot,out.begin,capacity*32)) return RecoveryNativeResult::Alias;
        totalVectorElements_+=elements;
        for (std::size_t i=0;i<elements;++i) {
            const auto result=AppendString(out.begin+i*32,snapshot);
            if (result!=RecoveryNativeResult::Ready) return result;
        }
        out.stringCount=static_cast<std::uint32_t>(elements);return RecoveryNativeResult::Ready;
    }
    RecoveryNativeResult FString(std::uint32_t root,std::uintptr_t& data,std::int32_t& count,
        std::int32_t& capacity,std::uint16_t* chars,RecoveryNativeSnapshot& snapshot) const noexcept {
        struct Header {std::uintptr_t data;std::int32_t count,capacity;} value{};
        static_assert(sizeof(Header)==16);
        if(!Global(root,value)) return RecoveryNativeResult::Unreadable;
        if(value.count<0 || value.capacity<value.count || (!value.data && (value.count || value.capacity)))
            return RecoveryNativeResult::Shape;
        if(static_cast<std::size_t>(value.capacity)>kRecoveryCacheChars) return RecoveryNativeResult::Budget;
        data=value.data;count=value.count;capacity=value.capacity;
        const auto bytes=static_cast<std::size_t>(value.capacity)*sizeof(std::uint16_t);
        if(value.data && ((value.data&15) || !value.capacity || !Range(value.data,bytes,true,true) ||
            !Interval(snapshot,value.data,bytes))) return RecoveryNativeResult::Alias;
        if(value.count && (!Read(value.data,chars,static_cast<std::size_t>(value.count)*sizeof(std::uint16_t)) || chars[value.count-1]))
            return RecoveryNativeResult::Shape;
        return RecoveryNativeResult::Ready;
    }
    RecoveryNativeResult Pool(std::uintptr_t descriptor,std::uint16_t type,
        RecoveryDescriptor kind,RecoveryTypedPool& pool,RecoveryNativeSnapshot& snapshot) const noexcept {
        const std::size_t stride=kind==RecoveryDescriptor::Finish?0x30:kind==RecoveryDescriptor::Create?0x90:0x78;
        if (!descriptor || (descriptor&7) || !Range(descriptor,0x20+16*stride,true) ||
            !Interval(snapshot,descriptor,0x20+16*stride)) return RecoveryNativeResult::Descriptor;
        pool.descriptor=descriptor;pool.type=type;pool.firstFree=0xffff;
        for (std::uint16_t i=0;i<16;++i) {
            auto& slot=pool.slots[i];
            if (!Field(descriptor,0x20+i*stride,slot.references) || slot.references< -1) return RecoveryNativeResult::Pool;
            slot.payload=descriptor+0x28+i*stride;
            slot.firstString=snapshot.stringCount;
            const std::size_t offsets[]{0,kind==RecoveryDescriptor::Create?0x28u:0x20u,0x48,0x68};
            const unsigned count=kind==RecoveryDescriptor::Finish?1:kind==RecoveryDescriptor::Create?4:2;
            for (unsigned j=0;j<count;++j) {
                const auto result=AppendString(slot.payload+offsets[j],snapshot);
                if (result!=RecoveryNativeResult::Ready) return result;
            }
            slot.stringCount=count;
            if (kind==RecoveryDescriptor::Heartbeat) {
                const auto result=Vector(slot.payload+0x48,slot.vector,snapshot);
                if (result!=RecoveryNativeResult::Ready) return result;
            }
            if (slot.references== -1 && pool.firstFree==0xffff) pool.firstFree=i;
        }
        return RecoveryNativeResult::Ready;
    }
    RecoveryNativeResult Observe(RecoveryNativeSnapshot& out) const noexcept {
        // Equality includes POD padding; clear its object representation before
        // assigning fields, rather than relying on aggregate-init padding.
        std::memset(&out,0,sizeof(out));Reset();
        if (!Global(l_.standalone,out.standalone) || !Global(l_.core,out.core) ||
            !Global(l_.auth,out.auth) || !Global(l_.issuedId,out.issuedId) ||
            !Global(l_.invalidId,out.invalidId) || !Global(l_.heartbeatId,out.heartbeatId) ||
            !Global(l_.role,out.role) || !Global(l_.previousReady,out.previousReady) ||
            !Global(l_.previousConnected,out.previousConnected) || !Global(l_.connected,out.connected) ||
            !Global(l_.httpManager,out.httpManager) || !Global(l_.asyncManager,out.asyncManager) ||
            !Global(l_.gmalloc,out.gmalloc)) return RecoveryNativeResult::Unreadable;
        std::uintptr_t hook{},mallocHook{},freeHook{},table{};
        if (!Global(l_.statusHook,hook)) return RecoveryNativeResult::Unreadable;
        if (hook) return RecoveryNativeResult::Hook;
        if (!Global(l_.jsonMalloc,mallocHook) || !Global(l_.jsonFree,freeHook)) return RecoveryNativeResult::Unreadable;
        if (mallocHook!=c_.hostBase+0xC0EE30 || freeHook!=c_.hostBase+0xBFD630 ||
            !out.gmalloc || !Field(out.gmalloc,0,table) || table!=c_.hostBase+l_.gmallocVtable)
            return RecoveryNativeResult::Allocator;
        std::uintptr_t target{};
        if (!Field(table,0x18,target) || target!=c_.hostBase+0xA6CE90) return RecoveryNativeResult::Allocator;
        if (!out.httpManager || !Field(out.httpManager,0,table) || table!=c_.hostBase+l_.httpManagerVtable)
            return RecoveryNativeResult::Readiness;
        if (!out.asyncManager) return RecoveryNativeResult::Readiness;
        std::uint8_t active{};
        if (!Field(out.asyncManager,0,active) || !active) return RecoveryNativeResult::Readiness;
        for (const auto& import:kRecoveryImports) {
            std::uintptr_t actual{},expected{};
            if (!Global(import.slotRva,actual) || !c_.imports->resolve(c_.imports->context,import.module,import.name,&expected,e_) ||
                !expected || actual!=expected) return RecoveryNativeResult::Import;
        }
        if (!Global(l_.componentName,out.componentName) || !ConstName(out.componentName,"StandaloneServer") ||
            !Global(l_.finishService,out.finishService) || !ConstName(out.finishService,"45d1305aa6d846dcbb070dda4af292d4") ||
            !Global(l_.finishOperation,out.finishOperation) || !ConstName(out.finishOperation,"b9d34959ad8e491888c4fe0f7aa0c31b") ||
            !Global(l_.createService,out.createService) || !ConstName(out.createService,"45d1305aa6d846dcbb070dda4af292d4") ||
            !Global(l_.createOperation,out.createOperation) || !ConstName(out.createOperation,"82c2ef8d501d4158a7119cf664b544fe"))
            return RecoveryNativeResult::Descriptor;
        std::uint32_t seen{};
        for (std::size_t i=0;i<16;++i) {
            struct Row {std::uintptr_t start,stop,status,name;std::uint32_t policy,padding;} row{};
            if (!Global(l_.componentTable+static_cast<std::uint32_t>(i*0x28),row)) return RecoveryNativeResult::Unreadable;
            if (!row.start && !row.stop && !row.status && !row.name && !row.policy) continue;
            bool found{};
            for (unsigned j=0;j<std::size(kComponents);++j) {
                const auto& recipe=kComponents[j];
                if (row.start==c_.hostBase+recipe.start && row.stop==c_.hostBase+recipe.stop &&
                    row.status==c_.hostBase+recipe.status && row.policy==recipe.policy && ConstName(row.name,recipe.name)) {
                    if (seen&(1u<<j)) return RecoveryNativeResult::Readiness;
                    seen|=1u<<j;found=true;break;
                }
            }
            if (!found) return RecoveryNativeResult::Readiness;
        }
        if (seen!=0xff) return RecoveryNativeResult::Readiness;
        auto result=String(c_.hostBase+l_.sdkSession,out.sdkSession,&out);
        if (result!=RecoveryNativeResult::Ready) return result;
        result=String(c_.hostBase+l_.authorizationToken,out.authorizationToken,&out);
        if (result!=RecoveryNativeResult::Ready) return result;
        result=String(c_.hostBase+l_.cacheSession,out.cacheSession,&out);
        if (result!=RecoveryNativeResult::Ready) return result;
        result=String(c_.hostBase+l_.coreGuid,out.coreGuid,&out);
        if (result!=RecoveryNativeResult::Ready) return result;
        if (out.sdkSession.size>=sizeof(out.sdkBytes) || out.authorizationToken.size>=sizeof(out.authorizationBytes) ||
            out.cacheSession.size>=sizeof(out.cacheBytes) || out.coreGuid.size>=sizeof(out.coreGuidBytes)) return RecoveryNativeResult::Budget;
        if (!Read(out.sdkSession.data,out.sdkBytes,static_cast<std::size_t>(out.sdkSession.size)+1) ||
            !Read(out.authorizationToken.data,out.authorizationBytes,static_cast<std::size_t>(out.authorizationToken.size)+1) ||
            !Read(out.cacheSession.data,out.cacheBytes,static_cast<std::size_t>(out.cacheSession.size)+1) ||
            !Read(out.coreGuid.data,out.coreGuidBytes,static_cast<std::size_t>(out.coreGuid.size)+1)) return RecoveryNativeResult::Unreadable;
        result=Vector(c_.hostBase+l_.kernelVector,out.kernelVector,out);
        if (result!=RecoveryNativeResult::Ready) return result;
        result=FString(l_.publicIp,out.publicIpData,out.publicIpCount,out.publicIpCapacity,out.publicIpChars,out);
        if(result!=RecoveryNativeResult::Ready) return result;
        std::uintptr_t registry[256]{};
        if (!Global(l_.registry,registry) || registry[0]) return RecoveryNativeResult::Descriptor;
        RecoveryTypedPool* pools[]{&out.finish,&out.create,&out.heartbeat};
        const std::uint32_t tables[]{l_.finishVtable,l_.createVtable,l_.heartbeatVtable};
        const std::uint32_t allocators[]{0xBF0DB0,0xBF0E60,0xBF0F30};
        const std::uint32_t addrefs[]{0xBF1780,0xBF1790,0xBF17A0};
        const std::uint32_t releases[]{0xBF1900,0xBF1950,0xBF1980};
        const std::uint32_t resolves[]{0xBF1B20,0xBF1B50,0xBF1B70};
        for (unsigned j=0;j<3;++j) {
            const std::uintptr_t vtable=c_.hostBase+tables[j];
            const std::uint32_t offsets[]{0x28,0x88,0x90,0x98,0xA0};
            const std::uint32_t targets[]{0xBF55F0,allocators[j],addrefs[j],releases[j],resolves[j]};
            for (unsigned k=0;k<5;++k)
                if (!Field(vtable,offsets[k],target) || target!=c_.hostBase+targets[k]) return RecoveryNativeResult::Descriptor;
        }
        for (std::uint16_t i=1;i<256;++i) {
            if (!registry[i]) continue;
            if (!Field(registry[i],0,table)) return RecoveryNativeResult::Descriptor;
            for (unsigned j=0;j<3;++j) if (table==c_.hostBase+tables[j]) {
                std::uint16_t type{};
                if (pools[j]->descriptor || !Field(registry[i],8,type) || type!=i) return RecoveryNativeResult::Descriptor;
                result=Pool(registry[i],i,static_cast<RecoveryDescriptor>(j),*pools[j],out);
                if (result!=RecoveryNativeResult::Ready) return result;
            }
        }
        for (const auto pool:pools) if (!pool->descriptor) return RecoveryNativeResult::Descriptor;
        for (std::size_t i=0;i<128;++i) {
            auto& task=out.generic[i];
            if (!Read(c_.hostBase+l_.genericPool+i*0x78,task.raw,sizeof(task.raw))) return RecoveryNativeResult::Unreadable;
            std::memcpy(&task.state,task.raw,4);std::memcpy(&task.id,task.raw+4,4);
            std::memcpy(&task.component,task.raw+8,8);std::memcpy(&task.holder,task.raw+0x38,4);
            std::memcpy(&task.builder,task.raw+0x40,8);std::memcpy(&task.success,task.raw+0x48,8);
            std::memcpy(&task.error,task.raw+0x50,8);std::memcpy(&task.anchor,task.raw+0x58,8);
            std::memcpy(&task.interval,task.raw+0x60,8);std::memcpy(&task.errors,task.raw+0x68,4);
            std::memcpy(&task.throttles,task.raw+0x6c,4);task.expedite=task.raw[0x70];
            if (task.state>5 || task.state==1) return RecoveryNativeResult::Pool;
            if (!task.state) {++out.genericFree;continue;}
            const auto type=task.holder>>16,slot=task.holder&0xffff;
            if (!task.id || task.id==out.invalidId || task.id>out.issuedId || !type || type>=256 || !registry[type] || slot>=16)
                return RecoveryNativeResult::Pool;
            for (std::size_t j=0;j<i;++j) if (out.generic[j].state && task.id==out.generic[j].id) return RecoveryNativeResult::Pool;
            for (auto pool:pools) if (type==pool->type && pool->slots[slot].references<1) return RecoveryNativeResult::Pool;
        }
        // Known typed handles may have more than one legitimate cloned native
        // reference; every active generic reference must nevertheless be owned.
        for (const auto pool:pools) for (unsigned slot=0;slot<16;++slot) {
            unsigned refs{};
            for (const auto& task:out.generic) if (task.state && (task.holder>>16)==pool->type && (task.holder&0xffff)==slot) ++refs;
            if (refs && (pool->slots[slot].references<0 || refs>static_cast<unsigned>(pool->slots[slot].references))) return RecoveryNativeResult::Pool;
        }
        return RecoveryNativeResult::Ready;
    }
private:
    const RecoveryNativeContext& c_;
    DWORD* e_;
    const RecoveryNativeLayout& l_;
    mutable ReadScope scope_;
    mutable ImageSections sections_;
    mutable std::size_t totalVectorElements_{};
};
bool Context(const RecoveryNativeContext& c) noexcept {
    return c.hostBase && c.hostImageSize && c.hostImageSize<=(std::numeric_limits<std::uintptr_t>::max)()-c.hostBase &&
        c.memory.query && c.memory.read && c.imports && c.imports->resolve;
}
bool Random(void*,std::uint8_t* output,std::size_t bytes) noexcept {
    return output && bytes && bytes<=ULONG_MAX && BCryptGenRandom(nullptr,output,
        static_cast<ULONG>(bytes),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0;
}
constexpr RecoveryRandomOps kRandom{nullptr,Random};
bool SameString(const RecoveryNativeString& a,const RecoveryNativeString& b) noexcept {
    return a.object==b.object && a.data==b.data && a.size==b.size && a.capacity==b.capacity &&
        !std::memcmp(a.header,b.header,sizeof(a.header));
}
bool SameSlot(const RecoveryNativeSnapshot& a,const RecoveryTypedSlot& aa,
    const RecoveryNativeSnapshot& b,const RecoveryTypedSlot& bb) noexcept {
    if (aa.payload!=bb.payload || aa.stringCount!=bb.stringCount || aa.vector.object!=bb.vector.object ||
        aa.vector.begin!=bb.vector.begin || aa.vector.end!=bb.vector.end || aa.vector.capacity!=bb.vector.capacity ||
        aa.vector.stringCount!=bb.vector.stringCount) return false;
    for (std::uint32_t i=0;i<aa.stringCount;++i)
        if (!SameString(a.strings[aa.firstString+i],b.strings[bb.firstString+i])) return false;
    for (std::uint32_t i=0;i<aa.vector.stringCount;++i)
        if (!SameString(a.strings[aa.vector.firstString+i],b.strings[bb.vector.firstString+i])) return false;
    return true;
}
} // namespace
const RecoveryNativeLayout& ProductionRecoveryNativeLayout() noexcept {return kLayout;}
const char* NativeRecoveryInventorySha256() noexcept {return kRecoveryInventorySha256;}
const RecoveryRandomOps& ProductionRecoveryRandomOps() noexcept {return kRandom;}
const char* NativeRecoveryMetadataInventorySha256() noexcept {return kRecoveryMetadataInventorySha256;}
bool PrepareRecoveryMetadataMembers(RecoveryMetadataMembers& out,std::uint32_t count,
    const RecoveryRandomOps& random) noexcept {
    std::memset(&out,0,sizeof(out));
    if(count>kRecoveryMetadataMemberLimit || (count && !random.fill)) return false;
    std::uint8_t entropy[kRecoveryMetadataMemberLimit*16]{};
    if(count && !random.fill(random.context,entropy,static_cast<std::size_t>(count)*16)) return false;
    constexpr char hex[]="0123456789abcdef";
    for(std::uint32_t i=0;i<count;++i) {
        auto* uuid=entropy+static_cast<std::size_t>(i)*16;
        uuid[6]=static_cast<std::uint8_t>((uuid[6]&0x0f)|0x40);
        uuid[8]=static_cast<std::uint8_t>((uuid[8]&0x3f)|0x80);
        std::size_t cursor{};
        for(std::size_t byte=0;byte<16;++byte) {
            if(byte==4 || byte==6 || byte==8 || byte==10) out.text[i][cursor++]='-';
            out.text[i][cursor++]=hex[uuid[byte]>>4];
            out.text[i][cursor++]=hex[uuid[byte]&15];
        }
        // The zeroed final byte terminates each initialized 36-byte UUID.
        out.strings[i]={reinterpret_cast<std::uintptr_t>(out.text[i]),0,36,36};
    }
    out.vector.begin=reinterpret_cast<std::uintptr_t>(out.strings);
    out.vector.end=out.vector.begin+static_cast<std::uintptr_t>(count)*sizeof(out.strings[0]);
    out.vector.capacity=out.vector.end;
    out.count=count;
    return true;
}
ProfileResult ValidateNativeRecoveryProfile(std::uintptr_t base,const StartupProfile& host,
    const MemoryOps& memory,const NativeImportOps& imports,DWORD* error) noexcept {
    // One invocation only. Sharing region metadata across these fixed immutable
    // partitions removes duplicate VirtualQuery calls; every code/data/pointer/
    // import/pdata byte still goes through the original reader. The cache dies
    // before returning and is never carried across a Lease or owner visit.
    ReadScope scope(memory);
    for (const auto& partition:kRecoveryPartitions) {
        const auto result=ValidateNativeLoggingProfile(base,host,partition,scope.Ops(),imports,error);
        if (result!=ProfileResult::Ready) return result;
    }
    return ProfileResult::Ready;
}
ProfileResult ValidateNativeRecoveryMetadataProfile(std::uintptr_t base,const StartupProfile& host,
    const MemoryOps& memory,const NativeImportOps& imports,DWORD* error) noexcept {
    ReadScope scope(memory);
    for(const auto& partition:kMetadataPartitions) {
        const auto result=ValidateNativeLoggingProfile(base,host,partition,scope.Ops(),imports,error);
        if(result!=ProfileResult::Ready) return result;
    }
    return ProfileResult::Ready;
}
RecoveryNativeResult ReadRecoveryMetadataCache(const RecoveryNativeContext& context,
    RecoveryMetadataCache* output,DWORD* error) noexcept {
    const auto incoming=GetLastError();if(output)*output={};if(error)*error=ERROR_INVALID_DATA;
    auto result=RecoveryNativeResult::InvalidContext;
    if(output && Context(context)) {
        RecoveryMetadataCache observed[2]{};
        result=RecoveryNativeResult::Ready;
        for(auto& value:observed) {
            std::uint8_t cached[24]{};
            if(!ImageRangeProtection(context.hostBase,context.hostImageSize,0x17989F0,sizeof(cached),
                    PAGE_READWRITE,context.memory,error) ||
                !ReadImageRange(context.hostBase,context.hostImageSize,0x17989F0,cached,sizeof(cached),context.memory,error) ||
                !ImageRangeProtection(context.hostBase,context.hostImageSize,0x14AAD88,1,PAGE_READWRITE,context.memory,error) ||
                !ReadImageRange(context.hostBase,context.hostImageSize,0x14AAD88,&value.fullDirty,1,context.memory,error)) {
                result=RecoveryNativeResult::Unreadable;break;
            }
            value.registrationChanged=cached[0];
            std::memcpy(&value.counts.bots,cached+8,4);
            std::memcpy(&value.counts.maximum,cached+12,4);
            std::memcpy(&value.counts.pi,cached+16,4);
            std::memcpy(&value.countdownBits,cached+20,4);
            if(value.registrationChanged>1 || value.fullDirty>1) {result=RecoveryNativeResult::Shape;break;}
        }
        if(result==RecoveryNativeResult::Ready && std::memcmp(&observed[0],&observed[1],sizeof(observed[0])))
            result=RecoveryNativeResult::Changed;
        if(result==RecoveryNativeResult::Ready) {*output=observed[0];if(error)*error=ERROR_SUCCESS;}
    }
    SetLastError(incoming);return result;
}
bool EqualNativeRecoverySnapshot(const RecoveryNativeSnapshot& a,const RecoveryNativeSnapshot& b) noexcept {
    return !std::memcmp(&a,&b,sizeof(a));
}
RecoveryNativeResult RequireRecoveryMetadataAllocator(const RecoveryNativeContext& context,
    std::uintptr_t expected,DWORD* error) noexcept {
    const auto incoming=GetLastError();if(error)*error=ERROR_INVALID_DATA;
    auto result=RecoveryNativeResult::InvalidContext;
    if(expected && Context(context)) {
        const auto& layout=context.layout?*context.layout:kLayout;Reader reader(context,error);
        result=RecoveryNativeResult::Ready;
        for(unsigned pass=0;pass<2;++pass) {
            reader.Reset();std::uintptr_t current{},table{},allocate{},reallocate{},release{};
            if(!reader.Global(layout.gmalloc,current) || current!=expected || !reader.Field(current,0,table) ||
                table!=context.hostBase+layout.gmallocVtable || !reader.Field(table,8,allocate) ||
                allocate!=context.hostBase+0xA6F420 || !reader.Field(table,16,reallocate) ||
                reallocate!=context.hostBase+0xA71E40 || !reader.Field(table,24,release) ||
                release!=context.hostBase+0xA6CE90) {result=RecoveryNativeResult::Allocator;break;}
        }
        if(result==RecoveryNativeResult::Ready && error)*error=ERROR_SUCCESS;
    }
    SetLastError(incoming);return result;
}
RecoveryNativeResult ReadNativeRecoverySnapshot(const RecoveryNativeContext& context,
    RecoveryNativeSnapshot* out,DWORD* error) noexcept {
    const DWORD saved=GetLastError();
    if (error) *error=ERROR_INVALID_DATA;
    if (out) std::memset(out,0,sizeof(*out));
    auto result=RecoveryNativeResult::InvalidContext;
    if (out && Context(context)) {
        Reader reader(context,error);
        RecoveryNativeSnapshot first{},second{};
        result=reader.Observe(first);
        if (result==RecoveryNativeResult::Ready) result=reader.Observe(second);
        if (result==RecoveryNativeResult::Ready && !EqualNativeRecoverySnapshot(first,second)) result=RecoveryNativeResult::Changed;
        if (result==RecoveryNativeResult::Ready) {std::memcpy(out,&first,sizeof(first));if(error)*error=ERROR_SUCCESS;}
    }
    SetLastError(saved);return result;
}
RecoveryNativeResult RequireNativeRecoveryReady(const RecoveryNativeSnapshot& s) noexcept {
    // BFCD20 selects inline/heap authorization std::string data by capacity. Reader did
    // that same selection and copied its first byte. Stock BAB4A0 returns AL0
    // exactly for a nonnull selected buffer whose first byte is nonzero.
    // The native UUID wrapper can leave a nil value after a failed init; that
    // value cannot distinguish core lifetimes and must refuse before cancellation.
    constexpr char nilGuid[]="00000000-0000-0000-0000-000000000000";
    return s.core==1 && s.httpManager && s.asyncManager && s.auth==7 && s.role &&
        s.previousReady==1 && s.previousConnected==1 && s.connected==1 && s.authorizationToken.size &&
        s.authorizationBytes[0] && s.coreGuid.size==sizeof(nilGuid)-1 && s.coreGuidBytes[0] &&
        std::memcmp(s.coreGuidBytes,nilGuid,sizeof(nilGuid)-1) &&
        s.publicIpData && s.publicIpCount>1 && s.publicIpChars[0] ?
        RecoveryNativeResult::Ready:RecoveryNativeResult::Readiness;
}
RecoveryNativeResult RequireFinishFirstFree(const RecoveryNativeSnapshot& s) noexcept {
    if (s.genericFree<2 || s.finish.firstFree>=16) return RecoveryNativeResult::Pool;
    const auto& slot=s.finish.slots[s.finish.firstFree];
    // BF1900 retains released strings; BF0DB0 frees/reconstructs the positively
    // validated first-free payload. Do not reject it or reset native storage here.
    return slot.references== -1 ?RecoveryNativeResult::Ready:RecoveryNativeResult::Provenance;
}
RecoveryNativeResult RequireCreateFirstFree(const RecoveryNativeSnapshot& s) noexcept {
    return s.genericFree>=2 && s.create.firstFree<16 && s.create.slots[s.create.firstFree].references== -1 ?
        RecoveryNativeResult::Ready:RecoveryNativeResult::Pool;
}
RecoveryNativeResult RequireHeartbeatFirstFree(const RecoveryNativeSnapshot& fresh,
    const RecoveryNativeSnapshot& before,std::uint32_t oldHolder) noexcept {
    if (!fresh.genericFree || fresh.heartbeat.firstFree>=16 || fresh.heartbeat.descriptor!=before.heartbeat.descriptor ||
        fresh.heartbeat.type!=before.heartbeat.type || fresh.gmalloc!=before.gmalloc ||
        fresh.httpManager!=before.httpManager || fresh.asyncManager!=before.asyncManager ||
        !SameString(fresh.coreGuid,before.coreGuid) ||
        std::memcmp(fresh.coreGuidBytes,before.coreGuidBytes,sizeof(fresh.coreGuidBytes)) ||
        (oldHolder>>16)!=before.heartbeat.type || (oldHolder&0xffff)>=16) return RecoveryNativeResult::Provenance;
    const auto oldSlot=oldHolder&0xffff;
    if (before.heartbeat.slots[oldSlot].references!=1 || fresh.heartbeat.slots[oldSlot].references!= -1)
        return RecoveryNativeResult::Provenance;
    // BAB380 normally clears global Members14AAD70. It is freshly checked for
    // shape/owned-buffer nonalias by Reader, but its old contents are not a
    // retained request witness. The independently owned HB payloads below ARE.
    for (unsigned i=0;i<16;++i) {
        if (!SameSlot(fresh,fresh.heartbeat.slots[i],before,before.heartbeat.slots[i]) ||
            (i!=oldSlot && fresh.heartbeat.slots[i].references!=before.heartbeat.slots[i].references))
            return RecoveryNativeResult::Provenance;
    }
    const auto slot=fresh.heartbeat.firstFree;
    const auto& current=fresh.heartbeat.slots[slot];
    if (current.references!= -1) return RecoveryNativeResult::Pool;
    const auto freeHolder=(static_cast<std::uint32_t>(fresh.heartbeat.type)<<16)|static_cast<std::uint32_t>(slot);
    for (const auto& task:fresh.generic) if (task.state && task.holder==freeHolder) return RecoveryNativeResult::Pool;
    // Every slot was positively initialized/retained under the pre-cancel native
    // ownership envelope. The firstfree may be an earlier used slot, rather than
    // the old active HB. Full header/interval witnesses above prohibit adopting
    // changed or newly supplied buffers. Never skip a populated earlier slot.
    return before.heartbeat.slots[slot].references== -1 || slot==oldSlot ?
        RecoveryNativeResult::Ready:RecoveryNativeResult::Provenance;
}
RecoveryNativeResult ReadCreateResultString(const RecoveryNativeContext& context,
    const void* object,RecoveryNativeString* out,DWORD* error) noexcept {
    const DWORD saved=GetLastError();
    if(out)*out={};if(error)*error=ERROR_INVALID_DATA;
    auto result=RecoveryNativeResult::InvalidContext;
    if(out && Context(context)) {
        Reader reader(context,error);RecoveryNativeString a{},b{};
        result=reader.String(reinterpret_cast<std::uintptr_t>(object),a);
        if(result==RecoveryNativeResult::Ready) {reader.Reset();result=reader.String(reinterpret_cast<std::uintptr_t>(object),b);}
        if(result==RecoveryNativeResult::Ready && (!SameString(a,b) || !a.size)) result=RecoveryNativeResult::Changed;
        if(result==RecoveryNativeResult::Ready){*out=a;if(error)*error=ERROR_SUCCESS;}
    }
    SetLastError(saved);return result;
}
RecoveryNativeResult RequireRecoveryFinishInverse(const RecoveryNativeContext& context,
    std::uintptr_t expectedDescriptor,std::uint16_t type,std::uint16_t slot,
    bool boundLocal,std::uint32_t ownedHolder,DWORD* error) noexcept {
    const DWORD saved=GetLastError();
    if(error)*error=ERROR_INVALID_DATA;
    auto result=RecoveryNativeResult::InvalidContext;
    if(Context(context) && expectedDescriptor && type && type<256 && slot<16 &&
        (boundLocal?ownedHolder==((static_cast<std::uint32_t>(type)<<16)|slot):ownedHolder==0)) {
        const auto& layout=context.layout?*context.layout:kLayout;
        Reader reader(context,error);
        struct Observation {std::uintptr_t descriptor,vtable,release;std::uint16_t type;std::int32_t references;RecoveryNativeString string;};
        Observation observations[2]{};
        result=RecoveryNativeResult::Ready;
        for(auto& value:observations) {
            reader.Reset();
            if(!reader.Global(layout.registry+type*8,value.descriptor) || value.descriptor!=expectedDescriptor ||
                !reader.Field(value.descriptor,0,value.vtable) || value.vtable!=context.hostBase+layout.finishVtable ||
                !reader.Field(value.descriptor,8,value.type) || value.type!=type ||
                !reader.Field(value.vtable,0x98,value.release) || value.release!=context.hostBase+0xBF1900 ||
                !ImageRangeProtection(context.hostBase,context.hostImageSize,0xBF1900,1,PAGE_EXECUTE_READ,context.memory,error) ||
                !reader.Range(value.descriptor+0x20+slot*0x30,sizeof(value.references),true) ||
                !reader.Field(value.descriptor,0x20+slot*0x30,value.references)) {
                result=RecoveryNativeResult::Descriptor;break;
            }
            if(boundLocal?value.references<1:value.references!=0) {result=RecoveryNativeResult::Provenance;break;}
            result=reader.String(value.descriptor+0x28+slot*0x30,value.string);
            if(result!=RecoveryNativeResult::Ready) break;
        }
        const auto& a=observations[0];const auto& b=observations[1];
        if(result==RecoveryNativeResult::Ready && (a.descriptor!=b.descriptor || a.vtable!=b.vtable ||
            a.release!=b.release || a.type!=b.type || a.references!=b.references || !SameString(a.string,b.string)))
            result=RecoveryNativeResult::Changed;
        if(result==RecoveryNativeResult::Ready && error)*error=ERROR_SUCCESS;
    }
    SetLastError(saved);return result;
}
RecoveryNativeCalls NativeRecoveryCallAddresses(std::uintptr_t base) noexcept {
    if(!base || base>(std::numeric_limits<std::uintptr_t>::max)()-0xBF8010) return {};
    return {reinterpret_cast<RecoveryInitHolderFn>(base+0xBAEB40),reinterpret_cast<RecoveryBindHolderFn>(base+0xBAF090),
        reinterpret_cast<RecoveryResolveHolderFn>(base+0xBAF0C0),reinterpret_cast<RecoveryStringCopyFn>(base+0x1EE0),
        reinterpret_cast<RecoveryEnqueueFinishFn>(base+0xBA8F10),reinterpret_cast<RecoveryReleaseHolderFn>(base+0xBAEFE0),
        reinterpret_cast<RecoveryCancelFn>(base+0xBF8010),reinterpret_cast<RecoveryVoidFn>(base+0xBAB380),
        reinterpret_cast<RecoveryVoidFn>(base+0xBAB210),reinterpret_cast<RecoveryVoidFn>(base+0xA53560),
        reinterpret_cast<RecoveryCreateSuccessFn>(base+0xBAB120),reinterpret_cast<RecoveryAllocateFn>(base+0xBF0DB0),
        reinterpret_cast<RecoveryTypeFn>(base+0xBF55F0),reinterpret_cast<RecoverySlotReleaseFn>(base+0xBF1900)};
}
RecoveryMetadataCalls NativeRecoveryMetadataCallAddresses(std::uintptr_t base) noexcept {
    if(!base || base>(std::numeric_limits<std::uintptr_t>::max)()-0xBA9490) return {};
    return {reinterpret_cast<RecoveryMetadataHeadFn>(base+0xA576F0),
        reinterpret_cast<RecoveryMetadataObjectFn>(base+0xA5CAA0),
        reinterpret_cast<RecoveryMetadataObjectFn>(base+0xA45CF0),
        reinterpret_cast<RecoveryMetadataUpdateFn>(base+0xBA9490)};
}
} // namespace rs2fix::reporting
