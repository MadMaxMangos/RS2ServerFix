#pragma once
#include "companion/leech_recovery_native.h"
#include <cstring>
#include <iterator>
#include <stdexcept>
#include <vector>

namespace rs2fix::testcases::leech_fixture {
using namespace reporting;
// Synthetic PE/memory/import observations only. No image is loaded by Windows,
// and no native host, SDK, allocator, import or callback target is invoked.
#include "companion/leech_recovery_native_profile_data.inc"
struct NativeFixture {
    static constexpr std::uintptr_t kSyntheticBase=0x180000000ULL,kSyntheticHeapBase=0x190000000ULL;
    static constexpr char kInitialSession[]="11111111-2222-3333-4444-555555555555";
    static constexpr char kAuthorizationToken[]="synthetic-authorization-token-before-refresh";
    static constexpr char kCoreGuid[]="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    std::vector<std::uint8_t> image=std::vector<std::uint8_t>(0x1A12000);
    std::vector<std::uint8_t> heap=std::vector<std::uint8_t>(0x200000);
    std::uintptr_t base,heapBase;
    bool ownedAddresses;
    const RecoveryNativeLayout& layout=ProductionRecoveryNativeLayout();
    StartupProfile host{0x1A12000,0x12345678,{0x98765432,0},1,0x1000};
    NativeImportOps imports{this,Resolve};
    bool failImport{},changeSecond{};
    std::uint32_t changeSecondContentOffset{};
    unsigned observations{};
    std::uint32_t finishObject=0x14B0000,createObject=0x14B1000,hbObject=0x14B2000;
    template<class T> void Put(std::uint32_t rva,T value){std::memcpy(image.data()+rva,&value,sizeof(value));}
    template<class T> void HeapPut(std::uint32_t offset,T value){std::memcpy(heap.data()+offset,&value,sizeof(value));}
    void Text(std::uint32_t rva,const char* value){std::memcpy(image.data()+rva,value,std::strlen(value)+1);}
    void Inline(std::uint32_t object){
        if(object>image.size() || image.size()-object<32) throw std::invalid_argument("fixture string header");
        std::memset(image.data()+object,0,32);Put<std::uint64_t>(object+0x18,15);
    }
    void InlineString(std::uint32_t object,const char* value){
        if(!value || std::strlen(value)>15) throw std::invalid_argument("fixture inline string");
        Inline(object);const auto length=std::strlen(value);
        std::memcpy(image.data()+object,value,length+1);Put<std::uint64_t>(object+0x10,length);
    }
    void HeapString(std::uint32_t object,std::uint32_t offset,const char* value,std::uint64_t capacity=63){
        if(!value || capacity<16 || offset>=heap.size() || capacity>=heap.size()-offset ||
            std::strlen(value)>capacity) throw std::invalid_argument("fixture heap string");
        const auto length=std::strlen(value);Inline(object);
        Put(object,heapBase+offset);Put<std::uint64_t>(object+0x10,length);Put<std::uint64_t>(object+0x18,capacity);
        std::memcpy(heap.data()+offset,value,length+1);
    }
    void ClearString(std::uint32_t object){
        if(object>image.size() || image.size()-object<32) throw std::invalid_argument("fixture string header");
        std::uint64_t capacity{};std::memcpy(&capacity,image.data()+object+0x18,8);
        if(capacity<16) {
            if(capacity!=15) throw std::invalid_argument("fixture inline capacity");
            image[object]=0;
        } else {
            std::uintptr_t data{};std::memcpy(&data,image.data()+object,8);
            if(data<heapBase || data-heapBase>=heap.size() || capacity>=heap.size()-(data-heapBase))
                throw std::invalid_argument("fixture heap capacity");
            heap[static_cast<std::size_t>(data-heapBase)]=0;
        }
        Put<std::uint64_t>(object+0x10,0);
    }
    explicit NativeFixture(bool owned=false):base(owned?reinterpret_cast<std::uintptr_t>(image.data()):kSyntheticBase),
        heapBase(owned?reinterpret_cast<std::uintptr_t>(heap.data()):kSyntheticHeapBase),ownedAddresses(owned){
        IMAGE_DOS_HEADER dos{};dos.e_magic=IMAGE_DOS_SIGNATURE;dos.e_lfanew=0x80;Put(0,dos);
        IMAGE_NT_HEADERS64 nt{};nt.Signature=IMAGE_NT_SIGNATURE;nt.FileHeader.Machine=IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.Characteristics=IMAGE_FILE_EXECUTABLE_IMAGE;nt.FileHeader.SizeOfOptionalHeader=sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.FileHeader.NumberOfSections=4;nt.FileHeader.TimeDateStamp=host.timestamp;nt.OptionalHeader.Magic=IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.SizeOfImage=host.imageSize;nt.OptionalHeader.SizeOfHeaders=0x1000;nt.OptionalHeader.NumberOfRvaAndSizes=16;
        nt.OptionalHeader.CheckSum=host.checksums[0];nt.OptionalHeader.AddressOfEntryPoint=host.entryRva;
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]={0x17E7000,0x100008};
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]={0x1A00000,40};Put(0x80,nt);
        const std::uint32_t starts[]{0x1000,0xE90000,0x14A0000,0x17E0000,0x1A12000};
        for(unsigned i=0;i<4;++i){IMAGE_SECTION_HEADER section{};section.VirtualAddress=starts[i];section.Misc.VirtualSize=starts[i+1]-starts[i];
            section.Characteristics=IMAGE_SCN_MEM_READ|(i==0?IMAGE_SCN_MEM_EXECUTE:0)|(i==2?IMAGE_SCN_MEM_WRITE:0);
            Put(0x80+static_cast<std::uint32_t>(sizeof(nt)+i*sizeof(section)),section);}
        for(const auto& part:kRecoveryPartitions){
            for(std::size_t i=0;i<part.body.spanCount;++i){const auto& s=part.body.spans[i].span;std::memcpy(image.data()+s.rva,s.bytes,s.size);}
            for(std::size_t i=0;i<part.body.pointerCount;++i){const auto& p=part.body.pointers[i];Put(p.slotRva,base+p.targetRva);}
            for(std::size_t i=0;i<part.body.exceptionCount;++i){const auto& e=part.body.exceptions[i];std::uint32_t record[]{e.beginRva,e.endRva,e.unwindRva};std::memcpy(image.data()+e.entryRva,record,12);}
        }
        IMAGE_IMPORT_DESCRIPTOR descriptor{};descriptor.Name=0x1A00100;descriptor.FirstThunk=0xE94000;descriptor.OriginalFirstThunk=0x1A01000;Put(0x1A00000,descriptor);
        Text(descriptor.Name,"MSVCR110.dll");
        for(std::size_t i=0;i<std::size(kRecoveryImports);++i){const auto& p=kRecoveryImports[i];const auto nameRva=static_cast<std::uint32_t>(0x1A08000+i*128);
            Put<std::uint64_t>(descriptor.OriginalFirstThunk+p.slotRva-descriptor.FirstThunk,nameRva);
            Text(nameRva+2,p.name);Put(p.slotRva,0x1C0000000ULL+i*0x100);}
        Put(layout.standalone,3u);Put(layout.core,1u);Put(layout.auth,7u);Put(layout.issuedId,77u);Put(layout.invalidId,0u);Put(layout.heartbeatId,77u);
        Put<std::uint8_t>(layout.role,1);Put<std::uint8_t>(layout.previousReady,1);Put<std::uint8_t>(layout.previousConnected,1);Put<std::uint8_t>(layout.connected,1);
        Put(layout.httpManager,base+0x14B4000);Put(0x14B4000,base+layout.httpManagerVtable);
        Put(layout.asyncManager,base+0x14B4100);Put<std::uint8_t>(0x14B4100,1);
        Put(layout.gmalloc,base+0x14B4200);Put(0x14B4200,base+layout.gmallocVtable);
        Put(layout.jsonMalloc,base+0xC0EE30);Put(layout.jsonFree,base+0xBFD630);
        Text(0x1490000,"StandaloneServer");Put(layout.componentName,base+0x1490000);
        Text(0x1490100,"45d1305aa6d846dcbb070dda4af292d4");Put(layout.finishService,base+0x1490100);Put(layout.createService,base+0x1490100);
        Text(0x1490200,"b9d34959ad8e491888c4fe0f7aa0c31b");Put(layout.finishOperation,base+0x1490200);
        Text(0x1490300,"82c2ef8d501d4158a7119cf664b544fe");Put(layout.createOperation,base+0x1490300);
        struct C {const char* name;std::uint32_t start,stop,status,policy;};
        const C components[]{
            {"AsyncDeferOperationsComponent",0xBA4C40,0xBA4C90,0xBA4CE0,1},{"AuthorizationComponent",0xBFBB70,0xBFC4E0,0xBFC510,1},
            {"FactComponent",0xBAE3E0,0xBAE400,0xBAE420,2},{"StandaloneServer",0xBAB210,0xBAB230,0xBAB350,3},
            {"Presence",0xBFAA50,0xBFAC40,0xBFAD60,3},{"UserHeartbeatComponent",0xC09A30,0xC09BA0,0xC09C60,3},
            {"MessagingComponent",0xC0A7F0,0xC0AB20,0xC0AE60,3},{"GlobalEssentialComponentHack",0xBF60A0,0xBF60A0,0xBF6090,4}};
        for(unsigned i=0;i<8;++i){const auto r=layout.componentTable+i*0x28;const auto& c=components[i];
            Put(r,base+c.start);Put(r+8,base+c.stop);Put(r+16,base+c.status);Put(r+24,base+0x1490400+i*64);
            Put(r+32,c.policy);Text(0x1490400+i*64,c.name);}
        // Distinct owned buffers model the SDK/cache copies, rotating auth token,
        // and stable core GUID. No captured identities enter these fixtures.
        HeapString(layout.sdkSession,0x100,kInitialSession,47);
        HeapString(layout.authorizationToken,0x200,kAuthorizationToken);
        HeapString(layout.cacheSession,0x400,kInitialSession,47);
        HeapString(layout.coreGuid,0x500,kCoreGuid,47);
        constexpr char16_t publicIp[]=u"192.0.2.123";
        Put(layout.publicIp,heapBase+0x300);Put<std::int32_t>(layout.publicIp+8,static_cast<std::int32_t>(std::size(publicIp)));
        Put<std::int32_t>(layout.publicIp+12,32);std::memcpy(heap.data()+0x300,publicIp,sizeof(publicIp));
        Put(layout.kernelVector,heapBase+0x60000);Put(layout.kernelVector+8,heapBase+0x60000+64*32);
        Put(layout.kernelVector+16,heapBase+0x60000+128*32);
        for(unsigned i=0;i<64;++i)HeapPut<std::uint64_t>(0x60000+i*32+0x18,15);
        constexpr char globalMember[]="global-old-member-value";
        HeapPut(0x60000,heapBase+0x70000);HeapPut<std::uint64_t>(0x60010,sizeof(globalMember)-1);
        HeapPut<std::uint64_t>(0x60018,31);std::memcpy(heap.data()+0x70000,globalMember,sizeof(globalMember));
        const std::uint32_t objects[]{finishObject,createObject,hbObject},tables[]{layout.finishVtable,layout.createVtable,layout.heartbeatVtable};
        for(unsigned j=0;j<3;++j){Put(layout.registry+(40+j)*8,base+objects[j]);Put(objects[j],base+tables[j]);Put<std::uint16_t>(objects[j]+8,static_cast<std::uint16_t>(40+j));
            const auto stride=j==0?0x30u:j==1?0x90u:0x78u;
            for(unsigned i=0;i<16;++i){Put<std::int32_t>(objects[j]+0x20+i*stride,-1);const auto payload=objects[j]+0x28+i*stride;
                Inline(payload);if(j==1){Inline(payload+0x28);Inline(payload+0x48);Inline(payload+0x68);}if(j==2){Inline(payload+0x20);
                    HeapString(payload,0x1000+i*0x100,"ordinary-retained-used-heartbeat-session");
                    const auto vectorOffset=0x10000+i*0x2000;Put(payload+0x48,heapBase+vectorOffset);Put(payload+0x50,heapBase+vectorOffset+64*32);Put(payload+0x58,heapBase+vectorOffset+128*32);
                    for(unsigned k=0;k<64;++k)HeapPut<std::uint64_t>(vectorOffset+k*32+0x18,15);
                    const auto ownedOffset=0x50000+i*0x100;
                    constexpr char value[]="owned-kernel-value-string";
                    HeapPut(vectorOffset,heapBase+ownedOffset);HeapPut<std::uint64_t>(vectorOffset+0x10,sizeof(value)-1);
                    HeapPut<std::uint64_t>(vectorOffset+0x18,31);std::memcpy(heap.data()+ownedOffset,value,sizeof(value));}}
        }
        Put<std::int32_t>(hbObject+0x20+2*0x78,1);
        Put(layout.genericPool,2u);Put(layout.genericPool+4,77u);Put(layout.genericPool+8,base+0x1490000);
        Put(layout.genericPool+0x38,(42u<<16)|2u);Put<std::uint64_t>(layout.genericPool+0x60,30000);
    }
    static bool Query(void* context,std::uintptr_t address,MemoryRegion* out,DWORD*) noexcept {
        auto& f=*static_cast<NativeFixture*>(context);
        if(address>=f.heapBase && address-f.heapBase<f.heap.size()) {*out={f.heapBase,f.heapBase,f.heap.size(),MEM_COMMIT,MEM_PRIVATE,PAGE_READWRITE};return true;}
        if(address<f.base || address-f.base>=f.image.size())return false;
        const auto r=address-f.base;std::uintptr_t low{},high{};DWORD protection{};
        if(r<0x1000){low=0;high=0x1000;protection=PAGE_READONLY;}
        else if(r<0xE90000){low=0x1000;high=0xE90000;protection=PAGE_EXECUTE_READ;}
        else if(r<0x14A0000){low=0xE90000;high=0x14A0000;protection=PAGE_READONLY;}
        else if(r<0x17E0000){low=0x14A0000;high=0x17E0000;protection=PAGE_READWRITE;}
        else{low=0x17E0000;high=f.image.size();protection=PAGE_READONLY;}
        *out={f.base+low,f.base,static_cast<std::size_t>(high-low),MEM_COMMIT,MEM_IMAGE,protection};return true;
    }
    static bool Read(void* context,std::uintptr_t address,void* out,std::size_t bytes,DWORD*) noexcept {
        auto& f=*static_cast<NativeFixture*>(context);
        if(address>=f.heapBase && address-f.heapBase<f.heap.size() && bytes<=f.heap.size()-(address-f.heapBase)){
            std::memcpy(out,f.heap.data()+(address-f.heapBase),bytes);return true;}
        if(address<f.base || address-f.base>=f.image.size() || bytes>f.image.size()-(address-f.base))return false;
        if(address==f.base+f.layout.standalone && ++f.observations==2) {
            if(f.changeSecond) f.Put(f.layout.issuedId,78u);
            if(f.changeSecondContentOffset) f.heap[f.changeSecondContentOffset]^=1;
        }
        std::memcpy(out,f.image.data()+(address-f.base),bytes);return true;
    }
    static bool Resolve(void* context,const char*,const char* name,std::uintptr_t* out,DWORD*) noexcept {
        auto& f=*static_cast<NativeFixture*>(context);
        for(std::size_t i=0;i<std::size(kRecoveryImports);++i)if(!std::strcmp(name,kRecoveryImports[i].name)){
            *out=0x1C0000000ULL+i*0x100+(f.failImport?1:0);return true;}
        return false;
    }
    MemoryOps Memory(){return {this,Query,Read};}
    RecoveryNativeContext Context(){return {base,host.imageSize,Memory(),&imports,&layout};}
    RecoveryNativeResult Snapshot(RecoveryNativeSnapshot& out){observations=0;DWORD error{};return ReadNativeRecoverySnapshot(Context(),&out,&error);}
};
} // namespace rs2fix::testcases::leech_fixture
