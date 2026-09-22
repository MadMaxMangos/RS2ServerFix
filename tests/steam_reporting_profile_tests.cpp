#include "companion/steam_reporting_profile.h"
#include "test_framework.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace rs2fix::testcases {
namespace {
using namespace reporting;
struct FakeImage {
    static constexpr std::uint32_t kSize=0x9000;
    std::uintptr_t base=0x180000000ULL; // Deliberately not the production preferred base.
    std::array<std::uint8_t,kSize> bytes{};
    std::array<std::uint8_t,1301> expectedCode{};
    const std::uint8_t expectedUnwind[4]{1,0,0,0};
    ReportingSpan spans[2]{};
    PointerRvaRecipe pointers[1]{{0x3200,0x1000}};
    RuntimeFunctionRecipe exceptions[1]{{0x4000,0x1000,0x1515,0x3100}};
    ReportingProfile profile{spans,2,pointers,1,exceptions,1,
        {0x5000,"steam_api64.dll","SteamGameServer_RunCallbacks"}};
    StartupProfile host{};
    std::size_t largestRead{};
    std::uint32_t failingRead=UINT32_MAX;
    DWORD codeProtection=PAGE_EXECUTE_READ;
    DWORD dataProtection=PAGE_READONLY;
    bool wrongAllocation{};
    bool discardedRelocations{};
    static constexpr std::uintptr_t kPump=0x7FF100001234ULL;

    template<class T> void Store(std::uint32_t rva, const T& item) {
        std::memcpy(bytes.data()+rva,&item,sizeof(item));
    }
    template<class T> T Load(std::uint32_t rva) const {
        T result{}; std::memcpy(&result,bytes.data()+rva,sizeof(result)); return result;
    }
    FakeImage() {
        host.imageSize=kSize; host.timestamp=0x12345678;
        host.checksumCount=1; host.checksums[0]=0xA55A; host.entryRva=0x1000;
        IMAGE_DOS_HEADER dos{}; dos.e_magic=IMAGE_DOS_SIGNATURE; dos.e_lfanew=0x80;
        Store(0,dos);
        IMAGE_NT_HEADERS64 nt{};
        nt.Signature=IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine=IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections=4;
        nt.FileHeader.TimeDateStamp=host.timestamp;
        nt.FileHeader.SizeOfOptionalHeader=sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.FileHeader.Characteristics=IMAGE_FILE_EXECUTABLE_IMAGE;
        nt.OptionalHeader.Magic=IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.SizeOfImage=kSize; nt.OptionalHeader.SizeOfHeaders=0x1000;
        nt.OptionalHeader.AddressOfEntryPoint=host.entryRva;
        nt.OptionalHeader.CheckSum=host.checksums[0];
        nt.OptionalHeader.NumberOfRvaAndSizes=IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]={0x5100,40};
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]={0x4000,12};
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]={0x7000,12};
        Store(0x80,nt);
        IMAGE_SECTION_HEADER sections[4]{};
        sections[0].VirtualAddress=0x1000; sections[0].Misc.VirtualSize=0x2000;
        sections[0].Characteristics=IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_EXECUTE;
        sections[1].VirtualAddress=0x3000; sections[1].Misc.VirtualSize=0x4000;
        sections[1].Characteristics=IMAGE_SCN_MEM_READ;
        sections[2].VirtualAddress=0x7000; sections[2].Misc.VirtualSize=0x1000;
        sections[2].Characteristics=IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_DISCARDABLE;
        sections[3].VirtualAddress=0x8000; sections[3].Misc.VirtualSize=0x1000;
        sections[3].Characteristics=IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE;
        std::memcpy(bytes.data()+0x80+sizeof(nt),sections,sizeof(sections));
        for (std::size_t i=0; i<expectedCode.size(); ++i) expectedCode[i]=static_cast<std::uint8_t>(i);
        std::memcpy(bytes.data()+0x1000,expectedCode.data(),expectedCode.size());
        std::memcpy(bytes.data()+0x3100,expectedUnwind,sizeof(expectedUnwind));
        spans[0]={{0x1000,expectedCode.size(),expectedCode.data()},SpanKind::Code};
        spans[1]={{0x3100,sizeof(expectedUnwind),expectedUnwind},SpanKind::ImmutableData};
        Store<std::uintptr_t>(0x3200,base+0x1000);
        const std::uint32_t triple[3]{0x1000,0x1515,0x3100};
        std::memcpy(bytes.data()+0x4000,triple,sizeof(triple));
        Store<std::uintptr_t>(0x5000,kPump);
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        descriptor.OriginalFirstThunk=0x5200; descriptor.Name=0x5300; descriptor.FirstThunk=0x5000;
        Store(0x5100,descriptor);
        Store<std::uint64_t>(0x5200,0x5400);
        std::memcpy(bytes.data()+0x5300,profile.pump.module,std::strlen(profile.pump.module)+1);
        std::memcpy(bytes.data()+0x5402,profile.pump.name,std::strlen(profile.pump.name)+1);
        const IMAGE_BASE_RELOCATION block{0x3000,12}; Store(0x7000,block);
        Store<std::uint16_t>(0x7008,0xA200); Store<std::uint16_t>(0x700A,0);
    }
    static bool Query(void* opaque, std::uintptr_t address, MemoryRegion* out, DWORD* error) noexcept {
        auto& f=*static_cast<FakeImage*>(opaque);
        if (address<f.base || address-f.base>=kSize) { if (error) *error=ERROR_INVALID_ADDRESS; return false; }
        const auto rva=address-f.base;
        if (f.discardedRelocations && rva>=0x7000 && rva<0x8000) {
            if (error) *error=ERROR_INVALID_ADDRESS;
            return false;
        }
        std::uint32_t lo{},hi=0x1000;
        DWORD protection=PAGE_READONLY;
        if (rva>=0x1000 && rva<0x3000) { lo=0x1000; hi=0x3000; protection=f.codeProtection; }
        else if (rva>=0x3000 && rva<0x8000) { lo=0x3000; hi=0x8000; protection=f.dataProtection; }
        else if (rva>=0x8000) { lo=0x8000; hi=kSize; protection=PAGE_READWRITE; }
        *out={f.base+lo,f.wrongAllocation ? f.base+0x1000 : f.base,hi-lo,MEM_COMMIT,MEM_IMAGE,protection};
        if (error) *error=ERROR_SUCCESS;
        return true;
    }
    static bool Read(void* opaque, std::uintptr_t address, void* output,
        std::size_t size, DWORD* error) noexcept {
        auto& f=*static_cast<FakeImage*>(opaque);
        f.largestRead=(std::max)(f.largestRead,size);
        if (address<f.base || address-f.base>=kSize || size>kSize-(address-f.base) ||
            size>kProfileReadChunk ||
            (f.failingRead>=address-f.base && f.failingRead-(address-f.base)<size)) {
            if (error) *error=ERROR_PARTIAL_COPY; return false;
        }
        std::memcpy(output,f.bytes.data()+static_cast<std::size_t>(address-f.base),size);
        if (error) *error=ERROR_SUCCESS;
        return true;
    }
    ProfileResult Validate(std::uintptr_t* original=nullptr) {
        std::uintptr_t local=123;
        DWORD error{};
        const MemoryOps memory{this,Query,Read};
        const auto result=ValidateReportingProfile(base,host,profile,memory,&local,&error);
        if (original) *original=local;
        if (result!=ProfileResult::Ready) RS2_CHECK(local==0);
        return result;
    }
};

void ChunkedAndRelocatedIdentity() {
    FakeImage f;
    std::uintptr_t original{};
    RS2_CHECK(f.Validate(&original)==ProfileResult::Ready && original==FakeImage::kPump);
    RS2_CHECK(f.largestRead==512); // The 1301-byte body must span multiple guarded reads.
    f.bytes[0x1000+1100]^=1;
    RS2_CHECK(f.Validate()==ProfileResult::BytesMismatch);
    f.bytes[0x1000+1100]^=1;
    f.Store<std::uintptr_t>(0x3200,0x140001000ULL); // Preferred-base pointer must not pass after relocation.
    RS2_CHECK(f.Validate()==ProfileResult::PointerMismatch);
    f.Store<std::uintptr_t>(0x3200,f.base+0x1000);
    f.failingRead=0x1000+1200;
    RS2_CHECK(f.Validate()==ProfileResult::BytesMismatch);
}
void ProtectionAndHeaderFailures() {
    FakeImage f;
    f.codeProtection=PAGE_EXECUTE_READWRITE;
    RS2_CHECK(f.Validate()==ProfileResult::ProtectionMismatch);
    f.codeProtection=PAGE_EXECUTE_READ|PAGE_GUARD;
    RS2_CHECK(f.Validate()==ProfileResult::ProtectionMismatch);
    f.codeProtection=PAGE_EXECUTE_READ; f.dataProtection=PAGE_READWRITE;
    RS2_CHECK(f.Validate()==ProfileResult::ProtectionMismatch);
    f.dataProtection=PAGE_READONLY; f.wrongAllocation=true;
    RS2_CHECK(f.Validate()==ProfileResult::ImageMismatch);
    f.wrongAllocation=false;
    auto nt=f.Load<IMAGE_NT_HEADERS64>(0x80);
    ++nt.FileHeader.TimeDateStamp; f.Store(0x80,nt);
    RS2_CHECK(f.Validate()==ProfileResult::ImageMismatch);
}
void ProfileBoundsAndSectionMismatch() {
    FakeImage f;
    f.spans[0].span.size=kProfileSpanBytes+1;
    RS2_CHECK(f.Validate()==ProfileResult::InvalidProfile);
    f.spans[0].span.size=f.expectedCode.size(); f.spans[1].span.rva=0x1100;
    RS2_CHECK(f.Validate()==ProfileResult::InvalidProfile);
    f.spans[1].span.rva=0x3100; f.profile.pointerCount=kProfilePointerLimit+1;
    RS2_CHECK(f.Validate()==ProfileResult::InvalidProfile);
    f.profile.pointerCount=1;
    const auto sectionRva=static_cast<std::uint32_t>(0x80+sizeof(IMAGE_NT_HEADERS64));
    auto section=f.Load<IMAGE_SECTION_HEADER>(sectionRva);
    section.Characteristics|=IMAGE_SCN_MEM_WRITE; f.Store(sectionRva,section);
    RS2_CHECK(f.Validate()==ProfileResult::ProtectionMismatch);
}
void UnwindMembershipAndDiscardedRelocations() {
    FakeImage f;
    auto nt=f.Load<IMAGE_NT_HEADERS64>(0x80);
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress=0x4010;
    f.Store(0x80,nt);
    RS2_CHECK(f.Validate()==ProfileResult::UnwindMismatch);
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress=0x4000; f.Store(0x80,nt);
    f.Store<std::uint32_t>(0x4008,0x3104);
    RS2_CHECK(f.Validate()==ProfileResult::UnwindMismatch);
    f.Store<std::uint32_t>(0x4008,0x3100);
    // Real loaders may decommit IMAGE_SCN_MEM_DISCARDABLE relocation pages.
    // The approved generator audits metadata; startup verifies the final image.
    f.discardedRelocations=true;
    RS2_CHECK(f.Validate()==ProfileResult::Ready);
    const auto originalWord=f.Load<std::uint64_t>(0x1000+512);
    f.Store<std::uint64_t>(0x1000+512,originalWord+0x100000000ULL);
    RS2_CHECK(f.Validate()==ProfileResult::BytesMismatch); // Unexpected loader-applied relocation effect.
}
void ImportIdentity() {
    FakeImage f;
    f.bytes[0x5402]='X';
    RS2_CHECK(f.Validate()==ProfileResult::ImportMismatch);
    f.bytes[0x5402]='S';
    f.Store<std::uint64_t>(0x5200,IMAGE_ORDINAL_FLAG64|1);
    RS2_CHECK(f.Validate()==ProfileResult::ImportMismatch);
    f.Store<std::uint64_t>(0x5200,0x5400); f.Store<std::uintptr_t>(0x5000,0);
    RS2_CHECK(f.Validate()==ProfileResult::ImportMismatch);
}
void ProductionInventoryBounds() {
    const auto& p=ProductionReportingProfile();
    RS2_CHECK(p.spanCount==59 && p.pointerCount==12 && p.exceptionCount==14);
    std::size_t sum{};
    for (std::size_t i=0; i<p.spanCount; ++i) {
        RS2_CHECK(p.spans[i].span.bytes && p.spans[i].span.size<=8192);
        sum+=p.spans[i].span.size;
    }
    RS2_CHECK(sum==38927 && p.pump.slotRva==0xE95570);
    RS2_CHECK(!std::strcmp(ReportingProfileInventorySha256(),
        "35A289F0367283F4A437A08E3EC970A4657C65D1605852B86F7D7F1223940C2E"));
    const auto& identities=ProductionReportingIdentities();
    RS2_CHECK(identities.steamClientImageSize==0x1766000 && identities.steamClientTimestamp==0x685F401F);
}
} // namespace
void ReportingProfileTests() {
    ChunkedAndRelocatedIdentity(); ProtectionAndHeaderFailures();
    ProfileBoundsAndSectionMismatch(); UnwindMembershipAndDiscardedRelocations();
    ImportIdentity(); ProductionInventoryBounds();
}
} // namespace rs2fix::testcases
