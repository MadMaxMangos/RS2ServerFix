#include "companion/steam_observer.h"
#include "test_framework.h"
#include <array>
#include <cstring>
#include <limits>

extern "C" {
void* Rs2AbiFactoryCall(rs2fix::observer::FactoryFn, std::int32_t, const char*);
extern const unsigned char Rs2AbiFactoryReturn[];
}
namespace rs2fix::testcases {
namespace {
using namespace observer;
unsigned g_originalCalls{};
DispatchState* g_pumpState{};
bool g_pumpAdmitted{};
void Pump() { ++g_originalCalls; }
void PumpWrapper() {
    g_pumpAdmitted=g_pumpState && AdmitExternalCall(*g_pumpState);
    Pump();
}
void* Factory(std::int32_t, const char*) { ++g_originalCalls; return nullptr; }
bool Init(std::uint32_t, std::uint16_t, std::uint16_t, std::uint16_t, std::int32_t, const char*) {
    ++g_originalCalls; return false;
}
void Shutdown() { ++g_originalCalls; }
bool ValidObject(void*, void*) noexcept { return false; }
struct Image {
    static constexpr std::uint32_t size=0x6000;
    std::uint8_t* bytes{};
    DWORD iatProtection{PAGE_READONLY};
    constexpr static std::uint8_t instructions[]{0x90,0x90,0xC3};
    ByteSpan span{0x1000,sizeof(instructions),instructions};
    StartupProfile startup{};
    Profile profile{};
    BootstrapContextV3 context{};
    DispatchState dispatch{};
    ServerPumpCell pump{};
    bool fourCells{};
    unsigned protects{}, writes{}, identities{};
    unsigned injectAt{}, injectMethod{}, failProtectAt{}, failWriteAt{}, failIdentityAt{}, failProtectFrom{};
    unsigned nativeValidations{}, failNativeValidationAt{}, failWriteAfterMutationAt{}, foreignAt{2};
    bool injected{}, foreign{}, corruptLiteral{}, failReadsAfterWrite{};
    bool failAllProtect{}, changeOnProtectFailure{}, failReadsAfterProtect{};
    explicit Image(bool reporting=false): fourCells(reporting) {
        bytes=static_cast<std::uint8_t*>(VirtualAlloc(nullptr,size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
        if (!bytes) throw std::bad_alloc();
        IMAGE_DOS_HEADER dos{}; dos.e_magic=IMAGE_DOS_SIGNATURE; dos.e_lfanew=0x80; Put(0,dos);
        IMAGE_NT_HEADERS64 nt{};
        nt.Signature=IMAGE_NT_SIGNATURE; nt.FileHeader.Machine=IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections=4; nt.FileHeader.TimeDateStamp=1234;
        nt.FileHeader.Characteristics=IMAGE_FILE_EXECUTABLE_IMAGE|IMAGE_FILE_LARGE_ADDRESS_AWARE;
        nt.FileHeader.SizeOfOptionalHeader=sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.OptionalHeader.Magic=IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.SizeOfImage=size; nt.OptionalHeader.SizeOfHeaders=0x400;
        nt.OptionalHeader.AddressOfEntryPoint=0x1000; nt.OptionalHeader.CheckSum=4321;
        nt.OptionalHeader.NumberOfRvaAndSizes=IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        Put(0x80,nt);
        for (unsigned i=0; i<4; ++i) {
            IMAGE_SECTION_HEADER section{};
            section.VirtualAddress=0x1000*(i+1); section.Misc.VirtualSize=0x1000;
            section.Characteristics=IMAGE_SCN_MEM_READ |
                (i==0 ? IMAGE_SCN_MEM_EXECUTE : (i==3 ? IMAGE_SCN_MEM_WRITE : 0));
            Put(0x80+static_cast<DWORD>(sizeof(nt)+i*sizeof(section)),section);
        }
        std::memcpy(bytes+0x1000,instructions,sizeof(instructions));
        startup={size,1234,{4321,0},1,0x1000,0x1002,0x4000,1,0x2000,0x1000,&span,1};
        Put(startup.stateRva,DWORD{1}); Put(startup.initializerSlotRva,Base()+startup.initializerRva);
        context={sizeof(context),kBootstrapAbiVersion,reinterpret_cast<HMODULE>(Base()),
            reinterpret_cast<HMODULE>(1),reinterpret_cast<HMODULE>(2),kRequiredGenuineExports,0,
            Base()+startup.returnRva,GetCurrentThreadId(),GetCurrentThreadId(),1,kTriggerExeCrtInitialize};
        profile.factoryIatRva=0x3100; profile.shutdownIatRva=0x3120; profile.initIatRva=0x3140;
        profile.accessorRva=0x1000; profile.factoryReturnRva=0x1002;
        profile.literalRva=0x2080; profile.contextRva=0x4080;
        profile.privateRva=0x40A0; profile.publicationRva=0x40A8;
        profile.spans=&span; profile.spanCount=1;
        std::memcpy(bytes+profile.literalRva,kInterfaceVersion,sizeof(kInterfaceVersion));
        Put(profile.contextRva,Base()+profile.accessorRva);
        Put(profile.factoryIatRva,reinterpret_cast<void*>(&Factory));
        Put(profile.shutdownIatRva,reinterpret_cast<void*>(&Shutdown));
        Put(profile.initIatRva,reinterpret_cast<void*>(&Init));
        pump={0x3160,Pump,PumpWrapper,this,ValidateNative};
        Put(pump.iatRva,reinterpret_cast<void*>(&Pump));
        const auto testModule=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        DispatchConfig config{testModule,0x10000000,
            static_cast<DWORD>(reinterpret_cast<std::uintptr_t>(Rs2AbiFactoryReturn)-testModule),
            reinterpret_cast<const char*>(bytes+profile.literalRva),0,0,
            Factory,Init,Shutdown,nullptr,ValidObject};
        InitializeDispatch(dispatch,config,{});
        ResetPublishedDispatchForTest(); RS2_CHECK(PublishDispatch(dispatch));
        g_pumpState=&dispatch; g_pumpAdmitted=false;
    }
    ~Image() { g_pumpState=nullptr; ResetPublishedDispatchForTest(); VirtualFree(bytes,0,MEM_RELEASE); }
    Image(const Image&)=delete;
    std::uintptr_t Base() const { return reinterpret_cast<std::uintptr_t>(bytes); }
    template<class T> void Put(DWORD rva, const T& value) {
        RS2_CHECK(rva<size && sizeof(value)<=size-rva); std::memcpy(bytes+rva,&value,sizeof(value));
    }
    template<class T> T Get(DWORD rva) const { T value{}; std::memcpy(&value,bytes+rva,sizeof(value)); return value; }
    void Inject(unsigned boundary) noexcept {
        if (injectAt!=boundary || injected) return;
        injected=true;
        if (injectMethod==0) (void)Rs2AbiFactoryCall(FactoryEntry,7,dispatch.config.versionLiteral);
        else if (injectMethod==1) (void)InitEntry(0,1,2,3,4,nullptr);
        else if (injectMethod==2) ShutdownEntry();
        else PumpWrapper();
    }
    static bool Query(void* data, std::uintptr_t address, MemoryRegion* region, DWORD* error) noexcept {
        auto& image=*static_cast<Image*>(data);
        if (address<image.Base() || address-image.Base()>=size) { *error=ERROR_NOACCESS; return false; }
        const auto page=(address-image.Base())/0x1000;
        const DWORD protection=page==1 ? PAGE_EXECUTE_READ : (page==3 ? image.iatProtection :
            (page==4 ? PAGE_READWRITE : PAGE_READONLY));
        *region={image.Base()+page*0x1000,image.Base(),0x1000,MEM_COMMIT,MEM_IMAGE,protection};
        *error=ERROR_SUCCESS; return true;
    }
    static bool Read(void* data, std::uintptr_t address, void* output, std::size_t count, DWORD* error) noexcept {
        auto& image=*static_cast<Image*>(data);
        if (address<image.Base() || address-image.Base()>size || count>size-(address-image.Base()) ||
            (image.failReadsAfterWrite && image.writes) ||
            (image.failReadsAfterProtect && image.protects)) { *error=ERROR_PARTIAL_COPY; return false; }
        std::memcpy(output,reinterpret_cast<void*>(address),count);
        if (image.protects>=2 && address==image.Base()+image.profile.publicationRva) image.Inject(6);
        *error=ERROR_SUCCESS; return true;
    }
    static bool Protect(void* data, std::uintptr_t address, std::size_t count, DWORD protection,
        DWORD* old, DWORD* error) noexcept {
        auto& image=*static_cast<Image*>(data); ++image.protects;
        if (address!=image.Base()+0x3000 || count!=0x1000 || image.protects==image.failProtectAt || image.failAllProtect ||
            (image.failProtectFrom && image.protects>=image.failProtectFrom)) {
            if (image.changeOnProtectFailure) image.iatProtection=PAGE_READWRITE;
            *error=ERROR_ACCESS_DENIED; return false;
        }
        *old=image.iatProtection; image.iatProtection=protection;
        if (image.protects==1) image.Inject(1);
        if (image.protects==2) image.Inject(5);
        *error=ERROR_SUCCESS; return true;
    }
    static bool Cas(void* data, std::uintptr_t address, void* expected, void* desired,
        void** observed, DWORD* error) noexcept {
        auto& image=*static_cast<Image*>(data); ++image.writes;
        if (image.writes==image.failWriteAt) { *error=ERROR_NOACCESS; return false; }
        const auto rva=static_cast<DWORD>(address-image.Base());
        if (image.foreign && image.writes==image.foreignAt) image.Put(rva,reinterpret_cast<void*>(0x12345678));
        *observed=image.Get<void*>(rva);
        if (*observed==expected) image.Put(rva,desired);
        if (image.writes<=3) image.Inject(image.writes+1);
        else if (image.fourCells && image.writes==4) image.Inject(7);
        if (image.corruptLiteral && image.writes==3) image.bytes[image.profile.literalRva]='X';
        if (image.writes==image.failWriteAfterMutationAt) { *error=ERROR_NOACCESS; return false; }
        *error=ERROR_SUCCESS; return true;
    }
    static bool Stable(void* data, DWORD* error) noexcept {
        auto& image=*static_cast<Image*>(data);
        *error=ERROR_SUCCESS; return ++image.identities!=image.failIdentityAt;
    }
    static bool ValidateNative(void* data, DWORD* error) noexcept {
        auto& image=*static_cast<Image*>(data);
        ++image.nativeValidations;
        // The second immutable-profile check must also work after all IAT
        // targets have changed; this callback deliberately ignores those cells.
        if (image.nativeValidations==2) image.Inject(8);
        if (image.nativeValidations==image.failNativeValidationAt) {
            *error=ERROR_INVALID_DATA; return false;
        }
        *error=ERROR_SUCCESS; return true;
    }
    TransactionOps Ops() { return {{this,Query,Read},this,0x1000,Protect,Cas,Stable}; }
    InstallResult Run() { return InstallObserver(context,startup,profile,dispatch,Ops(),fourCells ? &pump : nullptr); }
    bool Original() const {
        return Get<void*>(profile.factoryIatRva)==reinterpret_cast<void*>(&Factory) &&
            Get<void*>(profile.shutdownIatRva)==reinterpret_cast<void*>(&Shutdown) &&
            Get<void*>(profile.initIatRva)==reinterpret_cast<void*>(&Init) &&
            (!fourCells || Get<void*>(pump.iatRva)==reinterpret_cast<void*>(&Pump));
    }
};
void ConfigChecks() {
    Config config{};
    const auto parse=[&](const char* text) { return ParseConfig(text,std::strlen(text),&config); };
    RS2_CHECK(parse("enabled=1\n")==Reason::None && config.maxLogMiB==512);
    RS2_CHECK(parse("enabled=0\r\n")==Reason::ConfigDisabled);
    RS2_CHECK(parse(" enabled = 1\r\nmax_log_mib=1024\r\n")==Reason::None && config.maxLogMiB==1024);
    for (const auto text: {"", "max_log_mib=64", "enabled=1\nenabled=0",
        "enabled=1\nmax_log_mib=15", "enabled=1\nmax_log_mib=1025",
        "enabled=1\nsecret=2", "enabled=01", "enabled=1\rjunk",
        "enabled=1\nmax_log_mib=42949672960", "enabled=1\nmax_log_mib=-1",
        "enabled=1\nmax_log_mib=16\nmax_log_mib=16", "enabled=\xFF"})
        RS2_CHECK(parse(text)==Reason::ConfigInvalid);
    std::array<char,4097> tooLong{}; tooLong.fill(' ');
    RS2_CHECK(ParseConfig(tooLong.data(),tooLong.size(),&config)==Reason::ConfigInvalid);
    const char nullByte[]{'e','n','a','b','l','e','d','=','1',0};
    RS2_CHECK(ParseConfig(nullByte,sizeof(nullByte),&config)==Reason::ConfigInvalid);
}
void Transactions() {
    for (const DWORD protection: {DWORD{PAGE_READONLY},DWORD{PAGE_READWRITE}}) {
        Image image; image.iatProtection=protection;
        const auto result=image.Run();
        RS2_CHECK(result.armed && !result.fatal && result.reason==Reason::None);
        RS2_CHECK(ReadGate(image.dispatch)==Gate::Armed && image.iatProtection==protection);
        RS2_CHECK(image.protects==2 && image.writes==3);
    }
    { Image image; image.iatProtection=PAGE_WRITECOPY; const auto result=image.Run();
      RS2_CHECK(!result.armed && !result.fatal && result.reason==Reason::UnsupportedProtection);
      RS2_CHECK(image.protects==0 && image.writes==0 && image.Original());
      RS2_CHECK(image.iatProtection==PAGE_WRITECOPY); }
    for (unsigned method=0; method<3; ++method) {
        for (unsigned boundary=1; boundary<=6; ++boundary) {
            Image image; image.injectAt=boundary; image.injectMethod=method; g_originalCalls=0;
            const auto result=image.Run();
            RS2_CHECK(image.injected && g_originalCalls==1);
            RS2_CHECK(!result.armed && !result.fatal && result.reason==Reason::Contaminated);
            RS2_CHECK(image.Original() && image.iatProtection==PAGE_READONLY);
        }
    }
    for (unsigned failure=1; failure<=3; ++failure) {
        Image image; image.failWriteAt=failure;
        const auto result=image.Run();
        RS2_CHECK(!result.armed && !result.fatal && image.Original());
        RS2_CHECK(image.iatProtection==PAGE_READONLY);
    }
    for (unsigned failure=1; failure<=2; ++failure) {
        Image image; image.failProtectAt=failure;
        const auto result=image.Run();
        RS2_CHECK(!result.armed && !result.fatal && image.Original());
        RS2_CHECK(image.iatProtection==PAGE_READONLY);
    }
    { Image image; image.failAllProtect=true; const auto result=image.Run();
      RS2_CHECK(!result.armed && !result.fatal && result.reason==Reason::ProtectFailed);
      RS2_CHECK(result.error==ERROR_ACCESS_DENIED && image.writes==0 && image.Original());
      RS2_CHECK(image.iatProtection==PAGE_READONLY && ReadGate(image.dispatch)==Gate::Disabled); }
    { Image image; image.failAllProtect=true; image.failReadsAfterProtect=true;
      const auto result=image.Run();
      RS2_CHECK(!result.armed && result.fatal && result.reason==Reason::RollbackFailed);
      RS2_CHECK(image.writes==0); } // Failure does not permit assuming unchanged memory.
    { Image image; image.failAllProtect=true; image.changeOnProtectFailure=true;
      const auto result=image.Run();
      RS2_CHECK(!result.armed && result.fatal && result.reason==Reason::RollbackFailed);
      RS2_CHECK(image.writes==0 && image.iatProtection==PAGE_READWRITE); }
    { Image image; image.iatProtection=PAGE_READWRITE; image.failWriteAt=1; image.failProtectFrom=2;
      const auto result=image.Run();
      RS2_CHECK(!result.armed && result.fatal && result.reason==Reason::RollbackFailed);
      RS2_CHECK(image.Original() && result.error==ERROR_NOACCESS); } // Preserve the first real error after successful reads.
    { Image image; image.failIdentityAt=2; const auto result=image.Run();
      RS2_CHECK(!result.armed && !result.fatal && image.Original()); }
    { Image image; image.corruptLiteral=true; const auto result=image.Run();
      RS2_CHECK(!result.armed && !result.fatal && image.Original()); }
    { Image image; image.foreign=true; const auto result=image.Run();
      RS2_CHECK(!result.armed && result.fatal && result.reason==Reason::RollbackFailed);
      RS2_CHECK(image.Get<void*>(image.profile.shutdownIatRva)==reinterpret_cast<void*>(0x12345678)); }
    { Image image; image.failReadsAfterWrite=true; const auto result=image.Run();
      RS2_CHECK(!result.armed && result.fatal && result.reason==Reason::RollbackFailed); }
    { Image image; image.Put(image.profile.privateRva,std::uintptr_t{1}); const auto result=image.Run();
      RS2_CHECK(!result.armed && !result.fatal && image.protects==0 && image.writes==0); }
    { Image image; image.profile.initIatRva=0x2100; const auto result=image.Run();
      RS2_CHECK(!result.armed && !result.fatal && result.reason==Reason::PageMismatch && image.protects==0); }
    { Image image; image.context.staticLoad=0; const auto result=image.Run();
      RS2_CHECK(!result.armed && !result.fatal && image.protects==0); }
    { Image image; image.Put(image.profile.factoryIatRva,reinterpret_cast<void*>(0x1234));
      const auto result=image.Run(); RS2_CHECK(!result.armed && !result.fatal && image.protects==0); }
}
void FourCellTransactions() {
    for (const DWORD protection: {DWORD{PAGE_READONLY},DWORD{PAGE_READWRITE}}) {
        Image image(true); image.iatProtection=protection;
        const auto result=image.Run();
        RS2_CHECK(result.armed && !result.fatal && result.reason==Reason::None);
        RS2_CHECK(image.protects==2 && image.writes==4 && image.nativeValidations==2);
        RS2_CHECK(image.iatProtection==protection && ReadGate(image.dispatch)==Gate::Armed);
        RS2_CHECK(image.Get<void*>(image.pump.iatRva)==reinterpret_cast<void*>(&PumpWrapper));
        g_originalCalls=0;
        image.Get<ShutdownFn>(image.pump.iatRva)();
        RS2_CHECK(g_originalCalls==1 && g_pumpAdmitted);
    }
    for (unsigned method=0; method<4; ++method) {
        for (unsigned boundary=1; boundary<=8; ++boundary) {
            Image image(true); image.injectAt=boundary; image.injectMethod=method; g_originalCalls=0;
            const auto result=image.Run();
            RS2_CHECK(image.injected && g_originalCalls==1);
            RS2_CHECK(!result.armed && !result.fatal && result.reason==Reason::Contaminated);
            RS2_CHECK(image.Original() && image.iatProtection==PAGE_READONLY);
            if (method==3) RS2_CHECK(!g_pumpAdmitted);
        }
    }
    // Every cell, including the newly introduced last write, rolls back inside
    // one transaction. A failed CAS need not mean that memory was untouched.
    for (unsigned failure=1; failure<=4; ++failure) {
        Image image(true); image.failWriteAt=failure;
        const auto result=image.Run();
        RS2_CHECK(!result.armed && !result.fatal && image.Original());
        RS2_CHECK(image.iatProtection==PAGE_READONLY && ReadGate(image.dispatch)==Gate::Disabled);
    }
    { Image image(true); image.failWriteAfterMutationAt=4;
      const auto result=image.Run();
      RS2_CHECK(!result.armed && !result.fatal && image.Original());
      RS2_CHECK(image.writes==8 && result.error==ERROR_NOACCESS); }
    for (unsigned failure=1; failure<=2; ++failure) {
        Image image(true); image.failNativeValidationAt=failure;
        const auto result=image.Run();
        RS2_CHECK(!result.armed && !result.fatal && result.reason==Reason::ProfileMismatch);
        RS2_CHECK(image.Original() && image.iatProtection==PAGE_READONLY);
        RS2_CHECK(failure!=1 || (image.protects==0 && image.writes==0));
    }
    { Image image(true); image.foreign=true; image.foreignAt=4;
      const auto result=image.Run();
      RS2_CHECK(!result.armed && result.fatal && result.reason==Reason::RollbackFailed);
      RS2_CHECK(image.Get<void*>(image.pump.iatRva)==reinterpret_cast<void*>(0x12345678));
      RS2_CHECK(image.Get<void*>(image.profile.factoryIatRva)==reinterpret_cast<void*>(&Factory));
      RS2_CHECK(image.Get<void*>(image.profile.shutdownIatRva)==reinterpret_cast<void*>(&Shutdown));
      RS2_CHECK(image.Get<void*>(image.profile.initIatRva)==reinterpret_cast<void*>(&Init)); }
    for (const DWORD duplicate: {DWORD{0x3100},DWORD{0x3120},DWORD{0x3140}}) {
        Image image(true); image.pump.iatRva=duplicate;
        const auto result=image.Run();
        RS2_CHECK(!result.armed && !result.fatal && result.reason==Reason::InvalidContext);
        RS2_CHECK(image.protects==0 && image.writes==0);
    }
    { Image image(true); image.pump.iatRva=0x2100;
      const auto result=image.Run();
      RS2_CHECK(!result.armed && !result.fatal && result.reason==Reason::PageMismatch);
      RS2_CHECK(image.protects==0 && image.writes==0); }
    for (const DWORD invalid: {DWORD{0x3FFC},DWORD{Image::size-4},DWORD{Image::size}}) {
        Image image(true); image.pump.iatRva=invalid;
        const auto result=image.Run();
        RS2_CHECK(!result.armed && !result.fatal && image.protects==0 && image.writes==0);
    }
    { Image image(true); image.pump.iatRva=0x3FF8;
      image.Put(image.pump.iatRva,reinterpret_cast<void*>(&Pump));
      const auto result=image.Run();
      RS2_CHECK(result.armed && !result.fatal && image.writes==4); }
    { Image image(true); auto ops=image.Ops(); ops.pageSize=4;
      const auto result=InstallObserver(image.context,image.startup,image.profile,image.dispatch,ops,&image.pump);
      RS2_CHECK(!result.armed && !result.fatal && image.protects==0 && image.writes==0); }
    { Image image(true); image.pump.validateNativeProfile=nullptr;
      const auto result=image.Run();
      RS2_CHECK(!result.armed && !result.fatal && image.protects==0 && image.writes==0); }
    { Image image(true); image.Put(image.pump.iatRva,reinterpret_cast<void*>(0x1234));
      const auto result=image.Run();
      RS2_CHECK(!result.armed && !result.fatal && result.reason==Reason::VerifyFailed);
      RS2_CHECK(image.protects==0 && image.writes==0); }
}
} // namespace
void RunObserverTransactionTests() { ConfigChecks(); Transactions(); FourCellTransactions(); }
} // namespace rs2fix::testcases
