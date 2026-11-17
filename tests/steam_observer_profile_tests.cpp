#include "companion/steam_observer_profile.h"
#include "pe_reader.h"
#include "test_framework.h"
#include <array>
#include <cstring>
#if defined(RS2_OBSERVER_FILES_ONLY)
#include "shared/steam_sdk_cohort.h"
#endif

namespace rs2fix::testcases {
namespace {
#if !defined(RS2_OBSERVER_FILES_ONLY)
void InertMethod() {}
bool FailRead(void*, std::uintptr_t, void*, std::size_t, DWORD* error) noexcept {
    *error=ERROR_PARTIAL_COPY; return false;
}
void GuardedObjects() {
    using namespace observer;
    std::array<void*,kSlotCount> table{};
    table.fill(reinterpret_cast<void*>(&InertMethod));
    struct Object { void* table; } object{table.data()};
    RS2_CHECK(ValidateInterfaceObject(nullptr,&object));
    RS2_CHECK(!ValidateInterfaceObject(nullptr,nullptr));
    RS2_CHECK(!ValidateInterfaceObject(nullptr,reinterpret_cast<void*>(1)));
    auto ops=ProductionMemoryOps(); ops.read=FailRead;
    RS2_CHECK(!ValidateInterfaceObject(&ops,&object));
    table[43]=nullptr; RS2_CHECK(!ValidateInterfaceObject(nullptr,&object));
    table[43]=table.data(); RS2_CHECK(!ValidateInterfaceObject(nullptr,&object));
    object.table=reinterpret_cast<void*>(8); RS2_CHECK(!ValidateInterfaceObject(nullptr,&object));
    auto* guard=VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    RS2_CHECK(guard!=nullptr);
    if (guard) {
        DWORD old{};
        RS2_CHECK(VirtualProtect(guard,4096,PAGE_READWRITE|PAGE_GUARD,&old));
        object.table=guard;
        RS2_CHECK(!ValidateInterfaceObject(nullptr,&object));
        MEMORY_BASIC_INFORMATION region{};
        RS2_CHECK(VirtualQuery(guard,&region,sizeof(region))==sizeof(region));
        RS2_CHECK((region.Protect&PAGE_GUARD)!=0); // qualification did not consume the guard
        VirtualFree(guard,0,MEM_RELEASE);
    }
}
#else
#if !defined(RS2_CURRENT_FULLDUMP_PATH) || !defined(RS2_CURRENT_STOCK_PATH) || \
    !defined(RS2_DEPOT_STEAM_API_PATH) || !defined(RS2_DEPOT_STEAM_CLIENT_PATH)
#error Observer evidence requires both current images and both approved depot Steam files.
#endif
void QualifiedFile(const wchar_t* hostPath, const char* expectedHash, const wchar_t* sdkPath,
    const char* expectedSdkHash, const observer::Profile& profile) {
    using namespace observer;
    pe::Image host{}, sdk{};
    std::string error;
    if (!pe::ReadPeImage(hostPath,&host,&error) ||
        !pe::ReadPeImage(sdkPath,&sdk,&error)) {
        std::cerr << "observer evidence unavailable: " << error << '\n';
        RS2_CHECK(false); return;
    }
    Sha256Digest hash{};
    const bool hostHashed=HashBytesSha256(host.rawBytes.data(),host.rawBytes.size(),&hash);
    RS2_CHECK(hostHashed);
    if (!hostHashed) return;
    const bool hostQualified=!std::strcmp(FormatSha256Upper(hash).data(),expectedHash);
    RS2_CHECK(hostQualified);
    if (!hostQualified) return; // Never interpret an unapproved physical executable.
    RS2_CHECK(hash==profile.hostDigest);
    if (hash!=profile.hostDigest) return;
    const bool sdkHashed=HashBytesSha256(sdk.rawBytes.data(),sdk.rawBytes.size(),&hash);
    RS2_CHECK(sdkHashed);
    if (!sdkHashed) return;
    const bool sdkQualified=!std::strcmp(FormatSha256Upper(hash).data(),expectedSdkHash);
    RS2_CHECK(sdkQualified);
    if (!sdkQualified) return;
    RS2_CHECK(hash==profile.sdkDigest);
    if (hash!=profile.sdkDigest) return;
    RS2_CHECK(sdk.sizeOfImage==profile.sdkImageSize && sdk.coffTimestamp==profile.sdkTimestamp &&
        sdk.checksum==profile.sdkChecksum);
    RS2_CHECK(sdk.machine==IMAGE_FILE_MACHINE_AMD64 && sdk.optionalMagic==IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        (sdk.characteristics&IMAGE_FILE_DLL)!=0);
    for (std::size_t i=0; i<profile.spanCount; ++i) {
        const auto& span=profile.spans[i];
        std::vector<std::uint8_t> bytes;
        RS2_CHECK(pe::ReadImageRva(host,span.rva,span.size,&bytes,&error));
        RS2_CHECK(bytes.size()==span.size && !std::memcmp(bytes.data(),span.bytes,span.size));
    }
    std::vector<std::uint8_t> literal;
    RS2_CHECK(pe::ReadImageRva(host,profile.literalRva,sizeof(kInterfaceVersion),&literal,&error));
    RS2_CHECK(literal.size()==sizeof(kInterfaceVersion) &&
        !std::memcmp(literal.data(),kInterfaceVersion,sizeof(kInterfaceVersion)));
    const std::uint32_t rvas[]{profile.factoryIatRva,profile.shutdownIatRva,profile.initIatRva};
    const char* names[]{"SteamInternal_FindOrCreateGameServerInterface","SteamGameServer_Shutdown",
        "SteamInternal_GameServer_Init"};
    for (unsigned i=0; i<3; ++i) {
        unsigned found=0, exported=0;
        for (const auto& module:host.normalImports) for (const auto& symbol:module.symbols)
            if (symbol.iatRva==rvas[i] && module.name==profile.importModule &&
                !symbol.byOrdinal && symbol.name==names[i]) ++found;
        for (const auto& symbol:sdk.exports)
            if (symbol.name==names[i] && symbol.forwarder.empty()) ++exported;
        RS2_CHECK(found==1 && exported==1);
    }
}
bool QualifiedSdkFile(const wchar_t* path, const char* expectedHash, pe::Image* image, Sha256Digest& hash) {
    std::string error;
    const bool parsed=pe::ReadPeImage(path,image,&error);
    RS2_CHECK(parsed);
    if (!parsed) { std::cerr<<"SDK evidence unavailable: "<<error<<'\n';return false; }
    const bool hashed=HashBytesSha256(image->rawBytes.data(),image->rawBytes.size(),&hash);
    RS2_CHECK(hashed);
    if (!hashed) return false;
    const bool qualified=!std::strcmp(FormatSha256Upper(hash).data(),expectedHash);
    RS2_CHECK(qualified);
    return qualified; // No interpretation of unapproved SDK bytes below this gate.
}
bool DirectCodeExport(const pe::Image& image, const char* name, std::uint32_t expectedRva) {
    const pe::ExportSymbol* selected{};unsigned found{};
    for (const auto& symbol:image.exports) if (symbol.name==name) { selected=&symbol;++found; }
    RS2_CHECK(found==1);
    if (found!=1) return false;
    const auto* section=pe::FindSection(image,selected->rva,1);
    const bool direct=selected->rva==expectedRva && selected->forwarder.empty() && section &&
        (section->characteristics&(IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_EXECUTE))==
            (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_EXECUTE) &&
        !(section->characteristics&(IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_DISCARDABLE));
    RS2_CHECK(direct);return direct;
}
template<std::size_t N> void PhysicalBytes(const pe::Image& image, std::uint32_t rva,
    const std::uint8_t (&expected)[N]) {
    std::vector<std::uint8_t> bytes;std::string error;
    RS2_CHECK(pe::ReadImageRva(image,rva,N,&bytes,&error));
    RS2_CHECK(bytes.size()==N && !std::memcmp(bytes.data(),expected,N));
}
void InterfaceLiteral(const pe::Image& image, std::uint32_t rva) {
    std::vector<std::uint8_t> bytes;std::string error;
    RS2_CHECK(pe::ReadImageRva(image,rva,sizeof(observer::kInterfaceVersion),&bytes,&error));
    RS2_CHECK(bytes.size()==sizeof(observer::kInterfaceVersion) &&
        !std::memcmp(bytes.data(),observer::kInterfaceVersion,sizeof(observer::kInterfaceVersion)));
    const auto* section=pe::FindSection(image,rva,sizeof(observer::kInterfaceVersion));
    RS2_CHECK(section && (section->characteristics&IMAGE_SCN_MEM_READ) &&
        !(section->characteristics&(IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_DISCARDABLE)));
}
void DepotSdkFiles() {
    pe::Image api{},client{};
    Sha256Digest apiHash{},clientHash{};
    if (!QualifiedSdkFile(RS2_DEPOT_STEAM_API_PATH,
        "473F5A312B56519F347741B63F3DEA590946B96EA40EF3803D5F452C39AF2F1E",&api,apiHash) ||
        !QualifiedSdkFile(RS2_DEPOT_STEAM_CLIENT_PATH,
        "0F2B9F92F8FF709C328F4FF8D12E4C36459597D2A65791CBDAA9D45E793221E5",&client,clientHash)) return;
    const auto& cohort=kDepotSteam20260827;
    RS2_CHECK(apiHash==cohort.apiDigest && clientHash==cohort.clientDigest);
    RS2_CHECK(api.rawBytes.size()==262944 && api.sizeOfImage==0x44000 &&
        api.coffTimestamp==0x5E4F3180 && api.checksum==0x47CED);
    RS2_CHECK(client.rawBytes.size()==23960272 && client.sizeOfImage==0x1732000 &&
        client.coffTimestamp==0x6657943E && client.checksum==0x16DB2ED);
    RS2_CHECK(api.sizeOfImage==cohort.apiImageSize && api.coffTimestamp==cohort.apiTimestamp &&
        api.checksum==cohort.apiChecksum && client.sizeOfImage==cohort.clientImageSize &&
        client.coffTimestamp==cohort.clientTimestamp && client.checksum==cohort.clientChecksum);
    RS2_CHECK(client.machine==IMAGE_FILE_MACHINE_AMD64 && client.optionalMagic==IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        (client.characteristics&IMAGE_FILE_DLL)!=0);
    struct Export { const char* name;std::uint32_t rva; };
    const Export apiExports[]{
        {"SteamInternal_FindOrCreateGameServerInterface",0x7D00},
        {"SteamInternal_GameServer_Init",0x7D30},{"SteamGameServer_RunCallbacks",0x7C10},
        {"SteamGameServer_Shutdown",0x7C30},{"SteamAPI_RegisterCallback",0x6D30},
        {"SteamAPI_UnregisterCallback",0x7690},{"SteamAPI_RegisterCallResult",0x6D00},
        {"SteamAPI_UnregisterCallResult",0x7680}
    };
    for (const auto& entry:apiExports) DirectCodeExport(api,entry.name,entry.rva);
    const Export clientExports[]{
        {"CreateInterface",0xC5ACE0},{"Steam_BGetCallback",0x8D5910},
        {"Steam_FreeLastCallback",0x8D5940},{"Steam_GetAPICallResult",0x8D5960}
    };
    for (const auto& entry:clientExports) DirectCodeExport(client,entry.name,entry.rva);

    // Physical 013 wrappers, not the different 015 layout in SDK 1.57 headers.
    // Each is mov rax,[rcx]; jmp [rax+slot*8], preserving incoming arguments.
    using observer::Method;
    struct Slot { const char* name;std::uint32_t rva,slot,declaredSlot; };
    const Slot slots[]{
        {"LogOnAnonymous",0x1890,6,static_cast<std::uint32_t>(Method::LogOnAnonymous)},
        {"BLoggedOn",0x1940,8,static_cast<std::uint32_t>(Method::BLoggedOn)},
        {"SetMaxPlayerCount",0x1990,12,static_cast<std::uint32_t>(Method::SetMaxPlayerCount)},
        {"SetKeyValue",0x1C60,20,static_cast<std::uint32_t>(Method::SetKeyValue)},
        {"BUpdateUserData",0x18A0,27,static_cast<std::uint32_t>(Method::BUpdateUserData)},
        {"BeginAuthSession",0x1A30,29,static_cast<std::uint32_t>(Method::BeginAuthSession)},
        {"EndAuthSession",0x1A40,30,static_cast<std::uint32_t>(Method::EndAuthSession)},
        {"EnableHeartbeats",0x1A60,39,static_cast<std::uint32_t>(Method::EnableHeartbeats)},
        {"SetHeartbeatInterval",0x1A70,40,static_cast<std::uint32_t>(Method::SetHeartbeatInterval)},
        {"ComputeNewPlayerCompatibility",0x1E90,43,static_cast<std::uint32_t>(observer::kSlotCount-1)}
    };
    for (const auto& slot:slots) {
        RS2_CHECK(slot.declaredSlot==slot.slot);
        const auto name=std::string("SteamAPI_ISteamGameServer_")+slot.name;
        if (!DirectCodeExport(api,name.c_str(),slot.rva)) continue;
        const auto offset=slot.slot*8;
        if (offset<0x80) {
            const std::uint8_t expected[]{0x48,0x8B,0x01,0x48,0xFF,0x60,static_cast<std::uint8_t>(offset)};
            PhysicalBytes(api,slot.rva,expected);
        } else {
            const std::uint8_t expected[]{0x48,0x8B,0x01,0x48,0xFF,0xA0,
                static_cast<std::uint8_t>(offset),static_cast<std::uint8_t>(offset>>8),0,0};
            PhysicalBytes(api,slot.rva,expected);
        }
    }
    // Init's actual LEA selects the 013 literal; string presence alone would not
    // connect this ABI to the exported flat-init path.
    const std::uint8_t initReference[]{0x4C,0x8D,0x0D,0xCC,0xA8,0x01,0x00};
    PhysicalBytes(api,0x7DE5,initReference);
    RS2_CHECK(0x7DE5+sizeof(initReference)+0x1A8CC==0x226B8);
    InterfaceLiteral(api,0x226B8);
    const std::uint8_t factoryEntry[]{0x4C,0x8B,0x0D,0x39,0xF7,0x99,0x00,
        0x4C,0x8B,0xD2,0x4C,0x8B,0xD9,0x4D,0x85,0xC9,0x74,0x2E};
    PhysicalBytes(client,0xC5ACE0,factoryEntry);
    // This is compiled-in 013 support, not proof that an initialized live
    // CreateInterface returns an object or that its vtable is valid.
    InterfaceLiteral(client,0x11787D8);
    std::cout<<"Depot Steam pair physical PE/013 evidence checked; legacy 8165 client "
        "not available as a physical input, no new legacy-client/runtime qualification\n";
}
void QualifiedFiles() {
    QualifiedFile(RS2_CURRENT_FULLDUMP_PATH,
        "0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393",
        RS2_OBSERVER_SDK_PATH,"A44E5537939AE4EEBC69000589AA9B2437A667813A1657CC779198BAE9B815A9",
        observer::ProductionObserverProfile());
    QualifiedFile(RS2_CURRENT_STOCK_PATH,
        "F4E38510832D1FAADA8AAD3B88CD2255B3EA49267EF0E874468E23BDE4EDFCC3",
        RS2_OBSERVER_SDK_PATH,"A44E5537939AE4EEBC69000589AA9B2437A667813A1657CC779198BAE9B815A9",
        observer::StockReportingObserverProfile());
    QualifiedFile(RS2_CURRENT_FULLDUMP_PATH,
        "0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393",
        RS2_DEPOT_STEAM_API_PATH,"473F5A312B56519F347741B63F3DEA590946B96EA40EF3803D5F452C39AF2F1E",
        observer::DepotReportingObserverProfile());
    QualifiedFile(RS2_CURRENT_STOCK_PATH,
        "F4E38510832D1FAADA8AAD3B88CD2255B3EA49267EF0E874468E23BDE4EDFCC3",
        RS2_DEPOT_STEAM_API_PATH,"473F5A312B56519F347741B63F3DEA590946B96EA40EF3803D5F452C39AF2F1E",
        observer::StockDepotReportingObserverProfile());
    DepotSdkFiles();
}
#endif
}
#if defined(RS2_OBSERVER_FILES_ONLY)
void RunObserverFileProfileTests() { QualifiedFiles(); }
#else
void RunObserverProfileTests() { GuardedObjects(); }
#endif
}
