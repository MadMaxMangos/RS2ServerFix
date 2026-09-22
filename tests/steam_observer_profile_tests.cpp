#include "companion/steam_observer_profile.h"
#include "pe_reader.h"
#include "test_framework.h"
#include <array>
#include <cstring>

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
void QualifiedFiles() {
    using namespace observer;
    const auto& profile=ProductionObserverProfile();
    pe::Image host{}, sdk{};
    std::string error;
    if (!pe::ReadPeImage(RS2_OBSERVER_HOST_PATH,&host,&error) ||
        !pe::ReadPeImage(RS2_OBSERVER_SDK_PATH,&sdk,&error)) {
        std::cerr << "observer evidence unavailable: " << error << '\n';
        RS2_CHECK(false); return;
    }
    Sha256Digest hash{};
    RS2_CHECK(HashBytesSha256(host.rawBytes.data(),host.rawBytes.size(),&hash));
    RS2_CHECK(hash==profile.hostDigest);
    RS2_CHECK(HashBytesSha256(sdk.rawBytes.data(),sdk.rawBytes.size(),&hash));
    RS2_CHECK(hash==profile.sdkDigest);
    RS2_CHECK(sdk.sizeOfImage==profile.sdkImageSize && sdk.coffTimestamp==profile.sdkTimestamp &&
        sdk.checksum==profile.sdkChecksum);
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
#endif
}
#if defined(RS2_OBSERVER_FILES_ONLY)
void RunObserverFileProfileTests() { QualifiedFiles(); }
#else
void RunObserverProfileTests() { GuardedObjects(); }
#endif
}
