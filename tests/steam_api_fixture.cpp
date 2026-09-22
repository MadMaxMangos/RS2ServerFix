// An inert, own-code DLL. No SDK headers, imports, networking or callbacks.
#include "steam_api_fixture.h"
#include <Windows.h>
#include <cstring>
#include <iterator>
#if defined(RS2_REPORTING_FIXTURE)
#include <cwchar>
#endif

extern "C" const char FixtureSteamSignature[] = "RS2-OWN-INERT-STEAM-FIXTURE-NOT-FOR-DEPLOYMENT";
namespace {
FixtureSteamSnapshot state{};
#if defined(RS2_REPORTING_FIXTURE)
HMODULE clientModule{};
bool Option(const wchar_t* option) noexcept {
    const wchar_t* cursor=GetCommandLineW();
    const auto length=std::wcslen(option);
    while (*cursor) {
        while (*cursor==L' ' || *cursor==L'\t') ++cursor;
        const wchar_t* start=cursor;
        bool quoted=false;
        while (*cursor && (quoted || (*cursor!=L' ' && *cursor!=L'\t'))) {
            if (*cursor==L'"') quoted=!quoted;
            ++cursor;
        }
        if (static_cast<std::size_t>(cursor-start)==length && std::wmemcmp(start,option,length)==0) return true;
    }
    return false;
}
bool SamePath(const wchar_t* a,const wchar_t* b) noexcept {
    return CompareStringOrdinal(a,-1,b,-1,TRUE)==CSTR_EQUAL;
}
bool LoadOwnClient() noexcept {
    if (clientModule) return true; // This fake SDK owns exactly one retained reference.
    ++state.clientLoadAttempts;
    HMODULE self{};
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<const wchar_t*>(FixtureSteamSignature),&self)) return false;
    wchar_t path[32768]{}, canonical[32768]{};
    const auto length=GetModuleFileNameW(self,path,static_cast<DWORD>(std::size(path)));
    if (length<3 || length>=std::size(path) || path[1]!=L':' || path[2]!=L'\\' ||
        !((path[0]>=L'A' && path[0]<=L'Z') || (path[0]>=L'a' && path[0]<=L'z'))) return false;
    const auto resolved=GetFullPathNameW(path,static_cast<DWORD>(std::size(canonical)),canonical,nullptr);
    if (!resolved || resolved>=std::size(canonical) || !SamePath(path,canonical)) return false;
    wchar_t* leaf=std::wcsrchr(path,L'\\');
    if (!leaf || !SamePath(leaf+1,L"rs2_test_steam_api.dll")) return false;
    ++leaf;
    if (wcscpy_s(leaf,std::size(path)-static_cast<std::size_t>(leaf-path),kFixtureSteamClientLeaf)) return false;
    // Full sibling path only: no CWD, PATH, game DLL name, callback or network.
    // The restricted dependency search cannot turn a missing fixture into a
    // real Steam client. Verify the module returned is this exact path as well.
    const HMODULE loaded=LoadLibraryExW(path,nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!loaded) return false;
    const auto loadedLength=GetModuleFileNameW(loaded,canonical,static_cast<DWORD>(std::size(canonical)));
    bool valid=loadedLength && loadedLength<std::size(canonical) && SamePath(path,canonical);
    const auto* signature=reinterpret_cast<const char*>(GetProcAddress(loaded,"FixtureSteamClientSignature"));
    MEMORY_BASIC_INFORMATION region{};
    if (valid) {
        const auto address=reinterpret_cast<std::uintptr_t>(signature);
        valid=signature && VirtualQuery(signature,&region,sizeof(region))==sizeof(region) &&
            region.AllocationBase==loaded && region.State==MEM_COMMIT && region.Type==MEM_IMAGE &&
            region.Protect==PAGE_READONLY && address>=reinterpret_cast<std::uintptr_t>(region.BaseAddress) &&
            address-reinterpret_cast<std::uintptr_t>(region.BaseAddress)<=region.RegionSize &&
            sizeof(kFixtureSteamClientSignature)<=region.RegionSize-
                (address-reinterpret_cast<std::uintptr_t>(region.BaseAddress));
    }
    if (valid) valid=std::memcmp(signature,kFixtureSteamClientSignature,sizeof(kFixtureSteamClientSignature))==0;
    if (!valid) { FreeLibrary(loaded); return false; }
    clientModule=loaded; ++state.clientLoads;
    return true;
}
#endif
struct Object { const void* const* vtable; };
extern Object object;
void Hit(void* receiver, unsigned slot) {
    ++state.methods[slot];
    if (receiver != &object || GetLastError() != 0x4321) ++state.badArguments;
    SetLastError(0x5678);
}
void Opaque(void*) { ++state.badArguments; }
void LogOn(void* receiver) { Hit(receiver, 6); }
bool LoggedOn(void* receiver) { Hit(receiver, 8); return true; }
void MaxPlayers(void* receiver, std::int32_t count) { Hit(receiver, 12); if (count != 64) ++state.badArguments; }
void KeyValue(void* receiver, const char* key, const char* value) {
    Hit(receiver, 20);
    if (reinterpret_cast<std::uintptr_t>(key) != kFixtureUnreadablePointer || key != value) ++state.badArguments;
}
bool Update(void* receiver, std::uint64_t id, const char* name, std::uint32_t score) {
    Hit(receiver, 27);
    if (id != kFixtureSteamId || reinterpret_cast<std::uintptr_t>(name) != kFixtureUnreadablePointer || score != 123) ++state.badArguments;
    return false;
}
std::int32_t Begin(void* receiver, const void* ticket, std::int32_t size, std::uint64_t id) {
    Hit(receiver, 29);
    if (id != kFixtureSteamId || reinterpret_cast<std::uintptr_t>(ticket) != kFixtureUnreadablePointer || size != 17) ++state.badArguments;
    return 7;
}
void End(void* receiver, std::uint64_t id) { Hit(receiver, 30); if (id != kFixtureSteamId) ++state.badArguments; }
void Heartbeats(void* receiver, bool enabled) { Hit(receiver, 39); if (!enabled) ++state.badArguments; }
void Interval(void* receiver, std::int32_t interval) { Hit(receiver, 40); if (interval != -1) ++state.badArguments; }
#define SLOT(fn) reinterpret_cast<const void*>(&fn)
const void* const table[]{
    SLOT(Opaque), SLOT(Opaque), SLOT(Opaque), SLOT(Opaque), SLOT(Opaque), SLOT(Opaque), SLOT(LogOn), SLOT(Opaque),
    SLOT(LoggedOn), SLOT(Opaque), SLOT(Opaque), SLOT(Opaque), SLOT(MaxPlayers), SLOT(Opaque), SLOT(Opaque), SLOT(Opaque),
    SLOT(Opaque), SLOT(Opaque), SLOT(Opaque), SLOT(Opaque), SLOT(KeyValue), SLOT(Opaque), SLOT(Opaque), SLOT(Opaque),
    SLOT(Opaque), SLOT(Opaque), SLOT(Opaque), SLOT(Update), SLOT(Opaque), SLOT(Begin), SLOT(End), SLOT(Opaque),
    SLOT(Opaque), SLOT(Opaque), SLOT(Opaque), SLOT(Opaque), SLOT(Opaque), SLOT(Opaque), SLOT(Opaque), SLOT(Heartbeats),
    SLOT(Interval), SLOT(Opaque), SLOT(Opaque), SLOT(Opaque)
};
#undef SLOT
static_assert(std::size(table) == 44);
Object object{table};
}

// C++ linkage is intentional under /EHsc. The .def aliases provide exact flat
// export names without telling a caller that these indirect calls cannot throw.
__declspec(noinline) void* FixtureSteamFactory(std::int32_t user, const char* version) {
    ++state.factory;
    if (user != 23 || std::strcmp(version, "SteamGameServer013") || GetLastError() != 0x4321) ++state.badArguments;
    SetLastError(0x5678);
    return &object;
}
// Same loaded module and disk identity, but not the named factory's export
// address. The own-code host installs this before its audio startup opportunity
// to exercise real SDK binding rejection without changing the genuine API.
void* FixtureSteamFactoryAlias(std::int32_t user, const char* version) {
    ++state.factoryAlias;
    return FixtureSteamFactory(user, version);
}
bool FixtureSteamInit(std::uint32_t ip, std::uint16_t steamPort, std::uint16_t gamePort,
    std::uint16_t queryPort, std::int32_t mode, const char* version) {
    ++state.init;
    if (ip != 0x10203040 || steamPort != 8766 || gamePort != 7777 || queryPort != 27015 || mode != 3 ||
        reinterpret_cast<std::uintptr_t>(version) != kFixtureUnreadablePointer || GetLastError() != 0x4321) ++state.badArguments;
#if defined(RS2_REPORTING_FIXTURE)
    bool result=!Option(L"--report-init-false");
    // Deliberately true-without-client: the real cold qualifier must reject it,
    // rather than conflating a missing client with a false native Init result.
    if (result && !Option(L"--report-client-missing") && !LoadOwnClient()) {
        ++state.clientLoadFailures; result=false;
    }
    SetLastError(0x5678);
    return result;
#else
    SetLastError(0x5678);
    return false;
#endif
}
void FixtureSteamShutdown() {
    ++state.shutdown;
    if (GetLastError() != 0x4321) ++state.badArguments;
#if defined(RS2_REPORTING_FIXTURE)
    if (clientModule) {
        if (FreeLibrary(clientModule)) { clientModule=nullptr; ++state.clientUnloads; }
        else ++state.badArguments;
    }
#endif
    SetLastError(0x5678);
}
#if defined(RS2_REPORTING_FIXTURE)
void FixtureSteamRunCallbacks() {
    const DWORD incoming=GetLastError();
    state.pumpInnerBefore=0; state.pumpInnerAfter=0; state.pumpInnerCall=0;
    LARGE_INTEGER before{},after{};
    const bool started=QueryPerformanceCounter(&before)!=FALSE;
    ++state.pump;
    if (incoming!=0x4321) ++state.badArguments;
    const bool ended=QueryPerformanceCounter(&after)!=FALSE;
    if (started && ended && before.QuadPart>=0 && after.QuadPart>=before.QuadPart) {
        state.pumpInnerBefore=before.QuadPart; state.pumpInnerAfter=after.QuadPart;
        state.pumpInnerCall=state.pump;
    } else state.pumpClockErrors=1;
    SetLastError(0x5678);
}
#endif
FixtureSteamSnapshot FixtureSteamReadSnapshot() { return state; }
