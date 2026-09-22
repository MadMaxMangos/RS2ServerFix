// Own-code startup host. This is deliberately separate from the inert-help
// functional harness and never loads VNGame/Steam/EOS or copied game code.
#include <Windows.h>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <iterator>
#if defined(RS2_OBSERVER_FIXTURE)
#include "steam_api_fixture.h"
#include "companion/steam_observer_dispatch.h"
#endif
#if defined(RS2_REPORTING_FIXTURE)
bool ExerciseReportingFixture();
#endif

extern "C" {
volatile DWORD FixtureState = 1;
BYTE FixtureHandle[20]{};
void FixtureInitialize();
int FixtureRecon(int draw, int count);
extern const BYTE FixtureReconLoad[];
__declspec(dllimport) void WINAPI X3DAudioInitialize(UINT32, FLOAT, BYTE*);
extern FARPROC __imp_X3DAudioInitialize;
#if defined(RS2_OBSERVER_FIXTURE)
void* FixtureSteamAccessor();
bool FixtureSteamPublisher(void*);
bool FixtureSteamAdvertise(void*);
extern std::uintptr_t FixtureSteamContext[3];
extern void* FixtureSteamPrivate;
extern void* FixtureSteamPublication;
extern FARPROC __imp_SteamInternal_GameServer_Init;
extern FARPROC __imp_SteamGameServer_Shutdown;
extern FARPROC __imp_SteamInternal_FindOrCreateGameServerInterface;
#endif
}

namespace {
bool Option(const wchar_t* option) noexcept {
    const wchar_t* cursor = GetCommandLineW();
    const std::size_t length = std::wcslen(option);
    while (*cursor != L'\0') {
        while (*cursor == L' ' || *cursor == L'\t') ++cursor;
        const wchar_t* start = cursor;
        bool quoted = false;
        while (*cursor != L'\0' && (quoted || (*cursor != L' ' && *cursor != L'\t'))) {
            if (*cursor == L'"') quoted = !quoted;
            ++cursor;
        }
        if (static_cast<std::size_t>(cursor - start) == length && std::wmemcmp(start, option, length) == 0) return true;
    }
    return false;
}
volatile DWORD g_initializeReturned{};
int g_selectorBeforeMain{};
bool g_companionBeforeMain{};
bool g_markerBeforeMain{};
bool g_dynamicRestored{};
bool OwnPath(const wchar_t* leaf, wchar_t* output, std::size_t capacity) noexcept {
    const DWORD size = GetModuleFileNameW(nullptr, output, static_cast<DWORD>(capacity));
    if (!size || size >= capacity) return false;
    wchar_t* slash = std::wcsrchr(output, L'\\');
    if (!slash) return false;
    const std::size_t prefix = static_cast<std::size_t>(slash + 1 - output);
    if (prefix + std::wcslen(leaf) >= capacity) return false;
    return wcscpy_s(output + prefix, capacity - prefix, leaf) == 0;
}
bool MarkerExists() noexcept {
    wchar_t leaf[100]{}, path[1024]{};
    if (swprintf_s(leaf, L"RS2ServerFix.loader.%lu.log", GetCurrentProcessId()) <= 0 ||
        !OwnPath(leaf, path, std::size(path))) return false;
    const DWORD attributes = GetFileAttributesW(path);
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}
bool WaitForReporter() noexcept {
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    wchar_t path[32768]{};
    const DWORD length = GetFinalPathNameByHandleW(output, path, static_cast<DWORD>(std::size(path)), FILE_NAME_NORMALIZED);
    if (!length || length >= std::size(path)) return false;
    HANDLE reader = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (reader == INVALID_HANDLE_VALUE) return false;
    bool found = false;
    const ULONGLONG deadline = GetTickCount64() + 2000;
    do {
        char bytes[4096]{}; DWORD read = 0; LARGE_INTEGER zero{};
        if (!SetFilePointerEx(reader, zero, nullptr, FILE_BEGIN) ||
            !ReadFile(reader, bytes, sizeof(bytes) - 1, &read, nullptr)) break;
        const char* line = std::strstr(bytes, "[RS2ServerFix]");
        if (line && std::strstr(line, "\r\n")) { found = true; break; }
        Sleep(10);
    } while (GetTickCount64() < deadline);
    return CloseHandle(reader) && found;
}
#if defined(RS2_OBSERVER_FIXTURE)
bool g_steamPrehookInstalled{};
FARPROC g_steamPrehookAlias{};
DWORD g_steamPrehookProtection{};
void PreHookSteamFactory() noexcept {
    // This mutation is confined to the disposable own-code EXE. The alias lives
    // inside the already imported fake DLL: module ownership and hash still
    // qualify, so the named-export/actual-IAT equality check must reject it.
    const auto module = GetModuleHandleW(L"rs2_test_steam_api.dll");
    const auto original = module ? GetProcAddress(module, "SteamInternal_FindOrCreateGameServerInterface") : nullptr;
    const auto alias = module ? GetProcAddress(module, "FixtureSteamFactoryAlias") : nullptr;
    MEMORY_BASIC_INFORMATION target{}, cell{};
    if (!original || !alias || original == alias || __imp_SteamInternal_FindOrCreateGameServerInterface != original ||
        FixtureState != 1 || g_initializeReturned || GetModuleHandleW(L"RS2ServerFix.dll") ||
        VirtualQuery(reinterpret_cast<const void*>(alias), &target, sizeof(target)) != sizeof(target) ||
        target.AllocationBase != module ||
        VirtualQuery(&__imp_SteamInternal_FindOrCreateGameServerInterface, &cell, sizeof(cell)) != sizeof(cell)) ExitProcess(94);
    DWORD protection{};
    if (!VirtualProtect(&__imp_SteamInternal_FindOrCreateGameServerInterface, sizeof(void*), PAGE_READWRITE, &protection)) ExitProcess(95);
    const auto replaced = InterlockedCompareExchangePointer(
        reinterpret_cast<PVOID volatile*>(&__imp_SteamInternal_FindOrCreateGameServerInterface),
        reinterpret_cast<PVOID>(alias), reinterpret_cast<PVOID>(original));
    DWORD ignored{};
    if (!VirtualProtect(&__imp_SteamInternal_FindOrCreateGameServerInterface, sizeof(void*), protection, &ignored) ||
        replaced != reinterpret_cast<PVOID>(original) || protection != cell.Protect ||
        VirtualQuery(&__imp_SteamInternal_FindOrCreateGameServerInterface, &cell, sizeof(cell)) != sizeof(cell) ||
        cell.Protect != protection || __imp_SteamInternal_FindOrCreateGameServerInterface != alias) ExitProcess(96);
    g_steamPrehookAlias = alias;
    g_steamPrehookProtection = protection;
    g_steamPrehookInstalled = true;
}
#if !defined(RS2_REPORTING_FIXTURE)
bool ExerciseSteamFixture() {
    namespace api = rs2fix::observer;
    // The imports are already mapped; never load another API or call real Steam.
    const auto module = GetModuleHandleW(L"rs2_test_steam_api.dll");
    const auto snapshot = reinterpret_cast<FixtureSteamSnapshotFn>(
        module ? GetProcAddress(module, "FixtureSteamReadSnapshot") : nullptr);
    if (!snapshot) return false;
    const auto before = snapshot();
    if (before.factory || before.init || before.shutdown || before.factoryAlias) return false;
    bool ok = true;
    SetLastError(0x4321);
    const auto init = reinterpret_cast<api::InitFn>(__imp_SteamInternal_GameServer_Init);
    const bool initialized = init(0x10203040, 8766, 7777, 27015, 3,
        reinterpret_cast<const char*>(kFixtureUnreadablePointer));
    ok = !initialized && GetLastError() == 0x5678 && ok;
    SetLastError(0x4321);
    void* object = FixtureSteamAccessor();
    ok = object && GetLastError() == 0x5678 && ok;
    if (!object) return false;
    SetLastError(0x4321);
    void* repeated = FixtureSteamAccessor();
    ok = repeated == object && GetLastError() == 0x5678 && ok;
    // Publication happens only after the CRT audio opportunity and observer
    // installation. This is fixture state, not a model of game ownership.
    FixtureSteamContext[1] = 1;
    FixtureSteamContext[2] = reinterpret_cast<std::uintptr_t>(object);
    FixtureSteamPrivate = object;
    FixtureSteamPublication = object;
    const auto table = *static_cast<const void* const**>(object);
    SetLastError(0x4321); reinterpret_cast<api::VoidMethod>(table[6])(object);
    ok = GetLastError() == 0x5678 && ok;
    SetLastError(0x4321); const bool logged = FixtureSteamPublisher(object);
    ok = logged && GetLastError() == 0x5678 && ok;
    SetLastError(0x4321); const bool advertised = FixtureSteamAdvertise(object);
    ok = advertised && GetLastError() == 0x5678 && ok;
    SetLastError(0x4321); reinterpret_cast<api::IntMethod>(table[12])(object, 64);
    ok = GetLastError() == 0x5678 && ok;
    const auto secret = reinterpret_cast<const char*>(kFixtureUnreadablePointer);
    SetLastError(0x4321); reinterpret_cast<api::KeyValueMethod>(table[20])(object, secret, secret);
    ok = GetLastError() == 0x5678 && ok;
    SetLastError(0x4321); const bool updated = reinterpret_cast<api::UpdateMethod>(table[27])(object, kFixtureSteamId, secret, 123);
    ok = !updated && GetLastError() == 0x5678 && ok;
    SetLastError(0x4321); const auto begun = reinterpret_cast<api::BeginMethod>(table[29])(object, secret, 17, kFixtureSteamId);
    ok = begun == 7 && GetLastError() == 0x5678 && ok;
    SetLastError(0x4321); reinterpret_cast<api::EndMethod>(table[30])(object, kFixtureSteamId);
    ok = GetLastError() == 0x5678 && ok;
    SetLastError(0x4321); reinterpret_cast<api::BoolArgumentMethod>(table[39])(object, true);
    ok = GetLastError() == 0x5678 && ok;
    SetLastError(0x4321); reinterpret_cast<api::IntMethod>(table[40])(object, -1);
    ok = GetLastError() == 0x5678 && ok;
    SetLastError(0x4321); reinterpret_cast<api::ShutdownFn>(__imp_SteamGameServer_Shutdown)();
    ok = GetLastError() == 0x5678 && ok;
    const auto after = snapshot();
    constexpr unsigned observed[]{6, 8, 12, 20, 27, 29, 30, 39, 40};
    for (unsigned i = 0; i < 44; ++i) {
        unsigned expected = 0;
        for (const auto slot : observed) if (slot == i) expected = i == 8 ? 2 : 1;
        ok = after.methods[i] == expected && ok;
    }
    const bool prehookRequested = Option(L"--prehook-steam-factory");
    if (prehookRequested) {
        MEMORY_BASIC_INFORMATION cell{};
        const bool preserved = g_steamPrehookInstalled && __imp_SteamInternal_FindOrCreateGameServerInterface == g_steamPrehookAlias &&
            VirtualQuery(&__imp_SteamInternal_FindOrCreateGameServerInterface, &cell, sizeof(cell)) == sizeof(cell) &&
            cell.Protect == g_steamPrehookProtection;
        std::printf("steam_prehook=installed-before-audio preserved=%s\n", preserved ? "true" : "false");
        ok = preserved && ok;
    }
    ok = after.factory == 2 && after.init == 1 && after.shutdown == 1 && after.badArguments == 0 &&
        after.factoryAlias == (prehookRequested ? 2u : 0u) && ok;
    std::printf("steam_fixture=%s factory=%u init=%u shutdown=%u bad_arguments=%u factory_alias=%u\n",
        ok ? "pass" : "fail", after.factory, after.init, after.shutdown, after.badArguments, after.factoryAlias);
    // Only the own-code fixture waits; the injected observer never blocks the
    // game on its logger. The runner inspects the actual emitted records.
    Sleep(1200);
    return ok;
}
#endif
#endif
__declspec(noinline) void WrongReturn() noexcept {
    X3DAudioInitialize(3, 343.5f, FixtureHandle);
    ++g_initializeReturned;
}
DWORD WINAPI WrongThread(void*) noexcept {
    FixtureInitialize();
    ++g_initializeReturned;
    return 0;
}
void DynamicCall() noexcept {
    wchar_t path[1024]{};
    if (!OwnPath(L"dynamic\\X3DAudio1_7.dll", path, std::size(path))) ExitProcess(83);
    HMODULE module = LoadLibraryExW(path, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) ExitProcess(84);
    FARPROC initialize = GetProcAddress(module, "X3DAudioInitialize");
    if (!initialize) ExitProcess(85);
    DWORD originalProtection = 0;
    if (!VirtualProtect(&__imp_X3DAudioInitialize, sizeof(__imp_X3DAudioInitialize), PAGE_READWRITE, &originalProtection)) ExitProcess(86);
    const auto original = __imp_X3DAudioInitialize;
    // Keep the profiled call site while routing through the dynamically loaded
    // proxy, so this case tests static-load eligibility with a matching caller.
    InterlockedExchangePointer(reinterpret_cast<PVOID volatile*>(&__imp_X3DAudioInitialize), reinterpret_cast<PVOID>(initialize));
    DWORD old = 0;
    if (!VirtualProtect(&__imp_X3DAudioInitialize, sizeof(__imp_X3DAudioInitialize), originalProtection, &old)) ExitProcess(87);
    FixtureInitialize();
    ++g_initializeReturned;
    DWORD prior = 0;
    if (!VirtualProtect(&__imp_X3DAudioInitialize, sizeof(__imp_X3DAudioInitialize), PAGE_READWRITE, &prior)) ExitProcess(88);
    InterlockedExchangePointer(reinterpret_cast<PVOID volatile*>(&__imp_X3DAudioInitialize), reinterpret_cast<PVOID>(original));
    if (!VirtualProtect(&__imp_X3DAudioInitialize, sizeof(__imp_X3DAudioInitialize), originalProtection, &old)) ExitProcess(89);
    MEMORY_BASIC_INFORMATION region{};
    g_dynamicRestored = __imp_X3DAudioInitialize == original &&
        VirtualQuery(&__imp_X3DAudioInitialize, &region, sizeof(region)) == sizeof(region) &&
        region.Protect == originalProtection;
    if (!g_dynamicRestored) ExitProcess(90);
    // Keep the dynamically attached proxy loaded until this own-code process exits.
}
}

#if defined(RS2_REPORTING_FIXTURE)
extern "C" bool FixtureReportingPrehookPreserved() noexcept {
    MEMORY_BASIC_INFORMATION cell{};
    return g_steamPrehookInstalled && __imp_SteamInternal_FindOrCreateGameServerInterface==g_steamPrehookAlias &&
        VirtualQuery(&__imp_SteamInternal_FindOrCreateGameServerInterface,&cell,sizeof(cell))==sizeof(cell) &&
        cell.Protect==g_steamPrehookProtection;
}
#endif
extern "C" void FixtureInitializerThunk() noexcept {
#if defined(RS2_OBSERVER_FIXTURE)
    if (Option(L"--prehook-steam-factory")) PreHookSteamFactory();
#endif
    if (Option(L"--prior-unrelated")) WrongReturn();
    if (Option(L"--wrong-stage")) FixtureState = 2;
    if (Option(L"--dynamic-load")) {
        DynamicCall();
    } else if (Option(L"--wrong-return")) {
        WrongReturn();
    } else if (Option(L"--wrong-thread")) {
        HANDLE thread = CreateThread(nullptr, 0, WrongThread, nullptr, 0, nullptr);
        if (!thread || WaitForSingleObject(thread, 10000) != WAIT_OBJECT_0) ExitProcess(80);
        CloseHandle(thread);
    } else {
        FixtureInitialize();
        ++g_initializeReturned;
        if (Option(L"--late-companion")) {
            wchar_t source[1024]{}, destination[1024]{};
            if (!OwnPath(L"pending-companion.dll", source, std::size(source)) ||
                !OwnPath(L"RS2ServerFix.dll", destination, std::size(destination)) ||
                !CopyFileW(source, destination, TRUE)) ExitProcess(91);
            FixtureInitialize();
            ++g_initializeReturned;
        }
        if (Option(L"--duplicate")) { FixtureInitialize(); ++g_initializeReturned; }
    }
    g_selectorBeforeMain = FixtureRecon(32767, 3);
    g_companionBeforeMain = GetModuleHandleW(L"RS2ServerFix.dll") != nullptr;
    g_markerBeforeMain = MarkerExists();
    FixtureState = 2;
}

#pragma section(".CRT$XCU", read)
extern "C" __declspec(allocate(".CRT$XCU")) void (*const FixtureInitializerSlot)() = FixtureInitializerThunk;

int wmain(int argc, wchar_t** argv) {
    if (FixtureState != 2) return 81;
    const int selected = FixtureRecon(32767, 3);
    const bool companion = GetModuleHandleW(L"RS2ServerFix.dll") != nullptr;
    int expected = -1;
    bool expectedCompanion = false;
    for (int i = 1; i < argc; ++i) {
        if (std::wcscmp(argv[i], L"--expect-original") == 0) expected = 3;
        else if (std::wcscmp(argv[i], L"--expect-corrected") == 0) expected = 2;
        else if (std::wcscmp(argv[i], L"--expect-companion") == 0) expectedCompanion = true;
    }
    const bool beforeMain = g_selectorBeforeMain == selected && g_companionBeforeMain == companion && g_initializeReturned != 0;
    std::printf("fixture_state=%lu selector=%d companion=%s before_main=%s marker_before_main=%s calls=%lu dynamic_restored=%s\n",
        FixtureState, selected, companion ? "present" : "absent", beforeMain ? "true" : "false",
        g_markerBeforeMain ? "true" : "false", g_initializeReturned, g_dynamicRestored ? "true" : "false");
    std::fflush(stdout);
    const bool valid = expected >= 0 && selected == expected && companion == expectedCompanion && beforeMain;
    if (Option(L"--immediate-exit")) ExitProcess(valid ? 0 : 82);
    // Ordinary tests observe completion through their own redirected output;
    // immediate-exit cases deliberately do not wait for this report-only thread.
    if (companion && !WaitForReporter()) return 92;
#if defined(RS2_OBSERVER_FIXTURE)
#if defined(RS2_REPORTING_FIXTURE)
    if (!ExerciseReportingFixture()) return 93;
#else
    if (!ExerciseSteamFixture()) return 93;
#endif
#endif
    return valid ? 0 : 82;
}
