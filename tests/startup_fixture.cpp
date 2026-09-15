// Own-code startup host. This is deliberately separate from the inert-help
// functional harness and never loads VNGame/Steam/EOS or copied game code.
#include <Windows.h>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <iterator>

extern "C" {
volatile DWORD FixtureState = 1;
BYTE FixtureHandle[20]{};
void FixtureInitialize();
int FixtureRecon(int draw, int count);
extern const BYTE FixtureReconLoad[];
__declspec(dllimport) void WINAPI X3DAudioInitialize(UINT32, FLOAT, BYTE*);
extern FARPROC __imp_X3DAudioInitialize;
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

extern "C" void FixtureInitializerThunk() noexcept {
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
    return valid ? 0 : 82;
}
