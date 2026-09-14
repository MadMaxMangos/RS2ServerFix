#include "shared/path_identity.h"
#include "companion/sha256.h"
#include <Windows.h>
#include <TlHelp32.h>
#define X3DAudioInitialize X3DAudioInitialize_SdkDeclarationOnly
#define X3DAudioCalculate X3DAudioCalculate_SdkDeclarationOnly
#include <x3daudio.h>
#undef X3DAudioCalculate
#undef X3DAudioInitialize
#include <array>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

extern "C" __declspec(dllimport) void WINAPI X3DAudioInitialize(UINT32, FLOAT, BYTE*);
volatile auto g_x3audioInitializeImportAnchor = &X3DAudioInitialize;
static_assert(X3DAUDIO_HANDLE_BYTESIZE == 20);
static_assert(sizeof(X3DAUDIO_LISTENER) == 56 && offsetof(X3DAUDIO_LISTENER, pCone) == 48);
static_assert(sizeof(X3DAUDIO_EMITTER) == 128 && offsetof(X3DAUDIO_EMITTER, ChannelCount) == 64);
static_assert(offsetof(X3DAUDIO_EMITTER, pVolumeCurve) == 80);
static_assert(sizeof(X3DAUDIO_DSP_SETTINGS) == 56 && offsetof(X3DAUDIO_DSP_SETTINGS, SrcChannelCount) == 16);
static_assert(offsetof(X3DAUDIO_DSP_SETTINGS, EmitterToListenerDistance) == 44);

namespace {
using CalculateFn = void(WINAPI*)(const BYTE*, const void*, const void*, UINT32, void*);
constexpr wchar_t kAudioLeaf[] = L"X3DAudio1_7.dll";
constexpr wchar_t kCompanionLeaf[] = L"RS2ServerFix.dll";
struct Options { std::wstring_view mode, modules, marker; };
void Usage() {
    std::cout << "rs2_static_import_harness --mode <vector|concurrent|fail-initialize|fail-calculate|immediate-exit>\n"
        "  [--expect-modules <system-only|proxy-and-system> --expect-marker absent]\n"
        "Sole --help performs no mode action. vector/concurrent require expectations; other modes forbid them.\n";
}
bool Parse(int argc, wchar_t** argv, Options* options) {
    if ((argc - 1) % 2 != 0) return false;
    for (int i = 1; i < argc; i += 2) {
        const std::wstring_view key(argv[i]), value(argv[i + 1]);
        if (value.empty() || value.find(L'"') != value.npos) return false;
        std::wstring_view* target = key == L"--mode" ? &options->mode :
            key == L"--expect-modules" ? &options->modules : key == L"--expect-marker" ? &options->marker : nullptr;
        if (target == nullptr || !target->empty()) return false;
        *target = value;
    }
    if (options->mode == L"vector" || options->mode == L"concurrent")
        return (options->modules == L"system-only" || options->modules == L"proxy-and-system") && options->marker == L"absent";
    return (options->mode == L"fail-initialize" || options->mode == L"fail-calculate" || options->mode == L"immediate-exit") &&
        options->modules.empty() && options->marker.empty();
}
bool OwnDirectory(std::wstring* directory) {
    std::array<wchar_t, rs2fix::kPathCapacity> path{}, result{}, leaf{};
    DWORD error = 0;
    if (!rs2fix::GetBoundedModulePath(nullptr, path.data(), path.size(), &error) ||
        !rs2fix::ExtractDirectoryAndLeaf(path.data(), path.size(), result.data(), result.size(),
            leaf.data(), leaf.size(), &error)) return false;
    *directory = result.data(); return true;
}
bool SameFile(const wchar_t* left, const wchar_t* right) {
    rs2fix::FileIdentity a{}, b{}; DWORD error = 0;
    return rs2fix::QueryFileIdentity(left, &a, &error) && rs2fix::QueryFileIdentity(right, &b, &error) &&
        rs2fix::SameFileIdentity(a, b);
}
struct Modules { HMODULE selected{}; bool valid{}; };
Modules InspectModules(bool proxy, bool requireCompleteSet) {
    Modules result{};
    std::wstring directory;
    std::array<wchar_t, 512> system{}; DWORD error = 0;
    if (!OwnDirectory(&directory) || !rs2fix::BuildSystemX3AudioPath(system.data(), system.size(), &error)) return result;
    const std::wstring local = directory + L"\\" + kAudioLeaf;
    HANDLE snapshot = INVALID_HANDLE_VALUE;
    for (unsigned attempt = 0; attempt < 3 && snapshot == INVALID_HANDLE_VALUE; ++attempt) {
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (snapshot == INVALID_HANDLE_VALUE && GetLastError() != ERROR_BAD_LENGTH) return result;
    }
    if (snapshot == INVALID_HANDLE_VALUE) return result;
    MODULEENTRY32W entry{}; entry.dwSize = sizeof(entry);
    bool ok = Module32FirstW(snapshot, &entry) != FALSE;
    unsigned audioCount = 0, localCount = 0, systemCount = 0, companionCount = 0;
    std::vector<rs2fix::FileIdentity> seen;
    while (ok) {
        if (_wcsicmp(entry.szModule, kCompanionLeaf) == 0) ++companionCount;
        if (_wcsicmp(entry.szModule, kAudioLeaf) == 0) {
            ++audioCount;
            std::array<wchar_t, rs2fix::kPathCapacity> loaded{};
            rs2fix::FileIdentity identity{};
            if (!rs2fix::GetBoundedModulePath(entry.hModule, loaded.data(), loaded.size(), &error) ||
                !rs2fix::QueryFileIdentity(loaded.data(), &identity, &error)) { ok = false; break; }
            for (const auto& old : seen) if (rs2fix::SameFileIdentity(old, identity)) ok = false;
            if (!ok) break;
            seen.push_back(identity);
            const bool isSystem = _wcsicmp(loaded.data(), system.data()) == 0 && SameFile(loaded.data(), system.data());
            const bool isLocal = _wcsicmp(loaded.data(), local.c_str()) == 0 && SameFile(loaded.data(), local.c_str());
            if (isSystem) ++systemCount;
            if (isLocal) ++localCount;
            if (proxy ? isLocal : isSystem) result.selected = entry.hModule;
            if (!isSystem && !isLocal) { ok = false; break; }
        }
        SetLastError(ERROR_SUCCESS);
        if (!Module32NextW(snapshot, &entry)) {
            ok = GetLastError() == ERROR_NO_MORE_FILES; break;
        }
    }
    if (!CloseHandle(snapshot)) ok = false;
    const bool expectedSet = proxy ? audioCount == 2 && localCount == 1 && systemCount == 1
                                  : audioCount == 1 && localCount == 0 && systemCount == 1;
    result.valid = ok && result.selected != nullptr && companionCount == 0 && (!requireCompleteSet || expectedSet);
    return result;
}
bool Vector(bool proxy, rs2fix::Sha256Digest* digest) {
    BYTE instance[X3DAUDIO_HANDLE_BYTESIZE]{};
    X3DAUDIO_LISTENER listener{}; X3DAUDIO_EMITTER emitter{}; X3DAUDIO_DSP_SETTINGS settings{};
    FLOAT matrix[2]{}, delays[2]{};
    listener.OrientFront = {0, 0, 1}; listener.OrientTop = {0, 1, 0};
    emitter.OrientFront = {0, 0, 1}; emitter.OrientTop = {0, 1, 0}; emitter.Position = {0, 0, 1};
    emitter.ChannelCount = 1; emitter.CurveDistanceScaler = 1; emitter.DopplerScaler = 1;
    settings.pMatrixCoefficients = matrix; settings.pDelayTimes = delays;
    settings.SrcChannelCount = 1; settings.DstChannelCount = 2;
    constexpr UINT32 flags = X3DAUDIO_CALCULATE_MATRIX | X3DAUDIO_CALCULATE_DELAY |
        X3DAUDIO_CALCULATE_LPF_DIRECT | X3DAUDIO_CALCULATE_LPF_REVERB | X3DAUDIO_CALCULATE_REVERB |
        X3DAUDIO_CALCULATE_DOPPLER | X3DAUDIO_CALCULATE_EMITTER_ANGLE;
    X3DAudioInitialize(SPEAKER_STEREO, X3DAUDIO_SPEED_OF_SOUND, instance);
    const auto modules = InspectModules(proxy, true);
    if (!modules.valid) return false;
    const auto calculate = reinterpret_cast<CalculateFn>(GetProcAddress(modules.selected, "X3DAudioCalculate"));
    if (calculate == nullptr) return false;
    calculate(instance, &listener, &emitter, flags, &settings);
    std::array<BYTE, 68> canonical{};
    std::memcpy(canonical.data(), instance, sizeof(instance));
    const FLOAT values[] = {settings.LPFDirectCoefficient, settings.LPFReverbCoefficient,
        settings.ReverbLevel, settings.DopplerFactor, settings.EmitterToListenerAngle,
        settings.EmitterToListenerDistance, settings.EmitterVelocityComponent,
        settings.ListenerVelocityComponent, matrix[0], matrix[1], delays[0], delays[1]};
    static_assert(sizeof(values) + sizeof(instance) == 68);
    for (std::size_t i = 0; i < std::size(values); ++i)
        std::memcpy(canonical.data() + sizeof(instance) + i * sizeof(FLOAT), &values[i], sizeof(FLOAT));
    return rs2fix::HashBytesSha256(canonical.data(), canonical.size(), digest);
}
struct ThreadData { HANDLE start{}; bool proxy{}, success{}; rs2fix::Sha256Digest digest{}; };
DWORD WINAPI VectorThread(void* argument) {
    auto& data = *static_cast<ThreadData*>(argument);
    if (WaitForSingleObject(data.start, 20000) == WAIT_OBJECT_0) data.success = Vector(data.proxy, &data.digest);
    return data.success ? 0 : 1;
}
bool Concurrent(bool proxy, rs2fix::Sha256Digest* digest) {
    HANDLE start = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (start == nullptr) return false;
    std::array<ThreadData, 16> data{}; std::array<HANDLE, 16> threads{};
    DWORD count = 0;
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i].start = start; data[i].proxy = proxy;
        threads[i] = CreateThread(nullptr, 0, VectorThread, &data[i], 0, nullptr);
        if (threads[i] == nullptr) break;
        ++count;
    }
    SetEvent(start);
    if (count != 0 && WaitForMultipleObjects(count, threads.data(), TRUE, 20000) != WAIT_OBJECT_0)
        ExitProcess(ERROR_TIMEOUT);
    bool success = count == data.size();
    for (std::size_t i = 0; i < count; ++i) {
        success = data[i].success && data[i].digest == data[0].digest && success;
        if (!CloseHandle(threads[i])) success = false;
    }
    if (!CloseHandle(start)) success = false;
    if (success) *digest = data[0].digest;
    return success;
}
bool Absent(const std::wstring& path) {
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return false;
    const DWORD error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}
bool NoMarkerOrCompanion(bool proxy) {
    std::wstring directory;
    std::array<wchar_t, rs2fix::kPathCapacity> temp{};
    const DWORD count = GetTempPathW(static_cast<DWORD>(temp.size()), temp.data());
    if (!OwnDirectory(&directory) || count == 0 || count >= temp.size()) return false;
    const std::wstring leaf = L"RS2ServerFix.loader." + std::to_wstring(GetCurrentProcessId()) + L".log";
    const ULONGLONG deadline = GetTickCount64() + 2000;
    do {
        if (!Absent(directory + L"\\" + leaf) || !Absent(std::wstring(temp.data()) + leaf) ||
            GetModuleHandleW(kCompanionLeaf) != nullptr) return false;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    return InspectModules(proxy, true).valid;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"--help") { Usage(); return 0; }
    Options options{};
    if (!Parse(argc, argv, &options)) { Usage(); return 2; }
    if (options.mode == L"immediate-exit") ExitProcess(0);
    if (g_x3audioInitializeImportAnchor == nullptr) return 1;
    if (options.mode == L"fail-initialize") {
        BYTE instance[20]{}; X3DAudioInitialize(SPEAKER_STEREO, X3DAUDIO_SPEED_OF_SOUND, instance); return 1;
    }
    if (options.mode == L"fail-calculate") {
        auto modules = InspectModules(true, false);
        if (!modules.valid) return 1;
        auto calculate = reinterpret_cast<CalculateFn>(GetProcAddress(modules.selected, "X3DAudioCalculate"));
        if (calculate == nullptr) return 1;
        BYTE instance[20]{}, listener[56]{}, emitter[128]{}, settings[56]{};
        calculate(instance, listener, emitter, 0, settings); return 1;
    }
    rs2fix::Sha256Digest digest{};
    const bool proxy = options.modules == L"proxy-and-system";
    if (!(options.mode == L"concurrent" ? Concurrent(proxy, &digest) : Vector(proxy, &digest)) ||
        !NoMarkerOrCompanion(proxy)) { std::cerr << "functional_or_module_or_absence_check_failed\n"; return 1; }
    const auto hex = rs2fix::FormatSha256Upper(digest);
    std::cout << "digest_sha256=" << hex.data() << '\n';
    return 0;
}
