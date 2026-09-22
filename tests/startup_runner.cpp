#include "shared/path_identity.h"
#include "shared/version.h"
#include "companion/sha256.h"
#include "file_evidence.h"
#include "genuine_manifest.h"
#include "pe_contract_lib.h"
#include "tool_paths.h"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <map>
#include <string>
#include <string_view>
#include <vector>
#if defined(RS2_OBSERVER_RUNNER)
#include "steam_api_fixture.h"
#include <filesystem>
#endif
#if defined(RS2_REPORTING_RUNNER)
#include "shared/steam_reporting_status.h"
#include "companion/steam_reporting_types.h"
#endif

namespace {
namespace tool = rs2fix::tooling;
struct Input { std::wstring path; rs2fix::Sha256Digest digest{}; };
struct Inputs {
    Input host, bootstrap, passive, active, production; std::wstring manifest;
#if defined(RS2_OBSERVER_RUNNER)
    Input sdk;
    std::string expectedVersion;
#endif
#if defined(RS2_REPORTING_RUNNER)
    Input client;
    bool calibrationOnly{};
#endif
};
struct Child {
    bool created{}, ended{}, timedOut{}, captured{}, preparationFailed{};
    DWORD error{}, status{STILL_ACTIVE}, pid{};
    std::string output;
};
struct Scenario {
    const wchar_t* name;
    const wchar_t* options;
    bool active{}, companion{}, markerFailure{}, missing{}, invalid{}, late{}, dynamic{}, production{}, immediate{};
    unsigned calls{1};
#if defined(RS2_OBSERVER_RUNNER)
    // 0=enabled, 1=disabled, 2=missing, 3=invalid, 4=wrong SDK disk hash,
    // 5=blocked output path, 6=pre-existing same-SDK factory IAT hook.
    unsigned observerMode{};
#endif
#if defined(RS2_REPORTING_RUNNER)
    unsigned reportMode{};
#endif
};
void Usage() {
#if defined(RS2_REPORTING_RUNNER)
    std::cout << "rs2_reporting_startup_runner --host <absolute-file> --bootstrap <absolute-file>\n"
        "  --companion <absolute-file> --sdk <absolute-inert-fixture-dll> --client <absolute-inert-client-dll>\n"
        "  --expected-companion-version 0.4.1.0 --genuine-manifest <absolute-file> [--calibration-only]\n"
        "Sole --help performs no process or file work.\n";
#elif defined(RS2_OBSERVER_RUNNER)
    std::cout << "rs2_observer_startup_runner --host <absolute-file> --bootstrap <absolute-file>\n"
        "  --companion <absolute-file> --sdk <absolute-inert-fixture-dll>\n"
        "  --expected-companion-version 0.3.0.0 --genuine-manifest <absolute-file>\n"
        "Sole --help performs no process or file work.\n";
#else
    std::cout << "rs2_startup_runner --host <absolute-file> --bootstrap <absolute-file>\n"
        "  --passive <absolute-file> --active <absolute-file> --genuine-manifest <absolute-file>\n"
        "  [--production-bootstrap <absolute-file>]\nSole --help performs no process or file work.\n";
#endif
}
bool Parse(int argc, wchar_t** argv, Inputs* inputs) {
#if defined(RS2_OBSERVER_RUNNER)
#if defined(RS2_REPORTING_RUNNER)
    if (argc!=15 && argc!=16) return false;
    if (argc==16) {
        if (std::wstring_view(argv[15])!=L"--calibration-only") return false;
        inputs->calibrationOnly=true;
    }
    const int arguments=15;
#else
    if (argc != 13) return false;
    const int arguments=argc;
#endif
    for (int i = 1; i < arguments; i += 2) {
        const std::wstring_view key(argv[i]);
        if (key == L"--expected-companion-version") {
#if defined(RS2_REPORTING_RUNNER)
            if (!inputs->expectedVersion.empty() || std::wcscmp(argv[i + 1], L"0.4.1.0")) return false;
            inputs->expectedVersion = "0.4.1.0";
#else
            if (!inputs->expectedVersion.empty() || std::wcscmp(argv[i + 1], L"0.3.0.0")) return false;
            inputs->expectedVersion = "0.3.0.0";
#endif
            continue;
        }
        std::wstring* target = key == L"--host" ? &inputs->host.path : key == L"--bootstrap" ? &inputs->bootstrap.path :
            key == L"--companion" ? &inputs->active.path : key == L"--sdk" ? &inputs->sdk.path :
#if defined(RS2_REPORTING_RUNNER)
            key == L"--client" ? &inputs->client.path :
#endif
            key == L"--genuine-manifest" ? &inputs->manifest : nullptr;
        if (!target || !target->empty() || !tool::IsAbsoluteToolPath(argv[i + 1])) return false;
        *target = argv[i + 1];
    }
    return !inputs->host.path.empty() && !inputs->bootstrap.path.empty() && !inputs->active.path.empty() &&
#if defined(RS2_REPORTING_RUNNER)
        !inputs->client.path.empty() &&
#endif
        !inputs->sdk.path.empty() && !inputs->expectedVersion.empty() && !inputs->manifest.empty();
#else
    if (argc != 11 && argc != 13) return false;
    for (int i = 1; i < argc; i += 2) {
        const std::wstring_view key(argv[i]);
        std::wstring* target = key == L"--host" ? &inputs->host.path : key == L"--bootstrap" ? &inputs->bootstrap.path :
            key == L"--passive" ? &inputs->passive.path : key == L"--active" ? &inputs->active.path :
            key == L"--genuine-manifest" ? &inputs->manifest : key == L"--production-bootstrap" ? &inputs->production.path : nullptr;
        if (!target || !target->empty() || !tool::IsAbsoluteToolPath(argv[i + 1])) return false;
        *target = argv[i + 1];
    }
    return !inputs->host.path.empty() && !inputs->bootstrap.path.empty() && !inputs->passive.path.empty() &&
        !inputs->active.path.empty() && !inputs->manifest.empty();
#endif
}
std::string ExpectedVersion(const Inputs& inputs) {
#if defined(RS2_OBSERVER_RUNNER)
    return inputs.expectedVersion;
#else
    (void)inputs;
    return RS2FIX_VERSION_ASCII;
#endif
}
bool Hash(const std::wstring& path, rs2fix::Sha256Digest* digest) {
    const auto result = rs2fix::HashFileSha256(path.c_str(), GetTickCount64() + 10000);
    if (!result.digestValid || result.timedOut) return false;
    *digest = result.digest; return true;
}
bool Artifact(Input* input, tool::ArtifactKind kind) {
    std::string error; std::wstring normalized; tool::ContractReport contract{};
    if (!tool::RequireAbsolutePlainFile(input->path.c_str(), &normalized, &error) ||
        !tool::CheckArtifactContract(normalized.c_str(), kind, &contract)) {
        std::cerr << "artifact_path=" << error << '\n';
        for (const auto& finding : contract.findings) std::cerr << "artifact_contract=" << finding << '\n';
        return false;
    }
    input->path = normalized;
    return Hash(input->path, &input->digest);
}
#if defined(RS2_REPORTING_RUNNER)
bool OwnClient(Input& input) {
    rs2fix::pe::Image image; std::wstring normalized; std::string error;
    if (!tool::RequireAbsolutePlainFile(input.path.c_str(),&normalized,&error) ||
        !rs2fix::pe::ReadPeImage(normalized.c_str(),&image,&error) || image.machine!=IMAGE_FILE_MACHINE_AMD64 ||
        !(image.characteristics&IMAGE_FILE_DLL) || !image.delayImports.empty() || image.exports.size()!=1) return false;
    const auto& symbol=image.exports[0];
    if (symbol.name!="FixtureSteamClientSignature" || !symbol.forwarder.empty()) return false;
    const auto* section=rs2fix::pe::FindSection(image,symbol.rva,sizeof(kFixtureSteamClientSignature));
    std::vector<std::uint8_t> signature;
    if (!section || !(section->characteristics&IMAGE_SCN_MEM_READ) ||
        (section->characteristics&(IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_DISCARDABLE)) ||
        !rs2fix::pe::ReadImageRva(image,symbol.rva,sizeof(kFixtureSteamClientSignature),&signature,&error) ||
        std::memcmp(signature.data(),kFixtureSteamClientSignature,sizeof(kFixtureSteamClientSignature))) return false;
    input.path=normalized;
    return Hash(normalized,&input.digest); // File-only qualification; never LoadLibrary in this runner.
}
#endif
bool Qualify(Inputs* inputs) {
    tool::GenuineManifest manifest{}; rs2fix::Sha256Digest manifestDigest{}; std::string error;
    wchar_t system[512]{}; DWORD code = 0; tool::FileEvidence evidence{};
    if (!rs2fix::BuildSystemX3AudioPath(system, std::size(system), &code) ||
        !tool::ReadGenuineManifest(inputs->manifest.c_str(), &manifest, &manifestDigest, &error) ||
        !tool::ReadFileEvidence(system, GetTickCount64() + 10000, &evidence, &error)) {
        std::cerr << "genuine_evidence_failed=" << error << '\n'; return false;
    }
    const auto* entry = tool::FindManifestEntry(manifest, evidence.sha256, tool::ManifestState::Qualified);
    if (!entry || !tool::MatchesGenuineManifestEntry(evidence, *entry, &error)) {
        std::cerr << "genuine_not_qualified=" << error << '\n'; return false;
    }
    const auto trust = tool::VerifyEmbeddedSignatureCacheOnly(system, tool::ProductionWinTrustOps());
    if (trust.verifyStatus != 0 || !trust.closeAttempted || trust.closeStatus != 0) return false;
#if defined(RS2_OBSERVER_RUNNER)
    rs2fix::pe::Image sdk; std::wstring normalized;
    if (!tool::RequireAbsolutePlainFile(inputs->sdk.path.c_str(), &normalized, &error) ||
        !rs2fix::pe::ReadPeImage(normalized.c_str(), &sdk, &error) || sdk.machine != IMAGE_FILE_MACHINE_AMD64 ||
        !(sdk.characteristics & IMAGE_FILE_DLL) || !sdk.delayImports.empty()) return false;
    bool ownFixture = false;
    for (const auto& symbol : sdk.exports) if (symbol.name == "FixtureSteamSignature" && symbol.forwarder.empty()) {
        std::vector<std::uint8_t> signature;
        ownFixture = rs2fix::pe::ReadImageRva(sdk, symbol.rva, sizeof(kFixtureSteamSignature), &signature, &error) &&
            !std::memcmp(signature.data(), kFixtureSteamSignature, sizeof(kFixtureSteamSignature));
    }
    inputs->sdk.path = normalized;
#if defined(RS2_REPORTING_RUNNER)
    bool namedPump=false;
    for (const auto& symbol:sdk.exports) if (symbol.name=="SteamGameServer_RunCallbacks" && symbol.forwarder.empty()) {
        const auto* section=rs2fix::pe::FindSection(sdk,symbol.rva,1);
        namedPump=section && (section->characteristics&IMAGE_SCN_MEM_EXECUTE) && !(section->characteristics&IMAGE_SCN_MEM_WRITE);
    }
    return ownFixture && namedPump && Hash(normalized,&inputs->sdk.digest) && OwnClient(inputs->client) &&
        Artifact(&inputs->host,tool::ArtifactKind::ReportingStartupFixture) &&
        Artifact(&inputs->bootstrap,tool::ArtifactKind::FixtureBootstrap) &&
        Artifact(&inputs->active,tool::ArtifactKind::FixtureCompanionReporting);
#else
    return ownFixture && Hash(normalized, &inputs->sdk.digest) &&
        Artifact(&inputs->host, tool::ArtifactKind::ObserverStartupFixture) &&
        Artifact(&inputs->bootstrap, tool::ArtifactKind::FixtureBootstrap) &&
        Artifact(&inputs->active, tool::ArtifactKind::FixtureCompanionObserver);
#endif
#else
    return Artifact(&inputs->host, tool::ArtifactKind::StartupFixture) &&
        Artifact(&inputs->bootstrap, tool::ArtifactKind::FixtureBootstrap) &&
        Artifact(&inputs->passive, tool::ArtifactKind::FixtureCompanionPassive) &&
        Artifact(&inputs->active, tool::ArtifactKind::FixtureCompanionActive) &&
        (inputs->production.path.empty() || Artifact(&inputs->production, tool::ArtifactKind::Bootstrap));
#endif
}
std::wstring Join(const std::wstring& directory, std::wstring_view leaf) {
    if (leaf.empty() || leaf.find_first_of(L"/\\\"") != leaf.npos) return {};
    return directory + L"\\" + std::wstring(leaf);
}
bool NewDirectory(const std::wstring& path) {
    std::wstring normalized; std::string error;
    return !path.empty() && CreateDirectoryW(path.c_str(), nullptr) &&
        tool::RequireAbsolutePlainDirectory(path.c_str(), &normalized, &error) && normalized == path;
}
bool Copy(const Input& input, const std::wstring& directory, const wchar_t* leaf) {
    const auto path = Join(directory, leaf); rs2fix::Sha256Digest copied{};
    return !path.empty() && CopyFileW(input.path.c_str(), path.c_str(), TRUE) && Hash(path, &copied) && copied == input.digest;
}
bool Read(const std::wstring& path, std::string* bytes, std::size_t maximum) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || static_cast<ULONGLONG>(size.QuadPart) > maximum) {
        CloseHandle(file); return false;
    }
    bytes->resize(static_cast<std::size_t>(size.QuadPart)); DWORD count = 0;
    const bool read = bytes->empty() || (ReadFile(file, bytes->data(), static_cast<DWORD>(bytes->size()), &count, nullptr) && count == bytes->size());
    return CloseHandle(file) && read;
}
bool BadFile(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    constexpr char data[] = "own-code-invalid-companion"; DWORD written = 0;
    const bool ok = WriteFile(file, data, sizeof(data), &written, nullptr) && written == sizeof(data) && FlushFileBuffers(file);
    return CloseHandle(file) && ok;
}
std::vector<wchar_t> Environment(const std::wstring& temporary) {
    LPWCH block = GetEnvironmentStringsW();
    if (!block) return {};
    std::vector<std::wstring> values;
    for (const wchar_t* value = block; *value; value += std::wcslen(value) + 1)
        if (_wcsnicmp(value, L"TEMP=", 5) != 0 && _wcsnicmp(value, L"TMP=", 4) != 0) values.emplace_back(value);
    FreeEnvironmentStringsW(block);
    values.emplace_back(L"TEMP=" + temporary); values.emplace_back(L"TMP=" + temporary);
    std::sort(values.begin(), values.end(), [](const auto& a, const auto& b) { return _wcsicmp(a.c_str(), b.c_str()) < 0; });
    std::vector<wchar_t> result;
    for (const auto& value : values) { result.insert(result.end(), value.begin(), value.end()); result.push_back(0); }
    result.push_back(0); return result;
}
Child Run(const std::wstring& directory, const std::wstring& temporary, const std::wstring& arguments, bool obstructMarker
#if defined(RS2_REPORTING_RUNNER)
    , DWORD childDeadline=20000, std::size_t maximumOutput=1024 * 1024
#endif
    ) {
    Child result{};
    auto environment = Environment(temporary);
    if (environment.empty()) return result;
    const auto outputPath = Join(directory, L"stdout-stderr.txt");
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE output = CreateFileW(outputPath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &security, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (output == INVALID_HANDLE_VALUE) { result.error = GetLastError(); return result; }
    HANDLE input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (input == INVALID_HANDLE_VALUE) { result.error = GetLastError(); CloseHandle(output); return result; }
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input; startup.StartupInfo.hStdOutput = output; startup.StartupInfo.hStdError = output;
    SIZE_T bytes = 0; InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    std::vector<BYTE> attributes(bytes);
    startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    HANDLE handles[]{input, output};
    bool initialized = InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes) != FALSE;
    if (!initialized || !UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            handles, sizeof(handles), nullptr, nullptr)) {
        result.error = GetLastError();
        if (initialized) DeleteProcThreadAttributeList(startup.lpAttributeList);
        CloseHandle(input); CloseHandle(output); return result;
    }
    const auto executable = Join(directory, L"fixture.exe");
    std::wstring command = L"\"" + executable + L"\" " + arguments;
    std::vector<wchar_t> mutableCommand(command.begin(), command.end()); mutableCommand.push_back(0);
    PROCESS_INFORMATION process{};
    const DWORD oldMode = GetErrorMode();
    SetErrorMode(oldMode | SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    const DWORD flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT |
        (obstructMarker ? CREATE_SUSPENDED : 0);
    result.created = CreateProcessW(executable.c_str(), mutableCommand.data(), nullptr, nullptr, TRUE,
        flags, environment.data(), directory.c_str(), &startup.StartupInfo, &process) != FALSE;
    result.error = result.created ? 0 : GetLastError();
    SetErrorMode(oldMode); DeleteProcThreadAttributeList(startup.lpAttributeList); CloseHandle(input);
    if (result.created) {
        result.pid = process.dwProcessId;
        if (obstructMarker) {
            // Suspension lets us occupy both PID-specific marker paths before
            // the fixture's CRT initializer can attempt its first marker write.
            const auto leaf = L"RS2ServerFix.loader." + std::to_wstring(result.pid) + L".log";
            if (!NewDirectory(Join(directory, leaf)) || !NewDirectory(Join(temporary, leaf)) ||
                ResumeThread(process.hThread) == MAXDWORD) {
                result.preparationFailed = true; result.error = GetLastError();
                TerminateProcess(process.hProcess, ERROR_INVALID_DATA);
            }
        }
        CloseHandle(process.hThread);
        DWORD waited = WaitForSingleObject(process.hProcess,
#if defined(RS2_REPORTING_RUNNER)
            childDeadline
#else
            20000
#endif
            );
        if (waited != WAIT_OBJECT_0) {
            result.timedOut = waited == WAIT_TIMEOUT;
            if (waited == WAIT_FAILED) result.error = GetLastError();
            TerminateProcess(process.hProcess, ERROR_TIMEOUT);
            waited = WaitForSingleObject(process.hProcess, 5000);
        }
        result.ended = waited == WAIT_OBJECT_0;
        if (result.ended) GetExitCodeProcess(process.hProcess, &result.status);
        CloseHandle(process.hProcess);
    }
    const bool closed = CloseHandle(output) != FALSE;
    result.captured = closed && Read(outputPath, &result.output,
#if defined(RS2_REPORTING_RUNNER)
        maximumOutput
#else
        1024 * 1024
#endif
        );
    return result;
}
bool Absent(const std::wstring& path) {
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return false;
    const DWORD error = GetLastError(); return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}
bool Marker(const Child& child, const std::wstring& directory, const Inputs& inputs, bool active) {
    const auto path = Join(directory, L"RS2ServerFix.loader." + std::to_wstring(child.pid) + L".log");
    std::string bytes;
    if (!Read(path, &bytes, 8192) || bytes.size() < 21 || bytes.substr(bytes.size() - 21) != "completion=complete\r\n") return false;
    std::map<std::string, std::string> fields;
    std::size_t begin = 0;
    while (begin < bytes.size()) {
        const auto end = bytes.find("\r\n", begin), equals = bytes.find('=', begin);
        if (end == bytes.npos || equals == bytes.npos || equals >= end ||
            !fields.emplace(bytes.substr(begin, equals - begin), bytes.substr(equals + 1, end - equals - 1)).second) return false;
        begin = end + 2;
    }
    return fields["schema"] == "3" && fields["version"] == ExpectedVersion(inputs) && fields["pid"] == std::to_string(child.pid) &&
        fields["sha256"] == rs2fix::FormatSha256Upper(inputs.host.digest).data() && fields["executable"] == "fixture.exe" &&
        fields["build_identity"] == "unknown" && fields["bootstrap_beside_executable"] == "true" &&
        fields["companion_beside_executable"] == "true" && fields["genuine_module"] == "system32" &&
        fields["genuine_initialize_present"] == "true" && fields["genuine_calculate_present"] == "true" &&
        fields["trigger"] == "exe-crt-initialize" && fields["mode"] == (active ? "active" : "passive") &&
        fields["fix"] == "recon-exclusive-scale-v1" && fields["qualification"] == "ready" &&
        fields["recon"] == (active ? "active" : "passive") && fields["reason"] == "none" && fields["initialize_result"] == "0";
}
bool StatusLine(const Inputs& inputs, const std::string& output, bool active, bool markerFailure, bool allowAbsent) {
    const std::string prefix = "[RS2ServerFix]";
    const auto at = output.find(prefix);
    if (at == output.npos) return allowAbsent;
    if (output.find(prefix, at + prefix.size()) != output.npos || (at != 0 && output[at - 1] != '\n')) return false;
    const auto end = output.find("\r\n", at);
    if (end == output.npos) return false;
    const std::string mode = active ? "active" : "passive";
    const std::string expected = "[RS2ServerFix] v" + ExpectedVersion(inputs) + " loaded; host=unknown; mode=" + mode +
        "; qualification=ready; recon=" + mode + "; fix=recon-exclusive-scale-v1; reason=none; marker=" +
        (markerFailure ? "failed; acceptance=failed" : "complete; acceptance=passed");
    return output.substr(at, end - at) == expected;
}
#if defined(RS2_OBSERVER_RUNNER)
bool CreateText(const std::wstring& path, std::string_view text) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written{};
    const bool ok = text.size() <= MAXDWORD && WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr) &&
        written == text.size() && FlushFileBuffers(file);
    return CloseHandle(file) && ok;
}
#if !defined(RS2_REPORTING_RUNNER)
bool StageObserver(const Inputs& inputs, const Scenario& scenario, const std::wstring& directory) {
    if (!Copy(inputs.sdk, directory, L"rs2_test_steam_api.dll")) return false;
    if (scenario.observerMode != 2) {
        const auto config = scenario.observerMode == 1 ? "enabled=0\r\n" : scenario.observerMode == 3 ?
            "enabled=1\nenabled=1\n" : "enabled=1\r\nmax_log_mib=16\r\n";
        if (!CreateText(Join(directory, L"RS2SteamObserve.ini"), config)) return false;
    }
    if (scenario.observerMode == 4) {
        // Change only a disposable OWN DLL's overlay. Its code/imports/exports
        // still run, but the qualified SDK disk hash must reject observation.
        HANDLE file = CreateFileW(Join(directory, L"rs2_test_steam_api.dll").c_str(), FILE_APPEND_DATA, 0,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        constexpr char changed[] = "own-fixture-unsupported-sdk-hash"; DWORD count{};
        const bool ok = WriteFile(file, changed, sizeof(changed), &count, nullptr) && count == sizeof(changed) && FlushFileBuffers(file);
        if (!CloseHandle(file) || !ok) return false;
    }
    if (scenario.observerMode == 5 && !CreateText(Join(directory, L"RS2SteamObserve"), "owned-obstruction")) return false;
    return true;
}
#endif
bool JsonUnsigned(const std::string& line, const char* name, std::uint64_t* value) {
    const std::string prefix = std::string("\"") + name + "\":";
    auto at = line.find(prefix);
    if (at == line.npos || line.find(prefix, at + prefix.size()) != line.npos) return false;
    at += prefix.size();
    if (at == line.size() || line[at] < '0' || line[at] > '9') return false;
    *value = 0;
    while (at < line.size() && line[at] >= '0' && line[at] <= '9') {
        const unsigned digit = line[at++] - '0';
        if (*value > (UINT64_MAX - digit) / 10) return false;
        *value = *value * 10 + digit;
    }
    return at < line.size() && (line[at] == ',' || line[at] == '}');
}
#if !defined(RS2_REPORTING_RUNNER)
bool ObserverEvidence(const Inputs& inputs, const Scenario& scenario, const Child& child, const std::wstring& directory) {
    if (child.output.find("steam_fixture=pass factory=2 init=1 shutdown=1 bad_arguments=0") == child.output.npos) return false;
    const bool enabled = scenario.observerMode == 0 && !scenario.markerFailure;
    const auto results = Join(directory, L"RS2SteamObserve"), keys = Join(directory, L"RS2SteamObserveKeys");
    const std::string prefix = "[RS2SteamObserve] v" + inputs.expectedVersion + "; status=";
    if (!enabled) {
        if (child.output.find(prefix + "disabled; reason=") == child.output.npos) return false;
        const char* reason = scenario.markerFailure ? "core_marker_failed" : scenario.observerMode == 1 ? "config_disabled" :
            scenario.observerMode == 2 ? "config_missing" : scenario.observerMode == 3 ? "config_invalid" :
            scenario.observerMode == 4 ? "sdk_identity_mismatch" :
            scenario.observerMode == 6 ? "sdk_binding_mismatch" : nullptr;
        if (reason && child.output.find(prefix + "disabled; reason=" + reason + "\r\n") == child.output.npos) return false;
        if (scenario.observerMode == 6 &&
            (child.output.find("steam_prehook=installed-before-audio preserved=true") == child.output.npos ||
             child.output.find("bad_arguments=0 factory_alias=2") == child.output.npos)) return false;
        return (scenario.observerMode == 5 || Absent(results)) && Absent(keys);
    }
    if (child.output.find(prefix + "armed;") == child.output.npos || child.output.find(prefix + "bound;") == child.output.npos ||
        child.output.find(prefix + "calls-observed;") == child.output.npos) return false;
    std::error_code error;
    std::filesystem::directory_iterator runs(results, error);
    if (error) return false;
    std::wstring runDirectory;
    for (const auto& run : runs) {
        if (!runDirectory.empty() || !run.is_directory(error) || error ||
            (GetFileAttributesW(run.path().c_str()) & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
        runDirectory = run.path().wstring();
    }
    if (runDirectory.empty()) return false;
    std::string bytes;
    if (!Read(Join(runDirectory, L"events.jsonl"), &bytes, 1024 * 1024) || bytes.empty() || bytes.back() != '\n') return false;
    // Never use a summary notice alone as evidence of actual intercepted calls.
    if (bytes.find("1234605616436508552") != bytes.npos || bytes.find("1122334455667788") != bytes.npos) return false;
    unsigned completed[47]{};
    bool startup = false, countersComplete = false;
    std::size_t start = 0;
    while (start < bytes.size()) {
        const auto end = bytes.find('\n', start);
        if (end == bytes.npos) return false;
        const auto line = bytes.substr(start, end - start);
        start = end + 1;
        if (line.find("\"type\":\"startup\"") != line.npos) {
            std::uint64_t pid{}, schema{};
            startup = JsonUnsigned(line, "pid", &pid) && pid == child.pid && JsonUnsigned(line, "schema", &schema) && schema == 1 &&
                line.find("\"version\":\"" + inputs.expectedVersion + "\"") != line.npos && line.find("\"armed\":true") != line.npos;
        } else if (line.find("\"type\":\"event\"") != line.npos) {
            std::uint64_t method{}, phase{}, result{};
            if (!JsonUnsigned(line, "method", &method) || method >= 47 || !JsonUnsigned(line, "phase", &phase)) return false;
            if (phase == 1) {
                ++completed[method];
                if ((method == 29 || method == 27 || method == 45) &&
                    (!JsonUnsigned(line, "result", &result) || result != (method == 29 ? 7u : 0u))) return false;
                if ((method == 27 || method == 29 || method == 30) && line.find("\"steam_token\":\"") == line.npos) return false;
            }
        } else if (line.find("\"type\":\"anchor\"") != line.npos) {
            bool exact = line.find("\"bindings_published\":1,") != line.npos;
            constexpr unsigned observed[]{6, 8, 12, 20, 27, 29, 30, 39, 40, 44, 45, 46};
            for (const auto method : observed) {
                const unsigned expected = method == 8 || method == 44 ? 2u : 1u;
                const auto tuple = "{\"method\":" + std::to_string(method) + ",\"entered\":" + std::to_string(expected) +
                    ",\"completed\":" + std::to_string(expected) + "}";
                exact = line.find(tuple) != line.npos && exact;
            }
            countersComplete = exact || countersComplete;
        }
    }
    // Queue contention may legitimately lose individual records even in a small
    // fixture. Require exact loss-independent counters AND real virtual-call
    // records, not an impossible promise that every queued record survives.
    unsigned virtualCompletions = 0;
    for (unsigned method = 0; method < 44; ++method) virtualCompletions += completed[method];
    return startup && countersComplete && virtualCompletions != 0;
}
#endif
#endif
#if defined(RS2_REPORTING_RUNNER)
#include "steam_reporting_startup_runner_checks.h"
#endif
bool Execute(const Inputs& inputs, const std::wstring& root, const Scenario& scenario) {
    const auto directory = Join(root, scenario.name), temporary = Join(directory, L"temp");
    if (!NewDirectory(directory) || !NewDirectory(temporary) || !Copy(inputs.host, directory, L"fixture.exe")) return false;
    std::wstring dllDirectory = directory;
    if (scenario.dynamic) { dllDirectory = Join(directory, L"dynamic"); if (!NewDirectory(dllDirectory)) return false; }
    const auto& bootstrap = scenario.production ? inputs.production : inputs.bootstrap;
    if (!Copy(bootstrap, dllDirectory, L"X3DAudio1_7.dll")) return false;
    const auto& companion = scenario.active ? inputs.active : inputs.passive;
    if (scenario.late) { if (!Copy(companion, directory, L"pending-companion.dll")) return false; }
    else if (scenario.invalid) { if (!BadFile(Join(dllDirectory, L"RS2ServerFix.dll"))) return false; }
    else if (!scenario.missing && !Copy(companion, dllDirectory, L"RS2ServerFix.dll")) return false;
#if defined(RS2_REPORTING_RUNNER)
    if (!StageReporting(inputs,scenario,directory)) return false;
#elif defined(RS2_OBSERVER_RUNNER)
    if (!StageObserver(inputs, scenario, directory)) return false;
#endif
    const bool corrected = scenario.active && scenario.companion;
    std::wstring arguments = scenario.options;
    arguments += corrected ? L" --expect-corrected" : L" --expect-original";
    if (scenario.companion) arguments += L" --expect-companion";
    if (scenario.immediate) arguments += L" --immediate-exit";
    const Child child = Run(directory, temporary, arguments, scenario.markerFailure
#if defined(RS2_REPORTING_RUNNER)
        // The fixed-count calibration intentionally takes over five minutes.
        // Allow 15 minutes, below the enclosing CTest deadline, so Run can
        // terminate and reap a stuck owned child. Ordinary limits stay intact.
        , scenario.reportMode==13 ? 900000 : 20000,
          scenario.reportMode==13 ? 16 * 1024 * 1024 : 1024 * 1024
#endif
        );
    bool ok = child.created && child.ended && !child.timedOut && !child.preparationFailed && child.captured && child.status == 0;
    const std::string observed = std::string("fixture_state=2 selector=") + (corrected ? "2" : "3") +
        " companion=" + (scenario.companion ? "present" : "absent") + " before_main=true marker_before_main=" +
        (scenario.companion && !scenario.markerFailure ? "true" : "false") + " calls=" + std::to_string(scenario.calls) +
        " dynamic_restored=" + (scenario.dynamic ? "true" : "false");
    const auto at = child.output.find(observed);
    ok = at != child.output.npos && child.output.find("fixture_state=", at + observed.size()) == child.output.npos && ok;
    const auto markerLeaf = L"RS2ServerFix.loader." + std::to_wstring(child.pid) + L".log";
    if (scenario.markerFailure) {
        for (const auto& base : {directory, temporary}) {
            const DWORD attributes = GetFileAttributesW(Join(base, markerLeaf).c_str());
            ok = attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) && ok;
        }
        ok = StatusLine(inputs, child.output, scenario.active, true, false) && ok;
    } else if (scenario.companion) {
        ok = Marker(child, directory, inputs, scenario.active) && Absent(Join(temporary, markerLeaf)) &&
            StatusLine(inputs, child.output, scenario.active, false, scenario.immediate) && ok;
    } else {
        ok = Absent(Join(directory, markerLeaf)) && Absent(Join(temporary, markerLeaf)) &&
            child.output.find("[RS2ServerFix]") == child.output.npos && ok;
    }
    rs2fix::Sha256Digest after{};
    ok = Hash(Join(directory, L"fixture.exe"), &after) && after == inputs.host.digest && ok;
#if defined(RS2_REPORTING_RUNNER)
    const bool reportingOk=ReportingEvidence(inputs,scenario,child,directory);
    ok=reportingOk && Hash(inputs.sdk.path,&after) && after==inputs.sdk.digest &&
        Hash(inputs.client.path,&after) && after==inputs.client.digest && ok;
    if (!reportingOk) std::cerr << "reporting_evidence=fail\n";
    if (ok && scenario.reportMode==13) ok=WriteTimingFixture(inputs,root,child);
#elif defined(RS2_OBSERVER_RUNNER)
    const bool observerOk = ObserverEvidence(inputs, scenario, child, directory);
    ok = observerOk && Hash(inputs.sdk.path, &after) && after == inputs.sdk.digest && ok;
    if (!observerOk) std::cerr << "observer_evidence=fail\n";
#endif
    if (!scenario.immediate || !ok) {
        std::wcout << L"case=" << scenario.name << L" pid=" << child.pid << L" exit=" << child.status
            << L" timeout=" << child.timedOut << L" result=" << (ok ? L"pass" : L"fail") << L'\n';
        if (!ok) std::cerr << child.output;
    }
    return ok;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"--help") { Usage(); return 0; }
    Inputs inputs{};
    if (!Parse(argc, argv, &inputs)) { Usage(); return 2; }
    if (!Qualify(&inputs)) return 1;
    std::array<wchar_t, rs2fix::kPathCapacity> buffer{}; std::wstring temporary; std::string error;
    const DWORD count = GetTempPathW(static_cast<DWORD>(buffer.size()), buffer.data());
    if (!count || count >= buffer.size() || !tool::RequireAbsolutePlainDirectory(buffer.data(), &temporary, &error)) return 1;
    const auto root = Join(temporary, L"RS2ServerFix.startup." + std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(GetTickCount64()));
    if (!NewDirectory(root) || !tool::IsPathWithin(temporary, root, false)) return 1;
    std::wcout << L"startup_evidence=" << root << std::endl;
#if defined(RS2_REPORTING_RUNNER)
    bool all=true;
    if (inputs.calibrationOnly) {
        Scenario calibration{L"report-calibration",L"--report-timing-fixture",true,true};
        calibration.reportMode=13;
        all=Execute(inputs,root,calibration);
    } else {
    const wchar_t* names[]{L"report-observe",L"report-repair",L"report-missing-config",L"report-disabled",
        L"report-invalid-config",L"report-prerequisite-disabled",L"report-wrong-sdk",L"report-blocked-writer",
        L"report-client-missing",L"report-wrong-client",L"report-init-false",L"report-core-marker-failed",
        L"report-preexisting-sdk-hook"};
    for (unsigned mode=0;mode<std::size(names);++mode) {
        const wchar_t* options=mode==1 ? L"--report-false-first-full" : mode==8 ? L"--report-client-missing" :
            mode==10 ? L"--report-init-false" : mode==12 ? L"--prehook-steam-factory" : L"";
        Scenario scenario{names[mode],options,true,true};
        scenario.reportMode=mode; scenario.markerFailure=mode==11;
        all=Execute(inputs,root,scenario) && all;
    }
    }
#elif defined(RS2_OBSERVER_RUNNER)
    bool all = true;
    const wchar_t* names[]{L"observer-enabled", L"observer-disabled", L"observer-missing-config", L"observer-invalid-config",
        L"observer-unsupported-sdk", L"observer-blocked-writer", L"observer-preexisting-sdk-hook"};
    for (unsigned mode = 0; mode < std::size(names); ++mode) {
        Scenario scenario{names[mode], mode == 6 ? L"--prehook-steam-factory" : L"", true, true}; scenario.observerMode = mode;
        all = Execute(inputs, root, scenario) && all;
    }
    Scenario markerFailure{L"observer-core-marker-failed", L"", true, true, true};
    all = Execute(inputs, root, markerFailure) && all;
#else
    const Scenario scenarios[]{
        {L"01-passive", L"", false, true},
        {L"02-active", L"", true, true},
        {L"03-wrong-stage", L"--wrong-stage", true, false},
        {L"04-wrong-thread", L"--wrong-thread", true, false},
        {L"05-wrong-return", L"--wrong-return", true, false},
        {L"06-prior-unrelated", L"--prior-unrelated", true, true, false, false, false, false, false, false, false, 2},
        {L"07-duplicate", L"--duplicate", true, true, false, false, false, false, false, false, false, 2},
        {L"08-missing-companion", L"", true, false, false, true},
        {L"09-invalid-companion", L"", true, false, false, false, true},
        {L"10-no-late-retry", L"--late-companion", true, false, false, false, false, true, false, false, false, 2},
        {L"11-active-marker-failed", L"", true, true, true},
        {L"12-dynamic-attach", L"--dynamic-load", true, false, false, false, false, false, true},
    };
    bool all = true;
    for (const auto& scenario : scenarios) all = Execute(inputs, root, scenario) && all;
    if (!inputs.production.path.empty()) {
        Scenario production{L"13-production-rejects-fixture", L"", true, false}; production.production = true;
        all = Execute(inputs, root, production) && all;
    }
    unsigned exitsPassed = 0;
    for (unsigned i = 0; i < 128; ++i) {
        wchar_t name[80]{}; swprintf_s(name, L"immediate-exit-%03u", i);
        Scenario early{name, L"", i % 2 != 0, true}; early.immediate = true;
        const bool passed = Execute(inputs, root, early);
        if (passed) ++exitsPassed;
        all = passed && all;
    }
    std::cout << "immediate_exit_passed=" << exitsPassed << "/128 result=" << (all ? "pass" : "fail") << '\n';
#endif
    std::wcout << L"retained_startup_evidence=" << root << std::endl;
    return all ? 0 : 1;
}
