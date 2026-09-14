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

namespace {
namespace tool = rs2fix::tooling;
struct Input { std::wstring path; rs2fix::Sha256Digest digest{}; };
struct Inputs { Input host, bootstrap, passive, active, production; std::wstring manifest; };
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
};
void Usage() {
    std::cout << "rs2_startup_runner --host <absolute-file> --bootstrap <absolute-file>\n"
        "  --passive <absolute-file> --active <absolute-file> --genuine-manifest <absolute-file>\n"
        "  [--production-bootstrap <absolute-file>]\nSole --help performs no process or file work.\n";
}
bool Parse(int argc, wchar_t** argv, Inputs* inputs) {
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
    return Artifact(&inputs->host, tool::ArtifactKind::StartupFixture) &&
        Artifact(&inputs->bootstrap, tool::ArtifactKind::FixtureBootstrap) &&
        Artifact(&inputs->passive, tool::ArtifactKind::FixtureCompanionPassive) &&
        Artifact(&inputs->active, tool::ArtifactKind::FixtureCompanionActive) &&
        (inputs->production.path.empty() || Artifact(&inputs->production, tool::ArtifactKind::Bootstrap));
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
Child Run(const std::wstring& directory, const std::wstring& temporary, const std::wstring& arguments, bool obstructMarker) {
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
            const auto leaf = L"RS2ServerFix.loader." + std::to_wstring(result.pid) + L".log";
            if (!NewDirectory(Join(directory, leaf)) || !NewDirectory(Join(temporary, leaf)) ||
                ResumeThread(process.hThread) == MAXDWORD) {
                result.preparationFailed = true; result.error = GetLastError();
                TerminateProcess(process.hProcess, ERROR_INVALID_DATA);
            }
        }
        CloseHandle(process.hThread);
        DWORD waited = WaitForSingleObject(process.hProcess, 20000);
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
    result.captured = closed && Read(outputPath, &result.output, 1024 * 1024);
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
    return fields["schema"] == "3" && fields["version"] == RS2FIX_VERSION_ASCII && fields["pid"] == std::to_string(child.pid) &&
        fields["sha256"] == rs2fix::FormatSha256Upper(inputs.host.digest).data() && fields["executable"] == "fixture.exe" &&
        fields["build_identity"] == "unknown" && fields["bootstrap_beside_executable"] == "true" &&
        fields["companion_beside_executable"] == "true" && fields["genuine_module"] == "system32" &&
        fields["genuine_initialize_present"] == "true" && fields["genuine_calculate_present"] == "true" &&
        fields["trigger"] == "exe-crt-initialize" && fields["mode"] == (active ? "active" : "passive") &&
        fields["fix"] == "recon-exclusive-scale-v1" && fields["qualification"] == "ready" &&
        fields["recon"] == (active ? "active" : "passive") && fields["reason"] == "none" && fields["initialize_result"] == "0";
}
bool StatusLine(const std::string& output, bool active, bool markerFailure, bool allowAbsent) {
    const std::string prefix = "[RS2ServerFix]";
    const auto at = output.find(prefix);
    if (at == output.npos) return allowAbsent;
    if (output.find(prefix, at + prefix.size()) != output.npos || (at != 0 && output[at - 1] != '\n')) return false;
    const auto end = output.find("\r\n", at);
    if (end == output.npos) return false;
    const std::string mode = active ? "active" : "passive";
    const std::string expected = "[RS2ServerFix] v" RS2FIX_VERSION_ASCII " loaded; host=unknown; mode=" + mode +
        "; qualification=ready; recon=" + mode + "; fix=recon-exclusive-scale-v1; reason=none; marker=" +
        (markerFailure ? "failed; acceptance=failed" : "complete; acceptance=passed");
    return output.substr(at, end - at) == expected;
}
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
    const bool corrected = scenario.active && scenario.companion;
    std::wstring arguments = scenario.options;
    arguments += corrected ? L" --expect-corrected" : L" --expect-original";
    if (scenario.companion) arguments += L" --expect-companion";
    if (scenario.immediate) arguments += L" --immediate-exit";
    const Child child = Run(directory, temporary, arguments, scenario.markerFailure);
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
        ok = StatusLine(child.output, scenario.active, true, false) && ok;
    } else if (scenario.companion) {
        ok = Marker(child, directory, inputs, scenario.active) && Absent(Join(temporary, markerLeaf)) &&
            StatusLine(child.output, scenario.active, false, scenario.immediate) && ok;
    } else {
        ok = Absent(Join(directory, markerLeaf)) && Absent(Join(temporary, markerLeaf)) &&
            child.output.find("[RS2ServerFix]") == child.output.npos && ok;
    }
    rs2fix::Sha256Digest after{};
    ok = Hash(Join(directory, L"fixture.exe"), &after) && after == inputs.host.digest && ok;
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
    std::wcout << L"retained_startup_evidence=" << root << std::endl;
    return all ? 0 : 1;
}
