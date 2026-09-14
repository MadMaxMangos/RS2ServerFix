#include "shared/path_identity.h"
#include "companion/sha256.h"
#include "file_evidence.h"
#include "genuine_manifest.h"
#include "pe_contract_lib.h"
#include "tool_paths.h"
#include <Windows.h>
#include <array>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {
namespace tool = rs2fix::tooling;
constexpr DWORD kTimeout = 20000;
constexpr std::size_t kOutputLimit = 1024 * 1024;
struct Input { std::wstring path; rs2fix::Sha256Digest digest{}; };
struct Inputs { Input harness, bootstrap, missing, companion; std::wstring manifest; };
struct ProcessResult {
    bool created{}, timedOut{}, captured{}, ended{};
    DWORD createError{}, exitCode{STILL_ACTIVE}, pid{};
    std::string output;
};
void Usage() {
    std::cout << "rs2_static_import_runner --harness <absolute-file> --bootstrap <absolute-file>\n"
        "  --missing-genuine-bootstrap <absolute-file> --companion <absolute-file>\n"
        "  --genuine-manifest <absolute-file>\nSole --help performs no file or process work.\n";
}
bool Parse(int argc, wchar_t** argv, Inputs* inputs) {
    if (argc != 11) return false;
    for (int i = 1; i < argc; i += 2) {
        const std::wstring_view name(argv[i]), value(argv[i + 1]);
        std::wstring* target = name == L"--harness" ? &inputs->harness.path :
            name == L"--bootstrap" ? &inputs->bootstrap.path : name == L"--missing-genuine-bootstrap" ? &inputs->missing.path :
            name == L"--companion" ? &inputs->companion.path : name == L"--genuine-manifest" ? &inputs->manifest : nullptr;
        if (target == nullptr || !target->empty() || !tool::IsAbsoluteToolPath(value.data())) return false;
        *target = value;
    }
    return !inputs->harness.path.empty() && !inputs->bootstrap.path.empty() && !inputs->missing.path.empty() &&
        !inputs->companion.path.empty() && !inputs->manifest.empty();
}
bool FileHash(const std::wstring& path, rs2fix::Sha256Digest* digest) {
    const auto result = rs2fix::HashFileSha256(path.c_str(), GetTickCount64() + 10000);
    if (!result.digestValid || result.timedOut) return false;
    *digest = result.digest; return true;
}
bool Contract(Input* input, tool::ArtifactKind kind) {
    std::wstring normalized; std::string error; tool::ContractReport report{};
    if (!tool::RequireAbsolutePlainFile(input->path.c_str(), &normalized, &error)) {
        std::cerr << "input_path_failed=" << error << '\n'; return false;
    }
    input->path = normalized;
    if (!tool::CheckArtifactContract(input->path.c_str(), kind, &report)) {
        for (const auto& finding : report.findings) std::cerr << "artifact_contract=" << finding << '\n';
        return false;
    }
    return FileHash(input->path, &input->digest);
}
std::wstring Parent(const std::wstring& path) { return path.substr(0, path.find_last_of(L"\\/")); }
std::wstring Leaf(const std::wstring& path) { return path.substr(path.find_last_of(L"\\/") + 1); }
bool Qualify(Inputs* inputs) {
    std::string error; std::wstring manifestPath;
    if (!tool::RequireAbsolutePlainFile(inputs->manifest.c_str(), &manifestPath, &error)) {
        std::cerr << "manifest_path_failed=" << error << '\n'; return false;
    }
    inputs->manifest = manifestPath;
    tool::GenuineManifest manifest{}; rs2fix::Sha256Digest manifestHash{};
    if (!tool::ReadGenuineManifest(manifestPath.c_str(), &manifest, &manifestHash, &error)) {
        std::cerr << "manifest_failed=" << error << '\n'; return false;
    }
    wchar_t system[512]{}; DWORD systemError = 0; tool::FileEvidence evidence{};
    if (!rs2fix::BuildSystemX3AudioPath(system, std::size(system), &systemError) ||
        !tool::ReadFileEvidence(system, GetTickCount64() + 10000, &evidence, &error)) {
        std::cerr << "system_evidence_failed=" << error << " win32=" << systemError << '\n'; return false;
    }
    const auto* entry = tool::FindManifestEntry(manifest, evidence.sha256, tool::ManifestState::Qualified);
    if (entry == nullptr || !tool::MatchesGenuineManifestEntry(evidence, *entry, &error)) {
        std::cerr << "genuine_not_qualified=" << error << '\n'; return false;
    }
    const auto trust = tool::VerifyEmbeddedSignatureCacheOnly(system, tool::ProductionWinTrustOps());
    if (trust.verifyStatus != ERROR_SUCCESS || !trust.closeAttempted || trust.closeStatus != ERROR_SUCCESS) {
        std::cerr << "genuine_signature_failed=" << trust.verifyStatus << " close=" << trust.closeStatus << '\n'; return false;
    }
    if (!Contract(&inputs->harness, tool::ArtifactKind::Harness) ||
        !Contract(&inputs->bootstrap, tool::ArtifactKind::Bootstrap) ||
        !Contract(&inputs->missing, tool::ArtifactKind::MissingGenuineBootstrap) ||
        !Contract(&inputs->companion, tool::ArtifactKind::CompanionPassive)) return false;
    const auto configuration = Leaf(Parent(inputs->missing.path));
    const auto missingRoot = Leaf(Parent(Parent(inputs->missing.path)));
    std::array<wchar_t, rs2fix::kPathCapacity> own{}; DWORD errorCode = 0;
    if (!rs2fix::GetBoundedModulePath(nullptr, own.data(), own.size(), &errorCode)) return false;
    const auto ownConfiguration = Leaf(Parent(own.data()));
    if ((configuration != L"Debug" && configuration != L"Release") || configuration != ownConfiguration ||
        missingRoot != L"test-invalid-genuine" || inputs->missing.digest == inputs->bootstrap.digest) {
        std::cerr << "missing_genuine_artifact_isolation_failed\n"; return false;
    }
    const auto hash = rs2fix::FormatSha256Upper(evidence.sha256);
    std::cout << "qualified_system_sha256=" << hash.data() << '\n';
    return true;
}
std::wstring Join(const std::wstring& directory, std::wstring_view leaf) {
    if (leaf.empty() || leaf.find_first_of(L"\\/\"") != leaf.npos) return {};
    return directory + L"\\" + std::wstring(leaf);
}
bool PlainDirectory(const std::wstring& path) {
    std::wstring normalized; std::string error;
    return tool::RequireAbsolutePlainDirectory(path.c_str(), &normalized, &error) && normalized == path;
}
bool NewDirectory(const std::wstring& path) { return !path.empty() && CreateDirectoryW(path.c_str(), nullptr) && PlainDirectory(path); }
bool Copy(const Input& input, const std::wstring& directory, const wchar_t* leaf) {
    const auto path = Join(directory, leaf);
    rs2fix::Sha256Digest hash{};
    return !path.empty() && CopyFileW(input.path.c_str(), path.c_str(), TRUE) && FileHash(path, &hash) && hash == input.digest;
}
bool Malformed(const std::wstring& path) {
    constexpr char bytes[] = "not a portable executable";
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const bool ok = WriteFile(file, bytes, sizeof(bytes), &written, nullptr) && written == sizeof(bytes) && FlushFileBuffers(file);
    return CloseHandle(file) && ok;
}
bool Capture(const std::wstring& path, std::string* output) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > kOutputLimit) { CloseHandle(file); return false; }
    output->resize(static_cast<std::size_t>(size.QuadPart));
    DWORD count = 0;
    const bool ok = output->empty() || (ReadFile(file, output->data(), static_cast<DWORD>(output->size()), &count, nullptr) && count == output->size());
    return CloseHandle(file) && ok;
}
ProcessResult Run(const std::wstring& executable, const std::wstring& directory,
    const std::wstring& arguments, const wchar_t* captureLeaf) {
    ProcessResult result{};
    const auto outputPath = Join(directory, captureLeaf);
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE output = CreateFileW(outputPath.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &security, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (output == INVALID_HANDLE_VALUE) { result.createError = GetLastError(); return result; }
    HANDLE input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (input == INVALID_HANDLE_VALUE) { result.createError = GetLastError(); CloseHandle(output); return result; }
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input;
    startup.StartupInfo.hStdOutput = output; startup.StartupInfo.hStdError = output;
    SIZE_T attributeBytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeBytes);
    std::vector<BYTE> attributes(attributeBytes);
    startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    HANDLE inherited[] = {input, output};
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attributeBytes)) {
        result.createError = GetLastError(); CloseHandle(input); CloseHandle(output); return result;
    }
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        inherited, sizeof(inherited), nullptr, nullptr)) {
        result.createError = GetLastError(); DeleteProcThreadAttributeList(startup.lpAttributeList);
        CloseHandle(input); CloseHandle(output); return result;
    }
    std::wstring command = L"\"" + executable + L"\" " + arguments;
    std::vector<wchar_t> mutableCommand(command.begin(), command.end()); mutableCommand.push_back(0);
    PROCESS_INFORMATION process{};
    // This dedicated own-code test runner controls inherited loader UI for its children.
    const UINT savedMode = GetErrorMode();
    SetErrorMode(savedMode | SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    result.created = CreateProcessW(executable.c_str(), mutableCommand.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, directory.c_str(), &startup.StartupInfo, &process) != FALSE;
    result.createError = result.created ? ERROR_SUCCESS : GetLastError();
    SetErrorMode(savedMode);
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    CloseHandle(input);
    if (result.created) {
        result.pid = process.dwProcessId; CloseHandle(process.hThread);
        DWORD waited = WaitForSingleObject(process.hProcess, kTimeout);
        if (waited != WAIT_OBJECT_0) {
            result.timedOut = waited == WAIT_TIMEOUT;
            if (waited == WAIT_FAILED) result.createError = GetLastError();
            TerminateProcess(process.hProcess, ERROR_TIMEOUT);
            waited = WaitForSingleObject(process.hProcess, 5000);
        }
        result.ended = waited == WAIT_OBJECT_0;
        if (result.ended) GetExitCodeProcess(process.hProcess, &result.exitCode);
        CloseHandle(process.hProcess);
    }
    const bool closed = CloseHandle(output) != FALSE;
    result.captured = closed && Capture(outputPath, &result.output);
    return result;
}
bool NoReport(const ProcessResult& result, const std::wstring& directory, const std::wstring& temporary) {
    if (result.output.find("[RS2ServerFix]") != std::string::npos) return false;
    if (result.pid == 0) return true;
    const auto leaf = L"RS2ServerFix.loader." + std::to_wstring(result.pid) + L".log";
    for (const auto& base : {directory, temporary}) {
        const auto path = Join(base, leaf);
        if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return false;
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) return false;
    }
    return true;
}
bool Digest(const ProcessResult& result, rs2fix::Sha256Digest* digest) {
    constexpr std::string_view prefix = "digest_sha256=";
    const auto at = result.output.find(prefix);
    if (at == std::string::npos || (at != 0 && result.output[at - 1] != '\n') ||
        result.output.find(prefix, at + prefix.size()) != std::string::npos) return false;
    const auto end = result.output.find('\n', at);
    if (end == std::string::npos) return false;
    auto text = std::string_view(result.output).substr(at + prefix.size(), end - at - prefix.size());
    if (!text.empty() && text.back() == '\r') text.remove_suffix(1);
    return rs2fix::ParseSha256Upper(text, digest);
}
bool Healthy(const ProcessResult& result) {
    return result.created && result.ended && !result.timedOut && result.captured && result.exitCode == 0 && result.createError == 0;
}
bool Report(const char* name, const ProcessResult& result, bool passed) {
    std::cout << "case=" << name << " created=" << result.created << " timeout=" << result.timedOut
        << " exit=" << result.exitCode << " create_error=" << result.createError << " result=" << (passed ? "pass" : "fail") << '\n';
    if (!passed) std::cerr << result.output;
    return passed;
}
bool ValidRoot(const std::wstring& temporary, const std::wstring& root, const wchar_t* prefix) {
    return Parent(root) == temporary && Leaf(root).find(prefix) == 0 && PlainDirectory(root);
}
bool RemoveContents(const std::wstring& root, const std::wstring& directory) {
    if (!tool::IsPathWithin(root, directory, true) || !PlainDirectory(directory)) return false;
    WIN32_FIND_DATAW data{}; HANDLE search = FindFirstFileW((directory + L"\\*").c_str(), &data);
    if (search == INVALID_HANDLE_VALUE) return false;
    bool ok = true;
    do {
        if (std::wcscmp(data.cFileName, L".") == 0 || std::wcscmp(data.cFileName, L"..") == 0) continue;
        const auto path = Join(directory, data.cFileName);
        if (path.empty() || !tool::IsPathWithin(root, path, false) || (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) { ok = false; break; }
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ok = RemoveContents(root, path) && RemoveDirectoryW(path.c_str());
        else ok = DeleteFileW(path.c_str()) != FALSE;
        if (!ok) break;
    } while (FindNextFileW(search, &data));
    if (ok && GetLastError() != ERROR_NO_MORE_FILES) ok = false;
    FindClose(search); return ok;
}
bool HelpChecks(const Inputs& inputs, const std::wstring& temporary) {
    const auto root = Join(temporary, L"RS2ServerFix.help." + std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(GetTickCount64()));
    if (!NewDirectory(root) || !Copy(inputs.harness, root, L"harness.exe")) return false;
    std::array<wchar_t, rs2fix::kPathCapacity> own{}; DWORD error = 0;
    if (!rs2fix::GetBoundedModulePath(nullptr, own.data(), own.size(), &error)) return false;
    const auto sentinel = Join(root, L"never-created.exe");
    const auto runnerHelp = Run(own.data(), root, L"--help", L"runner-help.txt");
    const auto runnerBad = Run(own.data(), root, L"--help --harness \"" + sentinel + L"\"", L"runner-help-invalid.txt");
    const auto harnessHelp = Run(Join(root, L"harness.exe"), root, L"--help", L"harness-help.txt");
    const auto harnessBad = Run(Join(root, L"harness.exe"), root, L"--help --expect-marker complete", L"harness-help-invalid.txt");
    bool ok = Healthy(runnerHelp) && Healthy(harnessHelp) && runnerBad.created && runnerBad.ended &&
        !runnerBad.timedOut && runnerBad.exitCode == 2 && runnerBad.captured && harnessBad.created && harnessBad.ended &&
        !harnessBad.timedOut && harnessBad.exitCode == 2 && harnessBad.captured;
    for (const auto& result : {runnerHelp, runnerBad, harnessHelp, harnessBad})
        ok = NoReport(result, root, temporary) && result.output.find("digest_sha256=") == std::string::npos && ok;
    for (const char* token : {"--harness", "--bootstrap", "--missing-genuine-bootstrap", "--companion", "--genuine-manifest"})
        ok = runnerHelp.output.find(token) != std::string::npos && ok;
    for (const char* token : {"vector", "concurrent", "fail-initialize", "fail-calculate", "immediate-exit", "system-only", "proxy-and-system", "absent"})
        ok = harnessHelp.output.find(token) != std::string::npos && ok;
    ok = GetFileAttributesW(sentinel.c_str()) == INVALID_FILE_ATTRIBUTES && ok;
    std::cout << "help_contract=" << (ok ? "pass" : "fail") << '\n';
    if (!ok) { std::wcerr << L"retained_help_evidence=" << root << '\n'; return false; }
    return ValidRoot(temporary, root, L"RS2ServerFix.help.") && RemoveContents(root, root) && RemoveDirectoryW(root.c_str());
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"--help") { Usage(); return 0; }
    Inputs inputs{};
    if (!Parse(argc, argv, &inputs)) { Usage(); return 2; }
    if (!Qualify(&inputs)) return 1;
    std::array<wchar_t, rs2fix::kPathCapacity> buffer{};
    const DWORD length = GetTempPathW(static_cast<DWORD>(buffer.size()), buffer.data());
    std::wstring temporary; std::string error;
    if (length == 0 || length >= buffer.size() || !tool::RequireAbsolutePlainDirectory(buffer.data(), &temporary, &error)) return 1;
    if (!HelpChecks(inputs, temporary)) return 1;
    const auto root = Join(temporary, L"RS2ServerFix.static." + std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(GetTickCount64()));
    if (!NewDirectory(root) || !ValidRoot(temporary, root, L"RS2ServerFix.static.")) return 1;
    const wchar_t* names[] = {L"01-system-control", L"02-companion-only", L"03-bootstrap-only", L"04-both",
        L"05-invalid-companion", L"06-missing-genuine", L"07-concurrent-first-calls", L"08-invalid-bootstrap", L"09-rollback"};
    rs2fix::Sha256Digest reference{}; bool all = true;
    for (unsigned i = 0; i < std::size(names); ++i) {
        const auto directory = i == 8 ? Join(root, names[3]) : Join(root, names[i]);
        bool prepared = i == 8 || (NewDirectory(directory) && Copy(inputs.harness, directory, L"harness.exe"));
        if (i == 1 || i == 3 || i == 6) prepared = prepared && Copy(inputs.companion, directory, L"RS2ServerFix.dll");
        if (i == 2 || i == 3 || i == 4 || i == 6) prepared = prepared && Copy(inputs.bootstrap, directory, L"X3DAudio1_7.dll");
        if (i == 4) prepared = prepared && Malformed(Join(directory, L"RS2ServerFix.dll"));
        if (i == 5) prepared = prepared && Copy(inputs.missing, directory, L"X3DAudio1_7.dll");
        if (i == 7) prepared = prepared && Malformed(Join(directory, L"X3DAudio1_7.dll"));
        if (i == 8) prepared = prepared && DeleteFileW(Join(directory, L"X3DAudio1_7.dll").c_str()) &&
            DeleteFileW(Join(directory, L"RS2ServerFix.dll").c_str());
        if (!prepared) { std::wcerr << L"case_prepare_failed=" << names[i] << '\n'; all = false; break; }
        const auto executable = Join(directory, L"harness.exe");
        if (i == 5) {
            for (const wchar_t* mode : {L"fail-initialize", L"fail-calculate"}) {
                const auto result = Run(executable, directory, std::wstring(L"--mode ") + mode,
                    mode == std::wstring_view(L"fail-initialize") ? L"initialize.txt" : L"calculate.txt");
                const bool pass = result.created && result.ended && !result.timedOut && result.captured &&
                    result.exitCode == 0xC0000602UL && NoReport(result, directory, temporary) && result.output.find("digest_sha256=") == std::string::npos;
                all = Report(mode == std::wstring_view(L"fail-initialize") ? "06-missing-genuine-initialize" : "06-missing-genuine-calculate", result, pass) && all;
            }
            continue;
        }
        const bool system = i == 0 || i == 1 || i == 8;
        std::wstring arguments = i == 6 ? L"--mode concurrent" : L"--mode vector";
        arguments += system ? L" --expect-modules system-only" : L" --expect-modules proxy-and-system";
        arguments += L" --expect-marker absent";
        const auto result = Run(executable, directory, arguments, i == 8 ? L"rollback-output.txt" : L"output.txt");
        bool pass = false; rs2fix::Sha256Digest digest{};
        if (i == 7) {
            const bool createReject = !result.created && (result.createError == ERROR_BAD_EXE_FORMAT ||
                result.createError == ERROR_MOD_NOT_FOUND || result.createError == ERROR_PROC_NOT_FOUND || result.createError == ERROR_DLL_INIT_FAILED);
            pass = !result.timedOut && result.captured && (createReject || (result.created && result.ended && (result.exitCode & 0x80000000u))) &&
                result.output.find("digest_sha256=") == std::string::npos && NoReport(result, directory, temporary);
        } else {
            pass = Healthy(result) && Digest(result, &digest) && NoReport(result, directory, temporary);
            if (i == 0 && pass) reference = digest;
            else pass = pass && digest == reference;
        }
        std::string narrow;
        for (const wchar_t* letter = names[i]; *letter != 0; ++letter)
            narrow.push_back(static_cast<char>(*letter)); // fixed ASCII case literals
        all = Report(narrow.c_str(), result, pass) && all;
        if (!result.ended && result.created) break;
    }
    if (!all) { std::wcerr << L"retained_case_evidence=" << root << '\n'; return 1; }
    const auto hex = rs2fix::FormatSha256Upper(reference);
    std::cout << "reference_digest_sha256=" << hex.data() << "\ncases=9 result=pass\n";
    if (!ValidRoot(temporary, root, L"RS2ServerFix.static.") || !RemoveContents(root, root) || !RemoveDirectoryW(root.c_str())) return 1;
    return 0;
}
