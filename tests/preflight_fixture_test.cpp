#include "deployment_preflight.h"
#include "companion/sha256.h"
#include "test_framework.h"
#include <Windows.h>
#include <winioctl.h>
#include <algorithm>
#include <cstring>
#include <functional>
#include <iostream>
#include <vector>

namespace {
using namespace rs2fix;
using namespace rs2fix::tooling;
std::wstring g_workspace;
unsigned g_case = 0;
bool WriteFileNew(const std::wstring& path, const std::string& data) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written{}; const bool ok = WriteFile(file, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) && written == data.size();
    CloseHandle(file); return ok;
}
std::string ReadText(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > 64 * 1024 * 1024) { CloseHandle(file); return {}; }
    std::string text(static_cast<std::size_t>(size.QuadPart), '\0'); DWORD n{};
    const bool ok = ReadFile(file, text.data(), static_cast<DWORD>(text.size()), &n, nullptr) && n == text.size();
    CloseHandle(file); return ok ? text : std::string{};
}
bool RemoveOwnTree(const std::wstring& path) {
    if (path.size() <= g_workspace.size() || path.compare(0, g_workspace.size(), g_workspace) != 0 || path[g_workspace.size()] != L'\\') return false;
    WIN32_FIND_DATAW data{}; HANDLE find = FindFirstFileW((path + L"\\*").c_str(), &data);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (std::wcscmp(data.cFileName, L".") == 0 || std::wcscmp(data.cFileName, L"..") == 0) continue;
            const auto child = path + L"\\" + data.cFileName;
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) RemoveDirectoryW(child.c_str()); else RemoveOwnTree(child);
            } else DeleteFileW(child.c_str());
        } while (FindNextFileW(find, &data));
        FindClose(find);
    }
    return RemoveDirectoryW(path.c_str()) != FALSE;
}
bool RunHelp(const std::wstring& scanner, const std::wstring& arguments, DWORD wanted) {
    const auto output = g_workspace + L"\\help-" + std::to_wstring(++g_case) + L".txt";
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE file = CreateFileW(output.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &security, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    std::wstring command = L"\"" + scanner + L"\" " + arguments;
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = file; startup.hStdError = file;
    startup.hStdInput = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr);
    PROCESS_INFORMATION process{};
    const bool created = CreateProcessW(scanner.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, g_workspace.c_str(), &startup, &process) != FALSE;
    CloseHandle(file); if (startup.hStdInput != INVALID_HANDLE_VALUE) CloseHandle(startup.hStdInput);
    if (!created) return false;
    CloseHandle(process.hThread);
    const DWORD wait = WaitForSingleObject(process.hProcess, 20000); DWORD code{};
    if (wait == WAIT_TIMEOUT) { TerminateProcess(process.hProcess, ERROR_TIMEOUT); WaitForSingleObject(process.hProcess, 5000); }
    const bool exited = GetExitCodeProcess(process.hProcess, &code) != FALSE; CloseHandle(process.hProcess);
    const auto text = ReadText(output); DeleteFileW(output.c_str());
    if (wanted == 0) for (const auto* part : { "--target-root", "--bootstrap-sha256", "--companion-sha256", "--genuine-manifest", "--report", "--mode", "--av-edr-disposition", "--wdac-disposition", "--applocker-disposition", "--eac-disposition", "not-observed-yet", "blocked" }) RS2_CHECK(text.find(part) != text.npos);
    return exited && wait == WAIT_OBJECT_0 && code == wanted;
}
struct Inject {
    KnownDllState known{KnownDllState::Absent}; bool badSignature{}, changeIdentity{}, shortWrite{}, flushFailure{}, closeFailure{};
    std::wstring identityPath; std::size_t identityCalls{};
};
bool Identity(void* opaque, const wchar_t* path, FileIdentity* identity, DWORD* error) noexcept {
    auto& injected = *static_cast<Inject*>(opaque);
    const bool ok = QueryFileIdentity(path, identity, error);
    if (ok && injected.changeIdentity && EqualEvidencePath(path, injected.identityPath) && ++injected.identityCalls == 2) ++identity->fileIndexLow;
    return ok;
}
EmbeddedSignatureResult Signature(void* opaque, const wchar_t* path) noexcept {
    if (static_cast<Inject*>(opaque)->badSignature) return {TRUST_E_NOSIGNATURE, ERROR_SUCCESS, true};
    return VerifyEmbeddedSignatureCacheOnly(path, ProductionWinTrustOps());
}
KnownDllState Known(void* opaque, const wchar_t*, DWORD* error) noexcept { *error = ERROR_SUCCESS; return static_cast<Inject*>(opaque)->known; }
HANDLE CreateReport(void*, const wchar_t* path, DWORD* error) noexcept { const auto& ops = ProductionEvidenceFileOps(); return ops.createNew(ops.context, path, error); }
bool WriteReport(void* opaque, HANDLE file, const void* data, DWORD size, DWORD* written, DWORD* error) noexcept {
    const auto& ops = ProductionEvidenceFileOps();
    if (static_cast<Inject*>(opaque)->shortWrite) { *written = 0; *error = ERROR_WRITE_FAULT; return false; }
    return ops.write(ops.context, file, data, size, written, error);
}
bool FlushReport(void* opaque, HANDLE file, DWORD* error) noexcept {
    if (static_cast<Inject*>(opaque)->flushFailure) { *error = ERROR_WRITE_FAULT; return false; }
    const auto& ops = ProductionEvidenceFileOps(); return ops.flush(ops.context, file, error);
}
bool CloseReport(void* opaque, HANDLE file, DWORD* error) noexcept {
    const auto& ops = ProductionEvidenceFileOps(); const bool ok = ops.close(ops.context, file, error);
    if (static_cast<Inject*>(opaque)->closeFailure) { *error = ERROR_WRITE_FAULT; return false; } return ok;
}
bool RemoveReport(void*, const wchar_t* path, DWORD* error) noexcept { const auto& ops = ProductionEvidenceFileOps(); return ops.remove(ops.context, path, error); }
PreflightOps Ops(Inject& injected) {
    return {&injected, Identity, Signature, Known, {&injected, CreateReport, WriteReport, FlushReport, CloseReport, RemoveReport}};
}
bool MutateMachine(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    IMAGE_DOS_HEADER dos{}; DWORD read{};
    bool ok = ReadFile(file, &dos, sizeof(dos), &read, nullptr) && read == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE;
    LARGE_INTEGER position{}; position.QuadPart = static_cast<LONGLONG>(dos.e_lfanew) + sizeof(DWORD);
    WORD machine = IMAGE_FILE_MACHINE_I386;
    ok = ok && SetFilePointerEx(file, position, nullptr, FILE_BEGIN) && WriteFile(file, &machine, sizeof(machine), &read, nullptr) && read == sizeof(machine);
    CloseHandle(file); return ok;
}
bool CreateOwnReparse(const std::wstring& path, bool directory) {
    // A third-party GUID reparse tag needs no symlink privilege and exercises
    // the same unconditional no-reparse rule without a target or a filesystem filter.
    if (directory ? !CreateDirectoryW(path.c_str(), nullptr) : !WriteFileNew(path, "own-reparse-fixture")) return false;
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    struct ReparseGuidHeader { DWORD tag; WORD length; WORD reserved; GUID guid; };
    const ReparseGuidHeader data{0x00000042, 0, 0,
        {0x3c83a849, 0x1364, 0x4aaf, {0xa8,0x7c,0x93,0xbe,0x79,0x8b,0xbc,0x11}}};
    DWORD returned{};
    const bool ok = DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT,
        const_cast<ReparseGuidHeader*>(&data), sizeof(data), nullptr, 0, &returned, nullptr) != FALSE;
    CloseHandle(handle); return ok;
}
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 6) { std::cerr << "usage: preflight-fixture <scanner> <stock-exe> <bootstrap> <companion> <manifest>\n"; return 2; }
    wchar_t temp[kPathCapacity]{}; const DWORD n = GetTempPathW(static_cast<DWORD>(std::size(temp)), temp);
    RS2_CHECK(n != 0 && n < std::size(temp)); if (!n || n >= std::size(temp)) return 1;
    g_workspace = std::wstring(temp) + L"RS2ServerFix.preflight." + std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(GetTickCount64());
    RS2_CHECK(CreateDirectoryW(g_workspace.c_str(), nullptr) != FALSE);
    RS2_CHECK(RunHelp(argv[1], L"--help", 0));
    const auto sentinel = g_workspace + L"\\sentinel.txt";
    RS2_CHECK(RunHelp(argv[1], L"--help --report \"" + sentinel + L"\"", 2));
    RS2_CHECK(GetFileAttributesW(sentinel.c_str()) == INVALID_FILE_ATTRIBUTES);
    const auto bootstrap = HashFileSha256(argv[3], GetTickCount64() + 10000), companion = HashFileSha256(argv[4], GetTickCount64() + 10000);
    RS2_CHECK(bootstrap.digestValid && companion.digestValid);
    auto run = [&](const char* name, int expected, const char* finding,
                   const std::function<void(PreflightInputs&, Inject&, const std::wstring&)>& modify) {
        const auto root = g_workspace + L"\\case-" + std::to_wstring(++g_case);
        RS2_CHECK(CreateDirectoryW(root.c_str(), nullptr) != FALSE);
        const auto host = root + L"\\VNGame-current-stock.exe";
        RS2_CHECK(CopyFileW(argv[2], host.c_str(), TRUE) != FALSE);
        PreflightInputs in; in.targetRoot = root; in.bootstrapPath = argv[3]; in.companionPath = argv[4]; in.genuineManifestPath = argv[5];
        in.bootstrapSha256 = bootstrap.digest; in.companionSha256 = companion.digest; in.reportPath = g_workspace + L"\\report-" + std::to_wstring(g_case) + L".txt";
        Inject injected; modify(in, injected, host);
        std::string diagnostic; const int code = RunDeploymentPreflight(in, Ops(injected), &diagnostic);
        if (code != expected) std::cerr << "case=" << name << " actual=" << code << " diagnostic=" << diagnostic << '\n';
        RS2_CHECK(code == expected);
        const auto report = ReadText(in.reportPath);
        if (finding && report.find(finding) == report.npos) std::cerr << "case=" << name << " missing=" << finding << '\n' << report;
        if (finding) RS2_CHECK(report.find(finding) != report.npos);
        if (code == 0) { RS2_CHECK(report.size() >= 13 && report.substr(report.size() - 13) == "result=pass\r\n"); RS2_CHECK(report.find("x3audio_importer_count=1\r\n") != report.npos); }
        RS2_CHECK(report.find("D:\\") == report.npos && report.find("C:\\") == report.npos);
        if (injected.shortWrite || injected.flushFailure || injected.closeFailure) RS2_CHECK(GetFileAttributesW(in.reportPath.c_str()) == INVALID_FILE_ATTRIBUTES);
        if (in.genuineManifestPath != argv[5] && in.genuineManifestPath.compare(0, g_workspace.size(), g_workspace) == 0) DeleteFileW(in.genuineManifestPath.c_str());
        DeleteFileW(in.reportPath.c_str()); RS2_CHECK(RemoveOwnTree(root));
    };
    auto none = [](PreflightInputs&, Inject&, const std::wstring&) {};
    run("positive", 0, "result=pass", none);
    run("active-stock", 1, "active-requires-current-full-dump", [](auto& in, auto&, const auto&) { in.mode = DeploymentMode::Active; });
    run("bootstrap-hash", 1, "artifact-contract-hash", [](auto& in, auto&, const auto&) { ++in.bootstrapSha256[0]; });
    run("companion-hash", 1, "artifact-contract-hash", [](auto& in, auto&, const auto&) { ++in.companionSha256[0]; });
    run("bootstrap-contract", 1, "artifact-contract-hash", [](auto& in, auto&, const auto&) { in.bootstrapPath = in.companionPath; in.bootstrapSha256 = in.companionSha256; });
    run("companion-contract", 1, "artifact-contract-hash", [](auto& in, auto&, const auto&) { in.companionPath = in.bootstrapPath; in.companionSha256 = in.bootstrapSha256; });
    run("manifest-provisional", 1, "genuine-qualification-trust", [](auto& in, auto&, const auto&) {
        auto bytes = ReadText(in.genuineManifestPath); const auto state = bytes.find("state=qualified\r\n"); RS2_CHECK(state != bytes.npos);
        if (state != bytes.npos) bytes.replace(state, std::strlen("state=qualified"), "state=provisional");
        in.genuineManifestPath = g_workspace + L"\\provisional.manifest"; RS2_CHECK(WriteFileNew(in.genuineManifestPath, bytes));
    });
    run("manifest-invalid", 1, "manifest-invalid", [](auto& in, auto&, const auto&) {
        in.genuineManifestPath = g_workspace + L"\\malformed.manifest"; RS2_CHECK(WriteFileNew(in.genuineManifestPath, "schema=1\n"));
    });
    run("target-machine", 1, "non-amd64-x3audio-importer", [](auto&, auto&, const auto& host) { RS2_CHECK(MutateMachine(host)); });
    run("duplicate-host", 1, "expected-one-current-target", [](auto& in, auto&, const auto& host) { RS2_CHECK(CopyFileW(host.c_str(), (in.targetRoot + L"\\second.exe").c_str(), TRUE) != FALSE); });
    run("missing-host", 1, "expected-one-current-target", [](auto&, auto&, const auto& host) { RS2_CHECK(DeleteFileW(host.c_str()) != FALSE); });
    run("malformed", 1, "malformed-pe", [](auto& in, auto&, const auto&) { RS2_CHECK(WriteFileNew(in.targetRoot + L"\\broken.dll", "MZ malformed")); });
    run("redirection", 1, "executable-local-redirection", [](auto& in, auto&, const auto&) { RS2_CHECK(CreateDirectoryW((in.targetRoot + L"\\VNGame.exe.local").c_str(), nullptr) != FALSE); });
    run("faultrep", 1, "forbidden-faultrep", [](auto& in, auto&, const auto&) { RS2_CHECK(WriteFileNew(in.targetRoot + L"\\faultrep.dll", "MZ")); });
    run("existing-proxy", 1, "pre-existing-x3audio", [](auto& in, auto&, const auto&) { RS2_CHECK(CopyFileW(in.bootstrapPath.c_str(), (in.targetRoot + L"\\X3DAudio1_7.dll").c_str(), TRUE) != FALSE); });
    run("renamed-proxy", 1, "renamed-local-proxy-artifact", [](auto& in, auto&, const auto&) { RS2_CHECK(CopyFileW(in.bootstrapPath.c_str(), (in.targetRoot + L"\\renamed.dll").c_str(), TRUE) != FALSE); });
    run("proxy-basename", 1, "unapproved-proxy-basename", [](auto& in, auto&, const auto&) { RS2_CHECK(WriteFileNew(in.targetRoot + L"\\version.dll", "MZ")); });
    run("security-alert", 1, "operator-security-rejection", [](auto& in, auto&, const auto&) { in.avEdr = SecurityDisposition::Alerted; });
    run("security-block", 1, "operator-security-rejection", [](auto& in, auto&, const auto&) { in.eac = SecurityDisposition::Blocked; });
    run("known-present", 1, "known-dll-present", [](auto&, auto& injected, const auto&) { injected.known = KnownDllState::Present; });
    run("known-failed", 1, "known-dll-present-or-query-failed", [](auto&, auto& injected, const auto&) { injected.known = KnownDllState::QueryFailed; });
    run("signature", 1, "genuine-qualification-trust", [](auto&, auto& injected, const auto&) { injected.badSignature = true; });
    run("identity", 1, "file-identity-changed", [](auto&, auto& injected, const auto& host) { injected.changeIdentity = true; injected.identityPath = host; });
    run("short-report", 1, nullptr, [](auto&, auto& injected, const auto&) { injected.shortWrite = true; });
    run("flush-report", 1, nullptr, [](auto&, auto& injected, const auto&) { injected.flushFailure = true; });
    run("close-report", 1, nullptr, [](auto&, auto& injected, const auto&) { injected.closeFailure = true; });
    run("relative-path", 2, nullptr, [](auto& in, auto&, const auto&) { in.targetRoot = L"relative"; });
    run("report-in-root", 2, nullptr, [](auto& in, auto&, const auto&) { in.reportPath = in.targetRoot + L"\\report.txt"; });
    run("report-exists", 2, "sentinel", [](auto& in, auto&, const auto&) { RS2_CHECK(WriteFileNew(in.reportPath, "sentinel")); });
    run("file-reparse", 1, "reparse-entry-not-scanned", [](auto& in, auto&, const auto&) { RS2_CHECK(CreateOwnReparse(in.targetRoot + L"\\reparse.dll", false)); });
    run("directory-reparse", 1, "reparse-entry-not-scanned", [](auto& in, auto&, const auto&) { RS2_CHECK(CreateOwnReparse(in.targetRoot + L"\\reparse-directory", true)); });
    const auto& production = ProductionPreflightOps(); DWORD error{};
    RS2_CHECK(production.queryKnownDllState(production.context, L"X3DAudio1_7.dll", &error) == KnownDllState::Absent);
    RS2_CHECK(EncodeEvidencePath(L"private name/\u00E9.dll") == "private%20name/%C3%A9.dll");
    RS2_CHECK(RemoveDirectoryW(g_workspace.c_str()) != FALSE);
    std::cout << "checks=" << rs2fix::test::g_checks << " failures=" << rs2fix::test::g_failures << '\n';
    return rs2fix::test::g_failures == 0 ? 0 : 1;
}
