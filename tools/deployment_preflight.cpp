#include "deployment_preflight.h"
#include "pe_contract_lib.h"
#include "tool_paths.h"
#include "companion/build_identity.h"
#include "companion/sha256.h"
#include <TlHelp32.h>
#include <algorithm>
#include <array>
#include <climits>
#include <cwchar>
#include <iostream>
#include <map>
#include <sstream>

namespace rs2fix::tooling {
bool EqualEvidencePath(std::wstring_view a, std::wstring_view b) noexcept {
    return a.size() <= INT_MAX && b.size() <= INT_MAX && CompareStringOrdinal(a.data(),
        static_cast<int>(a.size()), b.data(), static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}
std::wstring EvidenceLeaf(std::wstring_view path) {
    const auto pos = path.find_last_of(L"\\/");
    return std::wstring(pos == path.npos ? path : path.substr(pos + 1));
}
std::string EncodeEvidenceText(std::string_view bytes) {
    constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : bytes) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '/' || c == '-') out.push_back(static_cast<char>(c));
        else { out.push_back('%'); out.push_back(hex[c >> 4]); out.push_back(hex[c & 15]); }
    }
    return out;
}
std::string EncodeEvidencePath(std::wstring_view path) {
    if (path.empty()) return {};
    if (path.size() > INT_MAX) return "invalid-unicode-path";
    std::wstring slash(path); std::replace(slash.begin(), slash.end(), L'\\', L'/');
    const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, slash.data(), static_cast<int>(slash.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return "invalid-unicode-path";
    std::string utf8(static_cast<std::size_t>(n), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, slash.data(), static_cast<int>(slash.size()), utf8.data(), n, nullptr, nullptr) != n) return "invalid-unicode-path";
    return EncodeEvidenceText(utf8);
}
const char* DeploymentModeName(DeploymentMode mode) noexcept { return mode == DeploymentMode::Passive ? "passive" : "active"; }
bool ParseDeploymentMode(std::wstring_view text, DeploymentMode* mode) noexcept {
    if (text == L"passive") { *mode = DeploymentMode::Passive; return true; }
    if (text == L"active") { *mode = DeploymentMode::Active; return true; }
    return false;
}
bool IsX3AudioImport(std::string_view name) noexcept {
    constexpr std::string_view wanted = "x3daudio1_7.dll";
    if (name.size() != wanted.size()) return false;
    for (std::size_t i = 0; i < name.size(); ++i) {
        const char c = name[i] >= 'A' && name[i] <= 'Z' ? static_cast<char>(name[i] + 32) : name[i];
        if (c != wanted[i]) return false;
    }
    return true;
}
bool HasRequiredHostImports(const pe::Image& image) noexcept {
    std::size_t count = 0;
    for (const auto& module : image.normalImports) if (IsX3AudioImport(module.name)) {
        ++count;
        if (module.symbols.size() != 1 || module.symbols[0].byOrdinal || module.symbols[0].name != "X3DAudioInitialize") return false;
    }
    for (const auto& module : image.delayImports) if (IsX3AudioImport(module.name)) return false;
    return count == 1;
}
namespace {
constexpr std::size_t kMaxEvents = 262144, kMaxEntries = 65536, kMaxReport = 64U * 1024U * 1024U;
struct ReadGuard {
    HANDLE handle{INVALID_HANDLE_VALUE};
    BY_HANDLE_FILE_INFORMATION before{};
    ~ReadGuard() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
    bool Open(const std::wstring& path, bool directory) {
        handle = CreateFileW(path.c_str(), directory ? FILE_READ_ATTRIBUTES : GENERIC_READ,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr);
        return handle != INVALID_HANDLE_VALUE && GetFileInformationByHandle(handle, &before) &&
            (before.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
            ((before.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == directory;
    }
    bool Unchanged() const {
        BY_HANDLE_FILE_INFORMATION after{};
        return GetFileInformationByHandle(handle, &after) && before.dwVolumeSerialNumber == after.dwVolumeSerialNumber &&
            before.nFileIndexHigh == after.nFileIndexHigh && before.nFileIndexLow == after.nFileIndexLow &&
            before.nFileSizeHigh == after.nFileSizeHigh && before.nFileSizeLow == after.nFileSizeLow &&
            CompareFileTime(&before.ftLastWriteTime, &after.ftLastWriteTime) == 0;
    }
};
const char* SecurityName(SecurityDisposition s) noexcept {
    constexpr const char* names[] = { "not-observed-yet", "not-installed", "not-enforced", "allowed", "alerted", "blocked" };
    const auto index = static_cast<unsigned>(s);
    return index < std::size(names) ? names[index] : "invalid";
}
[[maybe_unused]] bool ParseSecurity(std::wstring_view s, SecurityDisposition* value) {
    constexpr const wchar_t* names[] = { L"not-observed-yet", L"not-installed", L"not-enforced", L"allowed", L"alerted", L"blocked" };
    for (unsigned i = 0; i < std::size(names); ++i) if (s == names[i]) { *value = static_cast<SecurityDisposition>(i); return true; }
    return false;
}
bool QueryIdentity(void*, const wchar_t* path, FileIdentity* id, DWORD* error) noexcept { return QueryFileIdentity(path, id, error); }
EmbeddedSignatureResult VerifySignature(void*, const wchar_t* path) noexcept { return VerifyEmbeddedSignatureCacheOnly(path, ProductionWinTrustOps()); }
KnownDllState QueryKnownDll(void*, const wchar_t* leaf, DWORD* error) noexcept {
    HKEY key{};
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
    if (status != ERROR_SUCCESS) { *error = static_cast<DWORD>(status); return KnownDllState::QueryFailed; }
    KnownDllState result = KnownDllState::QueryFailed;
    for (DWORD i = 0; i < 4096; ++i) {
        wchar_t name[16384]{}, data[16384]{};
        DWORD n = static_cast<DWORD>(std::size(name)), length = sizeof(data), type{};
        status = RegEnumValueW(key, i, name, &n, nullptr, &type, reinterpret_cast<BYTE*>(data), &length);
        if (status == ERROR_NO_MORE_ITEMS) { result = KnownDllState::Absent; break; }
        if (status != ERROR_SUCCESS || n >= std::size(name) || length > sizeof(data)) break;
        const auto namesLeaf = [](std::wstring_view value, const wchar_t* wanted) noexcept {
            const auto slash = value.find_last_of(L"\\/");
            return EqualEvidencePath(slash == value.npos ? value : value.substr(slash + 1), wanted);
        };
        if (namesLeaf(std::wstring_view(name, n), leaf)) { result = KnownDllState::Present; break; }
        if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
            if (length % sizeof(wchar_t) != 0 || length < sizeof(wchar_t) || data[length / sizeof(wchar_t) - 1] != L'\0') { status = ERROR_INVALID_DATA; break; }
            std::size_t start = 0;
            for (std::size_t j = 0; j < length / sizeof(wchar_t); ++j) if (data[j] == L'\0') {
                if (namesLeaf(std::wstring_view(data + start, j - start), leaf)) result = KnownDllState::Present;
                start = j + 1;
            }
            if (result == KnownDllState::Present) break;
        } else { status = ERROR_INVALID_DATA; break; }
    }
    const LSTATUS closed = RegCloseKey(key);
    if (closed != ERROR_SUCCESS) { *error = static_cast<DWORD>(closed); return KnownDllState::QueryFailed; }
    *error = result == KnownDllState::QueryFailed ? (status == ERROR_SUCCESS ? ERROR_BUFFER_OVERFLOW : static_cast<DWORD>(status)) : ERROR_SUCCESS;
    return result;
}
struct Scan {
    const PreflightInputs& inputs;
    const PreflightOps& ops;
    std::vector<std::string> events;
    std::vector<std::wstring> executableLeaves;
    std::size_t entries{}, peFiles{}, importers{}, selected{}, unsafe{}, bytes{};
    bool incomplete{};
    std::wstring target;
    BuildIdentity identity{BuildIdentity::Unknown};
    void Event(const char* kind, std::wstring_view path, std::uint16_t machine, std::string_view detail, bool bad = false) {
        const auto encodedPath = EncodeEvidencePath(path);
        if (encodedPath == "invalid-unicode-path") { bad = true; kind = "UNSAFE"; detail = "unrepresentable-path"; }
        if (bad) ++unsafe;
        std::string line = std::string(kind) + "|" + encodedPath + "|" +
            (machine == IMAGE_FILE_MACHINE_AMD64 ? "AMD64" : std::to_string(machine)) + "|" + EncodeEvidenceText(detail);
        if (events.size() + 1 >= kMaxEvents || line.size() + bytes >= kMaxReport - 16384) { incomplete = true; ++unsafe; return; }
        bytes += line.size() + 32; events.push_back(std::move(line));
    }
};
bool Suffix(std::wstring_view value, std::wstring_view suffix) { return value.size() >= suffix.size() && EqualEvidencePath(value.substr(value.size() - suffix.size()), suffix); }
void ScanFile(const std::wstring& path, const std::wstring& relative, Scan& scan) {
    DWORD code{}; FileIdentity before{}, after{}; std::wstring normalized; std::string error; pe::Image image;
    ReadGuard guard;
    if (!RequireAbsolutePlainFile(path.c_str(), &normalized, &error) || !guard.Open(normalized, false) || !scan.ops.queryFileIdentity(scan.ops.context, path.c_str(), &before, &code) || !before.valid) { scan.Event("UNSAFE", relative, 0, "file-unreadable", true); return; }
    if (!pe::ReadPeImage(normalized.c_str(), &image, &error)) { scan.Event("UNSAFE", relative, 0, "malformed-pe:" + error, true); return; }
    ++scan.peFiles; scan.Event("PE", relative, image.machine, "parsed");
    bool calculateExport = false, initializeExport = false, companionExport = false;
    for (const auto& symbol : image.exports) {
        calculateExport |= symbol.name == "X3DAudioCalculate";
        initializeExport |= symbol.name == "X3DAudioInitialize";
        companionExport |= symbol.name == "RS2ServerFix_InitializeV3";
    }
    if ((calculateExport && initializeExport && !EqualEvidencePath(EvidenceLeaf(relative), L"X3DAudio1_7.dll")) ||
        (companionExport && !EqualEvidencePath(EvidenceLeaf(relative), L"RS2ServerFix.dll")))
        scan.Event("UNSAFE", relative, image.machine, "renamed-local-proxy-artifact", true);
    bool imports = false;
    auto inspect = [&](const auto& modules, const char* kind) {
        for (const auto& module : modules) if (IsX3AudioImport(module.name)) {
            imports = true;
            if (module.symbols.empty()) scan.Event("UNSAFE", relative, image.machine, "empty-x3audio-import", true);
            for (const auto& symbol : module.symbols) {
                scan.Event("IMPORT", relative, image.machine, std::string(kind) + ":X3DAudio1_7.dll!" + (symbol.byOrdinal ? "#" + std::to_string(symbol.ordinal) : symbol.name));
                if (symbol.byOrdinal ? (symbol.ordinal != 1 && symbol.ordinal != 2) : (symbol.name != "X3DAudioCalculate" && symbol.name != "X3DAudioInitialize")) scan.Event("UNSAFE", relative, image.machine, "unexpected-x3audio-symbol", true);
            }
        }
    };
    inspect(image.normalImports, "normal"); inspect(image.delayImports, "delay");
    if (imports) { ++scan.importers; if (image.machine != IMAGE_FILE_MACHINE_AMD64) scan.Event("UNSAFE", relative, image.machine, "non-amd64-x3audio-importer", true); }
    if (Suffix(relative, L".exe")) {
        scan.executableLeaves.push_back(EvidenceLeaf(relative));
        const auto hash = HashFileSha256(path.c_str(), GetTickCount64() + 10000);
        const auto identity = ClassifyBuild(hash.digest, hash.digestValid);
        if (!hash.digestValid) scan.Event("UNSAFE", relative, image.machine, "executable-hash-failed", true);
        if (identity == BuildIdentity::CurrentStock || identity == BuildIdentity::CurrentFullDump) {
            ++scan.selected; scan.target = relative; scan.identity = identity;
            if (image.machine != IMAGE_FILE_MACHINE_AMD64 || image.optionalMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || image.tlsDirectoryRva != 0 || image.tlsDirectorySize != 0 || !HasRequiredHostImports(image)) scan.Event("UNSAFE", relative, image.machine, "target-startup-contract-failed", true);
            if (scan.inputs.mode == DeploymentMode::Active && identity != BuildIdentity::CurrentFullDump) scan.Event("UNSAFE", relative, image.machine, "active-requires-current-full-dump", true);
        }
    }
    if (!guard.Unchanged() || !scan.ops.queryFileIdentity(scan.ops.context, path.c_str(), &after, &code) || !SameFileIdentity(before, after)) scan.Event("UNSAFE", relative, image.machine, "file-identity-changed", true);
}
void ScanDirectory(const std::wstring& directory, const std::wstring& relative, std::size_t depth, Scan& scan) {
    if (depth >= 128 || scan.incomplete) { scan.incomplete = true; return; }
    std::wstring normalized; std::string error;
    ReadGuard guard;
    if (!RequireAbsolutePlainDirectory(directory.c_str(), &normalized, &error) || !IsPathWithin(scan.inputs.targetRoot, normalized, true) || !guard.Open(normalized, true)) { scan.Event("UNSAFE", relative, 0, "directory-not-plain-or-escaped", true); return; }
    WIN32_FIND_DATAW item{}; HANDLE find = FindFirstFileW((directory + L"\\*").c_str(), &item);
    if (find == INVALID_HANDLE_VALUE) { if (GetLastError() != ERROR_FILE_NOT_FOUND) scan.Event("UNSAFE", relative, 0, "enumeration-failed", true); return; }
    std::vector<WIN32_FIND_DATAW> entries;
    do {
        if (std::wcscmp(item.cFileName, L".") == 0 || std::wcscmp(item.cFileName, L"..") == 0) continue;
        if (++scan.entries >= kMaxEntries) { scan.incomplete = true; break; }
        entries.push_back(item);
    } while (FindNextFileW(find, &item));
    const DWORD lastError = GetLastError(); FindClose(find);
    if (!scan.incomplete && lastError != ERROR_NO_MORE_FILES) scan.Event("UNSAFE", relative, 0, "enumeration-incomplete", true);
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
        const int result = CompareStringOrdinal(a.cFileName, -1, b.cFileName, -1, TRUE);
        return result == CSTR_EQUAL ? std::wcscmp(a.cFileName, b.cFileName) < 0 : result == CSTR_LESS_THAN;
    });
    for (const auto& entry : entries) {
        if (scan.incomplete) return;
        const std::wstring leaf = entry.cFileName, child = directory + L"\\" + leaf;
        const std::wstring rel = relative.empty() ? leaf : relative + L"/" + leaf;
        if (child.size() >= kPathCapacity || !IsPathWithin(scan.inputs.targetRoot, child, false)) { scan.Event("UNSAFE", rel, 0, "path-escaped-or-overflow", true); continue; }
        if (Suffix(leaf, L".exe.local")) scan.Event("UNSAFE", rel, 0, "executable-local-redirection", true);
        if (EqualEvidencePath(leaf, L"faultrep.dll")) scan.Event("UNSAFE", rel, 0, "forbidden-faultrep", true);
        if (EqualEvidencePath(leaf, L"X3DAudio1_7.dll")) scan.Event("UNSAFE", rel, 0, "pre-existing-x3audio", true);
        constexpr const wchar_t* proxies[] = { L"version.dll", L"winmm.dll", L"winhttp.dll", L"dinput8.dll", L"dxgi.dll", L"dsound.dll", L"RS2ServerFix.dll" };
        for (const auto* proxy : proxies) if (EqualEvidencePath(leaf, proxy)) scan.Event("UNSAFE", rel, 0, "unapproved-proxy-basename", true);
        if ((entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) { scan.Event("UNSAFE", rel, 0, "reparse-entry-not-scanned", true); continue; }
        if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) ScanDirectory(child, rel, depth + 1, scan);
        else if (Suffix(leaf, L".exe") || Suffix(leaf, L".dll")) ScanFile(child, rel, scan);
    }
    if (!guard.Unchanged()) scan.Event("UNSAFE", relative, 0, "directory-changed-during-scan", true);
}
void CheckStopped(Scan& scan) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) { scan.Event("UNSAFE", L".", 0, "stopped-query-failed", true); return; }
    PROCESSENTRY32W process{}; process.dwSize = sizeof(process);
    BOOL next = Process32FirstW(snapshot, &process);
    if (!next) scan.Event("UNSAFE", L".", 0, "stopped-query-incomplete", true);
    std::size_t count = 0;
    while (next) {
        if (++count >= 65536) { scan.Event("UNSAFE", L".", 0, "stopped-query-bound", true); break; }
        bool relevant = false;
        for (const auto& leaf : scan.executableLeaves) if (EqualEvidencePath(leaf, process.szExeFile)) { relevant = true; break; }
        if (relevant) {
            HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process.th32ProcessID);
            wchar_t path[kPathCapacity]{}; DWORD size = static_cast<DWORD>(std::size(path));
            if (!handle || !QueryFullProcessImageNameW(handle, 0, path, &size)) scan.Event("UNSAFE", L".", 0, "stopped-process-query-failed", true);
            else if (IsPathWithin(scan.inputs.targetRoot, path, false)) scan.Event("UNSAFE", L".", 0, "target-tree-process-running", true);
            if (handle) CloseHandle(handle);
        }
        next = Process32NextW(snapshot, &process);
    }
    if (count < 65536 && GetLastError() != ERROR_NO_MORE_FILES) scan.Event("UNSAFE", L".", 0, "stopped-query-incomplete", true);
    CloseHandle(snapshot);
}
void CheckArtifact(const std::wstring& path, const Sha256Digest& expected, ArtifactKind kind, Scan& scan, const wchar_t* leaf) {
    FileIdentity before{}, after{}; DWORD code{}; ContractReport contract;
    const bool first = scan.ops.queryFileIdentity(scan.ops.context, path.c_str(), &before, &code);
    const auto hash = HashFileSha256(path.c_str(), GetTickCount64() + 10000);
    const bool valid = CheckArtifactContract(path.c_str(), kind, &contract);
    const bool last = scan.ops.queryFileIdentity(scan.ops.context, path.c_str(), &after, &code);
    if (!EqualEvidencePath(EvidenceLeaf(path), leaf) || !first || !last || !SameFileIdentity(before, after) || !hash.digestValid || hash.digest != expected || !valid) scan.Event("UNSAFE", leaf, 0, "artifact-contract-hash-or-identity-failed", true);
}
}
const PreflightOps& ProductionPreflightOps() noexcept {
    static const PreflightOps ops{nullptr, QueryIdentity, VerifySignature, QueryKnownDll, ProductionEvidenceFileOps()}; return ops;
}
int RunDeploymentPreflight(const PreflightInputs& inputs, const PreflightOps& ops, std::string* diagnostic) {
    if (diagnostic) diagnostic->clear();
    auto fail = [&](const char* why, int code) { if (diagnostic) *diagnostic = why; return code; };
    std::wstring root, bootstrap, companion, manifestPath, report, self; std::string error;
    wchar_t tool[kPathCapacity]{}; DWORD code{};
    if ((inputs.mode != DeploymentMode::Passive && inputs.mode != DeploymentMode::Active) ||
        !ops.queryFileIdentity || !ops.verifySignature || !ops.queryKnownDllState ||
        !RequireAbsolutePlainDirectory(inputs.targetRoot.c_str(), &root, &error) ||
        !RequireAbsolutePlainFile(inputs.bootstrapPath.c_str(), &bootstrap, &error) ||
        !RequireAbsolutePlainFile(inputs.companionPath.c_str(), &companion, &error) ||
        !RequireAbsolutePlainFile(inputs.genuineManifestPath.c_str(), &manifestPath, &error) ||
        !RequireAbsoluteNewFileOutsideRoot(inputs.reportPath.c_str(), root, &report, &error) ||
        !GetBoundedModulePath(nullptr, tool, std::size(tool), &code) || !RequireAbsolutePlainFile(tool, &self, &error)) return fail("usage-or-path-invalid", 2);
    if (IsPathWithin(root, bootstrap, true) || IsPathWithin(root, companion, true) || IsPathWithin(root, manifestPath, true) || IsPathWithin(root, self, true)) return fail("evidence-input-inside-target", 2);
    PreflightInputs normalized = inputs; normalized.targetRoot = root; Scan scan{normalized, ops};
    const auto toolHash = HashFileSha256(self.c_str(), GetTickCount64() + 10000);
    if (!toolHash.digestValid) return fail("tool-hash-failed", 2);
    GenuineManifest manifest; Sha256Digest manifestHash{};
    if (!ReadGenuineManifest(manifestPath.c_str(), &manifest, &manifestHash, &error)) scan.Event("UNSAFE", L".", 0, "manifest-invalid", true);
    CheckArtifact(bootstrap, inputs.bootstrapSha256, ArtifactKind::Bootstrap, scan, L"X3DAudio1_7.dll");
    CheckArtifact(companion, inputs.companionSha256, inputs.mode == DeploymentMode::Passive ? ArtifactKind::CompanionPassive : ArtifactKind::CompanionActive, scan, L"RS2ServerFix.dll");
    wchar_t genuinePath[512]{}; FileEvidence genuine; FileIdentity before{}, after{};
    bool genuineOk = BuildSystemX3AudioPath(genuinePath, std::size(genuinePath), &code) && ops.queryFileIdentity(ops.context, genuinePath, &before, &code) && ReadFileEvidence(genuinePath, GetTickCount64() + 10000, &genuine, &error);
    if (genuineOk) {
        const auto* entry = FindManifestEntry(manifest, genuine.sha256, ManifestState::Qualified);
        const auto signature = ops.verifySignature(ops.context, genuinePath);
        genuineOk = entry && MatchesGenuineManifestEntry(genuine, *entry, &error) && signature.verifyStatus == ERROR_SUCCESS && signature.closeAttempted && signature.closeStatus == ERROR_SUCCESS && ops.queryFileIdentity(ops.context, genuinePath, &after, &code) && SameFileIdentity(before, after);
    }
    if (!genuineOk) scan.Event("UNSAFE", L"X3DAudio1_7.dll", 0, "genuine-qualification-trust-or-identity-failed", true);
    const auto known = ops.queryKnownDllState(ops.context, L"X3DAudio1_7.dll", &code);
    if (known != KnownDllState::Absent) scan.Event("UNSAFE", L".", 0, "known-dll-present-or-query-failed", true);
    for (const auto state : { inputs.avEdr, inputs.wdac, inputs.appLocker, inputs.eac }) if (state == SecurityDisposition::Alerted || state == SecurityDisposition::Blocked || std::string_view(SecurityName(state)) == "invalid") scan.Event("UNSAFE", L".", 0, "operator-security-rejection", true);
    ScanDirectory(root, L"", 0, scan); CheckStopped(scan);
    if (scan.incomplete) ++scan.unsafe;
    if (scan.selected != 1) scan.Event("UNSAFE", L".", 0, "expected-one-current-target", true);
    if (scan.importers != 1) scan.Event("UNSAFE", L".", 0, "expected-one-x3audio-importer", true);
    std::ostringstream out;
    out << "schema=1\r\nmode=stopped-tree-preflight\r\ntool_sha256=" << FormatSha256Upper(toolHash.digest).data()
        << "\r\nmanifest_sha256=" << FormatSha256Upper(manifestHash).data()
        << "\r\nbootstrap_leaf=X3DAudio1_7.dll\r\nbootstrap_sha256=" << FormatSha256Upper(inputs.bootstrapSha256).data()
        << "\r\ncompanion_leaf=RS2ServerFix.dll\r\ncompanion_sha256=" << FormatSha256Upper(inputs.companionSha256).data()
        << "\r\ngenuine_sha256=" << FormatSha256Upper(genuine.sha256).data()
        << "\r\ntarget_build_identity=" << BuildIdentityName(scan.identity) << "\r\ntarget_executable=<TARGET_ROOT>/" << EncodeEvidencePath(scan.target)
        << "\r\noperator_recorded_av_edr=" << SecurityName(inputs.avEdr) << "\r\noperator_recorded_wdac=" << SecurityName(inputs.wdac)
        << "\r\noperator_recorded_applocker=" << SecurityName(inputs.appLocker) << "\r\noperator_recorded_eac=" << SecurityName(inputs.eac)
        << "\r\nknown_dll_x3audio=" << (known == KnownDllState::Absent ? "absent" : known == KnownDllState::Present ? "present" : "query-failed")
        << "\r\ndeployment_mode=" << DeploymentModeName(inputs.mode) << "\r\nevent_count=" << scan.events.size() + (scan.incomplete ? 1 : 0) << "\r\n";
    for (std::size_t i = 0; i < scan.events.size(); ++i) out << "event." << i << '=' << scan.events[i] << "\r\n";
    if (scan.incomplete) out << "event." << scan.events.size() << "=UNSAFE|.|0|scan-incomplete\r\n";
    out << "pe_file_count=" << scan.peFiles << "\r\nx3audio_importer_count=" << scan.importers << "\r\nunsafe_count=" << scan.unsafe << "\r\nresult=" << (scan.unsafe ? "unsafe" : "pass") << "\r\n";
    const auto bytes = out.str();
    if (bytes.size() >= kMaxReport || !WriteEvidenceBytesCreateNew(report.c_str(), bytes, ops.reportFileOps, &error)) return fail("report-write-failed", 1);
    return fail(scan.unsafe ? "unsafe" : "pass", scan.unsafe ? 1 : 0);
}
}
#ifndef RS2_PREFLIGHT_NO_MAIN
int wmain(int argc, wchar_t** argv) {
    using namespace rs2fix; using namespace rs2fix::tooling;
    constexpr const wchar_t* help = L"rs2_deployment_preflight --target-root <absolute plain directory> --bootstrap <absolute plain file> --bootstrap-sha256 <64 uppercase hex> --companion <absolute plain file> --companion-sha256 <64 uppercase hex> --genuine-manifest <absolute plain file> --report <absolute new file outside target root> --mode <passive|active> --av-edr-disposition <state> --wdac-disposition <state> --applocker-disposition <state> --eac-disposition <state>\nstate: not-observed-yet|not-installed|not-enforced|allowed|alerted|blocked\n";
    if (argc == 2 && std::wstring_view(argv[1]) == L"--help") { std::wcout << help; return 0; }
    for (int i = 1; i < argc; ++i) if (std::wstring_view(argv[i]) == L"--help") { std::wcerr << help; return 2; }
    if (argc != 25) { std::wcerr << help; return 2; }
    std::map<std::wstring, std::wstring> values;
    for (int i = 1; i < argc; i += 2) if (!values.emplace(argv[i], argv[i + 1]).second) return 2;
    constexpr const wchar_t* names[] = { L"--target-root", L"--bootstrap", L"--bootstrap-sha256", L"--companion", L"--companion-sha256", L"--genuine-manifest", L"--report", L"--mode", L"--av-edr-disposition", L"--wdac-disposition", L"--applocker-disposition", L"--eac-disposition" };
    for (const auto* name : names) if (values.find(name) == values.end()) return 2;
    auto digest = [&](const wchar_t* key, Sha256Digest* result) {
        const auto& v = values[key]; std::string ascii;
        for (wchar_t c : v) { if (c > 127) return false; ascii.push_back(static_cast<char>(c)); }
        return v.size() == 64 && ParseSha256Upper(ascii, result);
    };
    PreflightInputs in;
    in.targetRoot = values[L"--target-root"]; in.bootstrapPath = values[L"--bootstrap"]; in.companionPath = values[L"--companion"];
    in.genuineManifestPath = values[L"--genuine-manifest"]; in.reportPath = values[L"--report"];
    if (!digest(L"--bootstrap-sha256", &in.bootstrapSha256) || !digest(L"--companion-sha256", &in.companionSha256) || !ParseDeploymentMode(values[L"--mode"], &in.mode) || !ParseSecurity(values[L"--av-edr-disposition"], &in.avEdr) || !ParseSecurity(values[L"--wdac-disposition"], &in.wdac) || !ParseSecurity(values[L"--applocker-disposition"], &in.appLocker) || !ParseSecurity(values[L"--eac-disposition"], &in.eac)) return 2;
    std::string diagnostic; const int result = RunDeploymentPreflight(in, ProductionPreflightOps(), &diagnostic); std::cout << diagnostic << '\n'; return result;
}
#endif
