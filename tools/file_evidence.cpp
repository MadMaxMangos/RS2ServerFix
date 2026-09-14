#include "file_evidence.h"
#include "tool_paths.h"
#include "companion/sha256.h"
#include <Softpub.h>
#include <algorithm>
#include <cstring>
#include <cwchar>
namespace rs2fix::tooling {
namespace {
bool Fail(std::string* error, const char* token) {
    if (error) *error = token;
    return false;
}
VersionQuad Quad(DWORD high, DWORD low) {
    return {HIWORD(high), LOWORD(high), HIWORD(low), LOWORD(low)};
}
bool Within(const std::vector<BYTE>& bytes, const void* pointer, std::size_t length) {
    const auto base = reinterpret_cast<std::uintptr_t>(bytes.data());
    const auto value = reinterpret_cast<std::uintptr_t>(pointer);
    return value >= base && value - base <= bytes.size() && length <= bytes.size() - (value - base);
}
bool StringValue(std::vector<BYTE>& bytes, const wchar_t* key, std::wstring* value) {
    void* text = nullptr;
    UINT length = 0;
    const std::wstring query = L"\\StringFileInfo\\040904B0\\" + std::wstring(key);
    if (!VerQueryValueW(bytes.data(), query.c_str(), &text, &length) || !length || length > 4096 ||
        !Within(bytes, text, static_cast<std::size_t>(length) * sizeof(wchar_t))) return false;
    const auto* chars = static_cast<const wchar_t*>(text);
    if (wcsnlen_s(chars, length) != length - 1) return false;
    value->assign(chars, length - 1);
    return true;
}
LONG Invoke(void*, HWND window, GUID* action, WINTRUST_DATA* data) noexcept {
    return WinVerifyTrust(window, action, data);
}
bool SameInformation(const BY_HANDLE_FILE_INFORMATION& a, const BY_HANDLE_FILE_INFORMATION& b) {
    return a.dwVolumeSerialNumber == b.dwVolumeSerialNumber && a.nFileIndexHigh == b.nFileIndexHigh &&
        a.nFileIndexLow == b.nFileIndexLow && a.nFileSizeHigh == b.nFileSizeHigh && a.nFileSizeLow == b.nFileSizeLow &&
        a.ftLastWriteTime.dwHighDateTime == b.ftLastWriteTime.dwHighDateTime &&
        a.ftLastWriteTime.dwLowDateTime == b.ftLastWriteTime.dwLowDateTime;
}
}
bool ReadVersionIdentity(const wchar_t* absolutePath, VersionIdentity* version,
                          std::string* error, bool requireStrings) {
    if (!version) return Fail(error, "null_version_output");
    *version = {};
    std::wstring path;
    if (!RequireAbsolutePlainFile(absolutePath, &path, error)) return false;
    DWORD unused = 0;
    const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &unused);
    if (!size || size > 1024 * 1024) return Fail(error, "version_size_invalid");
    std::vector<BYTE> bytes(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, bytes.data())) return Fail(error, "version_read_failed");
    void* raw = nullptr;
    UINT length = 0;
    if (!VerQueryValueW(bytes.data(), L"\\", &raw, &length) || length < sizeof(VS_FIXEDFILEINFO) ||
        !Within(bytes, raw, length)) return Fail(error, "version_fixed_missing");
    VS_FIXEDFILEINFO fixed{};
    std::memcpy(&fixed, raw, sizeof(fixed));
    if (fixed.dwSignature != VS_FFI_SIGNATURE || fixed.dwStrucVersion != VS_FFI_STRUCVERSION)
        return Fail(error, "version_fixed_invalid");
    VersionIdentity parsed{};
    parsed.fileVersion = Quad(fixed.dwFileVersionMS, fixed.dwFileVersionLS);
    parsed.productVersion = Quad(fixed.dwProductVersionMS, fixed.dwProductVersionLS);
    if (requireStrings) {
        if (!VerQueryValueW(bytes.data(), L"\\VarFileInfo\\Translation", &raw, &length) ||
            !length || length > 64 || length % (2 * sizeof(WORD)) != 0 || !Within(bytes, raw, length))
            return Fail(error, "version_translation_invalid");
        for (std::size_t offset = 0; offset < length; offset += 2 * sizeof(WORD)) {
            WORD pair[2]{};
            std::memcpy(pair, static_cast<const BYTE*>(raw) + offset, sizeof(pair));
            parsed.translations.emplace_back(pair[0], pair[1]);
        }
        if (!StringValue(bytes, L"CompanyName", &parsed.companyName) ||
            !StringValue(bytes, L"ProductName", &parsed.productName) ||
            !StringValue(bytes, L"FileDescription", &parsed.fileDescription) ||
            !StringValue(bytes, L"OriginalFilename", &parsed.originalFilename) ||
            !StringValue(bytes, L"FileVersion", &parsed.fileVersionText) ||
            !StringValue(bytes, L"ProductVersion", &parsed.productVersionText))
            return Fail(error, "version_identity_string_missing");
    }
    *version = std::move(parsed);
    if (error) error->clear();
    return true;
}
bool ReadFileEvidence(const wchar_t* absolutePath, ULONGLONG hashDeadline,
                       FileEvidence* evidence, std::string* error) {
    if (!evidence) return Fail(error, "null_file_evidence");
    *evidence = {};
    std::wstring path;
    if (!RequireAbsolutePlainFile(absolutePath, &path, error)) return false;
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) return Fail(error, "evidence_open_failed");
    struct CloseFile { HANDLE file; ~CloseFile() { CloseHandle(file); } } close{file};
    BY_HANDLE_FILE_INFORMATION before{}, after{};
    if (!GetFileInformationByHandle(file, &before) ||
        (before.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0)
        return Fail(error, "evidence_file_identity_failed");
    const std::uint64_t size = (static_cast<std::uint64_t>(before.nFileSizeHigh) << 32) | before.nFileSizeLow;
    if (!size || size > 512ULL * 1024 * 1024) return Fail(error, "evidence_size_invalid");
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    std::size_t cursor = 0;
    while (cursor < bytes.size()) {
        if (GetTickCount64() > hashDeadline) return Fail(error, "evidence_hash_timeout");
        const DWORD request = static_cast<DWORD>(std::min<std::size_t>(65536, bytes.size() - cursor));
        DWORD read = 0;
        if (!ReadFile(file, bytes.data() + cursor, request, &read, nullptr) || read == 0 || read > request)
            return Fail(error, "evidence_read_failed");
        cursor += read;
    }
    FileEvidence parsed{};
    parsed.fileSize = size;
    if (!HashBytesSha256(bytes.data(), bytes.size(), &parsed.sha256)) return Fail(error, "evidence_hash_failed");
    if (GetTickCount64() > hashDeadline) return Fail(error, "evidence_hash_timeout");
    if (!pe::ReadPeBytes(bytes, &parsed.image, error)) return false;
    VersionIdentity version{};
    if (!ReadVersionIdentity(path.c_str(), &version, error, false)) return false;
    parsed.fileVersion = version.fileVersion;
    parsed.productVersion = version.productVersion;
    const HANDLE verify = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    const bool stable = verify != INVALID_HANDLE_VALUE && GetFileInformationByHandle(verify, &after) &&
        SameInformation(before, after) && GetFileInformationByHandle(file, &after) && SameInformation(before, after);
    if (verify != INVALID_HANDLE_VALUE) CloseHandle(verify);
    if (!stable) return Fail(error, "evidence_file_changed");
    *evidence = std::move(parsed);
    if (error) error->clear();
    return true;
}
const WinTrustOps& ProductionWinTrustOps() noexcept {
    static const WinTrustOps ops{nullptr, Invoke};
    return ops;
}
EmbeddedSignatureResult VerifyEmbeddedSignatureCacheOnly(const wchar_t* absolutePath, const WinTrustOps& ops) noexcept {
    EmbeddedSignatureResult result{TRUST_E_SUBJECT_NOT_TRUSTED, TRUST_E_SUBJECT_NOT_TRUSTED, false};
    if (!IsAbsoluteToolPath(absolutePath) || !ops.invoke) return result;
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = absolutePath;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const HWND window = reinterpret_cast<HWND>(INVALID_HANDLE_VALUE);
    result.verifyStatus = ops.invoke(ops.context, window, &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    result.closeAttempted = true;
    result.closeStatus = ops.invoke(ops.context, window, &action, &data);
    return result;
}
bool MatchesGenuineManifestEntry(const FileEvidence& evidence, const GenuineManifestEntry& entry, std::string* error) noexcept {
    if (evidence.fileSize != entry.fileSize) return Fail(error, "genuine_size_mismatch");
    if (evidence.sha256 != entry.sha256) return Fail(error, "genuine_digest_mismatch");
    if (evidence.image.machine != IMAGE_FILE_MACHINE_AMD64 || evidence.image.optionalMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        (evidence.image.characteristics & IMAGE_FILE_DLL) == 0) return Fail(error, "genuine_machine_mismatch");
    if (evidence.image.coffTimestamp != entry.coffTimestamp || evidence.image.sizeOfImage != entry.sizeOfImage)
        return Fail(error, "genuine_pe_identity_mismatch");
    if (!(evidence.fileVersion == entry.fileVersion) || !(evidence.productVersion == entry.productVersion))
        return Fail(error, "genuine_version_mismatch");
    if (evidence.image.exportFunctionCount != 2 || evidence.image.exports.size() != 2) return Fail(error, "genuine_export_count_mismatch");
    bool calculate = false, initialize = false;
    for (const auto& symbol : evidence.image.exports) {
        if (!symbol.rva || !symbol.forwarder.empty()) return Fail(error, "genuine_export_address_invalid");
        const auto* section = pe::FindSection(evidence.image, symbol.rva, 1);
        std::size_t raw = 0;
        if (!section || (section->characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 || !pe::MapImageRva(evidence.image, symbol.rva, 1, &raw))
            return Fail(error, "genuine_export_not_code");
        if (symbol.name == "X3DAudioCalculate" && symbol.ordinal == 1) calculate = true;
        else if (symbol.name == "X3DAudioInitialize" && symbol.ordinal == 2) initialize = true;
        else return Fail(error, "genuine_export_mismatch");
    }
    if (!calculate || !initialize) return Fail(error, "genuine_export_mismatch");
    if (error) error->clear();
    return true;
}
}
