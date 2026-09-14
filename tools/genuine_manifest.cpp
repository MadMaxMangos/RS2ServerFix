#include "genuine_manifest.h"
#include "tool_paths.h"
#include "companion/sha256.h"
#include <algorithm>
#include <array>
#include <limits>
#include <utility>
namespace rs2fix::tooling {
namespace {
bool Fail(std::string* error, const char* token) {
    if (error) *error = token;
    return false;
}
bool Decimal(std::string_view text, std::uint64_t maximum, std::uint64_t* value) {
    if (!value || text.empty() || (text.size() > 1 && text.front() == '0')) return false;
    std::uint64_t number = 0;
    for (char ch : text) {
        if (ch < '0' || ch > '9' || number > (maximum - static_cast<unsigned>(ch - '0')) / 10) return false;
        number = number * 10 + static_cast<unsigned>(ch - '0');
    }
    *value = number;
    return true;
}
bool Hex32(std::string_view text, std::uint32_t* value) {
    if (!value || text.size() != 10 || text.substr(0, 2) != "0x") return false;
    std::uint32_t number = 0;
    for (char ch : text.substr(2)) {
        const unsigned digit = ch >= '0' && ch <= '9' ? static_cast<unsigned>(ch - '0') :
            ch >= 'A' && ch <= 'F' ? static_cast<unsigned>(ch - 'A' + 10) : 16;
        if (digit > 15) return false;
        number = number * 16 + digit;
    }
    *value = number;
    return true;
}
bool Version(std::string_view text, VersionQuad* value) {
    std::uint16_t parts[4]{};
    for (std::size_t i = 0; i < 4; ++i) {
        const auto dot = text.find('.');
        if ((i == 3) != (dot == std::string_view::npos)) return false;
        std::uint64_t number = 0;
        if (!Decimal(text.substr(0, dot), UINT16_MAX, &number)) return false;
        parts[i] = static_cast<std::uint16_t>(number);
        if (dot != std::string_view::npos) text.remove_prefix(dot + 1);
    }
    *value = {parts[0], parts[1], parts[2], parts[3]};
    return true;
}
class Cursor {
public:
    explicit Cursor(std::string_view bytes) : bytes_(bytes) {}
    bool Validate(std::string* error) const {
        if (bytes_.size() > 65536) return Fail(error, "input_oversize");
        if (bytes_.size() < 2 || bytes_.substr(bytes_.size() - 2) != "\r\n") return Fail(error, "missing_final_crlf");
        std::size_t length = 0;
        for (std::size_t i = 0; i < bytes_.size(); ++i) {
            const auto ch = static_cast<unsigned char>(bytes_[i]);
            if (ch == 0 || ch > 127) return Fail(error, "invalid_ascii");
            if (ch == '\n') return Fail(error, "bare_lf");
            if (ch == '\r') {
                if (i + 1 == bytes_.size() || bytes_[i + 1] != '\n') return Fail(error, "bare_cr");
                if (length == 0) return Fail(error, "blank_line");
                length = 0;
                ++i;
            } else if (++length > 1024) return Fail(error, "line_too_long");
        }
        return true;
    }
    bool Take(std::string_view key, std::string_view* value, std::string* error) {
        const auto end = bytes_.find("\r\n", position_);
        if (end == std::string_view::npos) return Fail(error, "missing_field");
        const auto line = bytes_.substr(position_, end - position_);
        if (line.size() <= key.size() || line.substr(0, key.size()) != key || line[key.size()] != '=')
            return Fail(error, "unexpected_field");
        *value = line.substr(key.size() + 1);
        position_ = end + 2;
        return true;
    }
    bool Literal(std::string_view key, std::string_view wanted, std::string* error) {
        std::string_view value;
        return Take(key, &value, error) && (value == wanted || Fail(error, "invalid_literal"));
    }
    bool End(std::string* error) const {
        return position_ == bytes_.size() || Fail(error, "trailing_field");
    }
private:
    std::string_view bytes_;
    std::size_t position_{};
};
std::string DigestText(const Sha256Digest& value) { return FormatSha256Upper(value).data(); }
std::string VersionText(const VersionQuad& value) {
    return std::to_string(value.major) + "." + std::to_string(value.minor) + "." +
        std::to_string(value.build) + "." + std::to_string(value.revision);
}
std::string HexText(std::uint32_t value) {
    std::string text = "0x00000000";
    constexpr char digits[] = "0123456789ABCDEF";
    for (int i = 9; i >= 2; --i) { text[static_cast<std::size_t>(i)] = digits[value & 15]; value >>= 4; }
    return text;
}
HANDLE Create(void*, const wchar_t* path, DWORD* error) noexcept {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    *error = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    return file;
}
bool Write(void*, HANDLE file, const void* data, DWORD size, DWORD* written, DWORD* error) noexcept {
    const bool result = WriteFile(file, data, size, written, nullptr) != FALSE;
    *error = result ? ERROR_SUCCESS : GetLastError(); return result;
}
bool Flush(void*, HANDLE file, DWORD* error) noexcept {
    const bool result = FlushFileBuffers(file) != FALSE; *error = result ? 0 : GetLastError(); return result;
}
bool Close(void*, HANDLE file, DWORD* error) noexcept {
    const bool result = CloseHandle(file) != FALSE; *error = result ? 0 : GetLastError(); return result;
}
bool Remove(void*, const wchar_t* path, DWORD* error) noexcept {
    const bool result = DeleteFileW(path) != FALSE; *error = result ? 0 : GetLastError(); return result;
}
}
bool operator==(const VersionQuad& left, const VersionQuad& right) noexcept {
    return left.major == right.major && left.minor == right.minor && left.build == right.build && left.revision == right.revision;
}
bool ParseGenuineManifest(std::string_view bytes, GenuineManifest* manifest, std::string* error) {
    if (!manifest) return Fail(error, "null_manifest");
    *manifest = {};
    if (error) error->clear();
    Cursor cursor(bytes);
    std::string_view value;
    std::uint64_t count = 0;
    if (!cursor.Validate(error) || !cursor.Literal("schema", "1", error) ||
        !cursor.Take("entry_count", &value, error)) return false;
    if (!Decimal(value, 32, &count) || count == 0) return Fail(error, "invalid_entry_count");
    GenuineManifest parsed;
    for (std::uint64_t i = 0; i < count; ++i) {
        GenuineManifestEntry entry{};
        const std::string prefix = "entry." + std::to_string(i) + ".";
        if (!cursor.Take(prefix + "state", &value, error)) return false;
        if (value == "qualified") entry.state = ManifestState::Qualified;
        else if (value == "provisional") entry.state = ManifestState::Provisional;
        else return Fail(error, "invalid_state");
        if (!cursor.Take(prefix + "sha256", &value, error)) return false;
        if (!ParseSha256Upper(value, &entry.sha256)) return Fail(error, "invalid_sha256");
        for (const auto& existing : parsed.entries)
            if (existing.sha256 == entry.sha256) return Fail(error, "duplicate_digest");
        if (!cursor.Take(prefix + "file_size", &value, error)) return false;
        if (!Decimal(value, UINT64_MAX, &entry.fileSize) || !entry.fileSize) return Fail(error, "invalid_file_size");
        if (!cursor.Literal(prefix + "machine", "AMD64", error) || !cursor.Take(prefix + "coff_timestamp", &value, error)) return false;
        if (!Hex32(value, &entry.coffTimestamp)) return Fail(error, "invalid_timestamp");
        if (!cursor.Take(prefix + "size_of_image", &value, error)) return false;
        std::uint64_t size = 0;
        if (!Decimal(value, UINT32_MAX, &size) || !size) return Fail(error, "invalid_image_size");
        entry.sizeOfImage = static_cast<std::uint32_t>(size);
        if (!cursor.Take(prefix + "file_version_quad", &value, error)) return false;
        if (!Version(value, &entry.fileVersion)) return Fail(error, "invalid_version");
        if (!cursor.Take(prefix + "product_version_quad", &value, error)) return false;
        if (!Version(value, &entry.productVersion)) return Fail(error, "invalid_version");
        if (!cursor.Literal(prefix + "export_1", "X3DAudioCalculate@1", error) ||
            !cursor.Literal(prefix + "export_2", "X3DAudioInitialize@2", error) ||
            !cursor.Literal(prefix + "signature_policy", "embedded-winverifytrust-v2-cache-only", error) ||
            !cursor.Take(prefix + "evidence_path", &value, error)) return false;
        const std::string expected = "docs/evidence/x3audio/" + DigestText(entry.sha256) + ".md";
        if (value != expected) return Fail(error, "invalid_evidence_path");
        entry.evidencePath = std::string(value);
        parsed.entries.push_back(std::move(entry));
    }
    if (!cursor.End(error)) return false;
    *manifest = std::move(parsed);
    return true;
}
bool ReadGenuineManifest(const wchar_t* absolutePath, GenuineManifest* manifest,
                         Sha256Digest* manifestDigest, std::string* error) {
    if (!manifest || !manifestDigest) return Fail(error, "null_manifest_output");
    *manifest = {}; *manifestDigest = {};
    std::wstring path;
    if (!RequireAbsolutePlainFile(absolutePath, &path, error)) return false;
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) return Fail(error, "manifest_open_failed");
    BY_HANDLE_FILE_INFORMATION identity{};
    if (!GetFileInformationByHandle(file, &identity) ||
        (identity.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        CloseHandle(file);
        return Fail(error, "manifest_not_plain_file");
    }
    std::array<char, 65537> bytes{};
    DWORD total = 0;
    bool success = true;
    while (total < bytes.size()) {
        DWORD got = 0;
        if (!ReadFile(file, bytes.data() + total, static_cast<DWORD>(bytes.size()) - total, &got, nullptr)) { success = false; break; }
        if (!got) break;
        total += got;
    }
    if (!CloseHandle(file)) success = false;
    if (!success) return Fail(error, "manifest_read_failed");
    if (!ParseGenuineManifest(std::string_view(bytes.data(), total), manifest, error)) return false;
    if (!HashBytesSha256(bytes.data(), total, manifestDigest)) { *manifest = {}; return Fail(error, "manifest_hash_failed"); }
    return true;
}
const GenuineManifestEntry* FindManifestEntry(const GenuineManifest& manifest,
    const Sha256Digest& digest, ManifestState requiredState) noexcept {
    for (const auto& entry : manifest.entries)
        if (entry.state == requiredState && entry.sha256 == digest) return &entry;
    return nullptr;
}
bool AuditManifestEvidencePaths(const wchar_t* absoluteRepositoryRoot,
    const GenuineManifest& manifest, std::string* error) {
    std::wstring root;
    if (!RequireAbsolutePlainDirectory(absoluteRepositoryRoot, &root, error)) return false;
    for (const auto& entry : manifest.entries) {
        const std::string expected = "docs/evidence/x3audio/" + DigestText(entry.sha256) + ".md";
        if (entry.evidencePath != expected) return Fail(error, "invalid_evidence_path");
        std::wstring relative(entry.evidencePath.begin(), entry.evidencePath.end());
        std::replace(relative.begin(), relative.end(), L'/', L'\\');
        std::wstring checked;
        if (!RequireAbsolutePlainFile((root + L"\\" + relative).c_str(), &checked, error) ||
            !IsPathWithin(root, checked, false)) return Fail(error, "evidence_path_missing_or_unsafe");
    }
    return true;
}
bool FormatQualificationEvidence(const QualificationEvidence& evidence, std::string* bytes, std::string* error) {
    if (!bytes) return Fail(error, "null_evidence_output");
    bytes->clear();
    if (!evidence.candidateFileSize || !evidence.candidateSizeOfImage || evidence.childExitStatus != 0)
        return Fail(error, "invalid_qualification_success");
    *bytes = "schema=1\r\nmode=qualify-system32\r\nmanifest_sha256=" + DigestText(evidence.manifestDigest) +
        "\r\ncandidate_sha256=" + DigestText(evidence.candidateDigest) +
        "\r\ncandidate_file_size=" + std::to_string(evidence.candidateFileSize) +
        "\r\ncandidate_machine=AMD64\r\ncandidate_coff_timestamp=" + HexText(evidence.candidateCoffTimestamp) +
        "\r\ncandidate_size_of_image=" + std::to_string(evidence.candidateSizeOfImage) +
        "\r\ncandidate_file_version_quad=" + VersionText(evidence.candidateFileVersion) +
        "\r\ncandidate_product_version_quad=" + VersionText(evidence.candidateProductVersion) +
        "\r\ncandidate_export_1=X3DAudioCalculate@1\r\ncandidate_export_2=X3DAudioInitialize@2\r\n"
        "candidate_signature_policy=embedded-winverifytrust-v2-cache-only\r\n"
        "winverifytrust_status=ERROR_SUCCESS\r\nabi_layout=pass\r\nchild_exit_status=0x00000000\r\n"
        "control_digest_sha256=" + DigestText(evidence.controlDigest) + "\r\n";
    if (error) error->clear();
    return true;
}
bool ParseQualificationEvidence(std::string_view bytes, QualificationEvidence* evidence, std::string* error) {
    if (!evidence) return Fail(error, "null_evidence_output");
    *evidence = {};
    QualificationEvidence parsed{};
    Cursor cursor(bytes);
    std::string_view value;
    if (!cursor.Validate(error) || !cursor.Literal("schema", "1", error) ||
        !cursor.Literal("mode", "qualify-system32", error)) return false;
    if (!cursor.Take("manifest_sha256", &value, error)) return false;
    if (!ParseSha256Upper(value, &parsed.manifestDigest)) return Fail(error, "invalid_sha256");
    if (!cursor.Take("candidate_sha256", &value, error)) return false;
    if (!ParseSha256Upper(value, &parsed.candidateDigest)) return Fail(error, "invalid_sha256");
    if (!cursor.Take("candidate_file_size", &value, error)) return false;
    if (!Decimal(value, UINT64_MAX, &parsed.candidateFileSize) || !parsed.candidateFileSize) return Fail(error, "invalid_file_size");
    if (!cursor.Literal("candidate_machine", "AMD64", error) || !cursor.Take("candidate_coff_timestamp", &value, error)) return false;
    if (!Hex32(value, &parsed.candidateCoffTimestamp)) return Fail(error, "invalid_timestamp");
    if (!cursor.Take("candidate_size_of_image", &value, error)) return false;
    std::uint64_t size = 0;
    if (!Decimal(value, UINT32_MAX, &size) || !size) return Fail(error, "invalid_image_size");
    parsed.candidateSizeOfImage = static_cast<std::uint32_t>(size);
    if (!cursor.Take("candidate_file_version_quad", &value, error)) return false;
    if (!Version(value, &parsed.candidateFileVersion)) return Fail(error, "invalid_version");
    if (!cursor.Take("candidate_product_version_quad", &value, error)) return false;
    if (!Version(value, &parsed.candidateProductVersion)) return Fail(error, "invalid_version");
    if (!cursor.Literal("candidate_export_1", "X3DAudioCalculate@1", error) ||
        !cursor.Literal("candidate_export_2", "X3DAudioInitialize@2", error) ||
        !cursor.Literal("candidate_signature_policy", "embedded-winverifytrust-v2-cache-only", error) ||
        !cursor.Literal("winverifytrust_status", "ERROR_SUCCESS", error) ||
        !cursor.Literal("abi_layout", "pass", error) ||
        !cursor.Literal("child_exit_status", "0x00000000", error) ||
        !cursor.Take("control_digest_sha256", &value, error)) return false;
    if (!ParseSha256Upper(value, &parsed.controlDigest)) return Fail(error, "invalid_sha256");
    if (!cursor.End(error)) return false;
    *evidence = parsed;
    if (error) error->clear();
    return true;
}
const EvidenceFileOps& ProductionEvidenceFileOps() noexcept {
    static const EvidenceFileOps ops{nullptr, Create, Write, Flush, Close, Remove};
    return ops;
}
bool WriteEvidenceBytesCreateNew(const wchar_t* absolutePath, std::string_view bytes,
    const EvidenceFileOps& ops, std::string* error) {
    std::wstring path;
    if (!RequireAbsoluteNewFileOutsideRoot(absolutePath, {}, &path, error)) return false;
    if (!ops.createNew || !ops.write || !ops.flush || !ops.close || !ops.remove || bytes.empty() || bytes.size() > UINT32_MAX)
        return Fail(error, "invalid_evidence_writer");
    DWORD code = 0;
    const HANDLE file = ops.createNew(ops.context, path.c_str(), &code);
    if (!file || file == INVALID_HANDLE_VALUE) return Fail(error, "evidence_create_failed");
    bool success = true;
    std::size_t cursor = 0;
    while (cursor < bytes.size()) {
        const auto request = static_cast<DWORD>(bytes.size() - cursor);
        DWORD written = 0;
        if (!ops.write(ops.context, file, bytes.data() + cursor, request, &written, &code) || !written || written > request) {
            success = false; break;
        }
        cursor += written;
    }
    if (success && !ops.flush(ops.context, file, &code)) success = false;
    if (!ops.close(ops.context, file, &code)) success = false;
    if (!success) {
        if (!ops.remove(ops.context, path.c_str(), &code)) return Fail(error, "evidence_failure_cleanup_failed");
        return Fail(error, "evidence_write_flush_or_close_failed");
    }
    if (error) error->clear();
    return true;
}
bool WriteQualificationEvidenceCreateNew(const wchar_t* absolutePath,
    const QualificationEvidence& evidence, const EvidenceFileOps& ops, std::string* error) {
    std::string bytes;
    return FormatQualificationEvidence(evidence, &bytes, error) &&
        WriteEvidenceBytesCreateNew(absolutePath, bytes, ops, error);
}
}
