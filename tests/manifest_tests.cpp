#include "test_framework.h"
#include "genuine_manifest.h"
#include "tool_paths.h"
#include <algorithm>
#include <array>
#include <cstring>
namespace rs2fix::testcases {
namespace {
using namespace tooling;
constexpr char kDigest[] = "9460709339701AD471A5CABE6365355F4D586DC4FCB86507C1331839DC555446";
std::string Record(unsigned index, std::string digest = kDigest) {
    const auto key = "entry." + std::to_string(index) + ".";
    return key + "state=qualified\r\n" + key + "sha256=" + digest + "\r\n" + key + "file_size=24920\r\n" +
        key + "machine=AMD64\r\n" + key + "coff_timestamp=0x4B6B06BE\r\n" + key + "size_of_image=36864\r\n" +
        key + "file_version_quad=9.28.1886.0\r\n" + key + "product_version_quad=9.28.1886.0\r\n" +
        key + "export_1=X3DAudioCalculate@1\r\n" + key + "export_2=X3DAudioInitialize@2\r\n" +
        key + "signature_policy=embedded-winverifytrust-v2-cache-only\r\n" + key + "evidence_path=docs/evidence/x3audio/" + digest + ".md\r\n";
}
std::string Seed() { return "schema=1\r\nentry_count=1\r\n" + Record(0); }
std::string Replace(std::string text, const std::string& old, const std::string& value) {
    const auto position = text.find(old);
    RS2_CHECK(position != std::string::npos);
    if (position != std::string::npos) text.replace(position, old.size(), value);
    return text;
}
void Reject(const std::string& text, const char* expected = nullptr) {
    GenuineManifest manifest; std::string error;
    RS2_CHECK(!ParseGenuineManifest(text, &manifest, &error));
    RS2_CHECK(!error.empty() && manifest.entries.empty());
    if (expected) RS2_CHECK(error == expected);
}
struct WriterFixture {
    const EvidenceFileOps* real{&ProductionEvidenceFileOps()};
    int mode{}, writes{}, removes{}, creates{};
};
HANDLE Create(void* context, const wchar_t* path, DWORD* error) noexcept {
    auto& state = *static_cast<WriterFixture*>(context); ++state.creates;
    return state.real->createNew(nullptr, path, error);
}
bool Write(void* context, HANDLE file, const void* data, DWORD size, DWORD* written, DWORD* error) noexcept {
    auto& state = *static_cast<WriterFixture*>(context); ++state.writes;
    if (state.mode == 1 && state.writes == 2) { *written = 0; *error = ERROR_SUCCESS; return true; }
    const DWORD request = state.mode == 1 && state.writes == 1 ? size / 2 : size;
    return state.real->write(nullptr, file, data, request, written, error);
}
bool Flush(void* context, HANDLE file, DWORD* error) noexcept {
    auto& state = *static_cast<WriterFixture*>(context);
    if (state.mode == 2) { *error = ERROR_WRITE_FAULT; return false; }
    return state.real->flush(nullptr, file, error);
}
bool Close(void* context, HANDLE file, DWORD* error) noexcept {
    auto& state = *static_cast<WriterFixture*>(context);
    const bool result = state.real->close(nullptr, file, error);
    if (state.mode == 3) { *error = ERROR_INVALID_HANDLE; return false; }
    return result;
}
bool Remove(void* context, const wchar_t* path, DWORD* error) noexcept {
    auto& state = *static_cast<WriterFixture*>(context); ++state.removes;
    return state.real->remove(nullptr, path, error);
}
std::string ReadBytes(const wchar_t* path) {
    const HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    RS2_CHECK(file != INVALID_HANDLE_VALUE);
    if (file == INVALID_HANDLE_VALUE) return {};
    std::array<char, 65537> bytes{}; DWORD read = 0;
    const bool okay = ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) != FALSE;
    RS2_CHECK(okay); RS2_CHECK(CloseHandle(file) != FALSE);
    return okay ? std::string(bytes.data(), read) : std::string{};
}
}
void RunManifestTests() {
    const std::string seed = Seed();
    GenuineManifest manifest; std::string error;
    RS2_CHECK(ParseGenuineManifest(seed, &manifest, &error));
    RS2_CHECK(manifest.entries.size() == 1);
    Sha256Digest digest{}; RS2_CHECK(ParseSha256Upper(kDigest, &digest));
    RS2_CHECK(FindManifestEntry(manifest, digest, ManifestState::Qualified) != nullptr);
    RS2_CHECK(FindManifestEntry(manifest, digest, ManifestState::Provisional) == nullptr);
    RS2_CHECK(ParseGenuineManifest(Replace(seed, "state=qualified", "state=provisional"), &manifest, &error));
    RS2_CHECK(FindManifestEntry(manifest, digest, ManifestState::Qualified) == nullptr);
    RS2_CHECK(FindManifestEntry(manifest, digest, ManifestState::Provisional) != nullptr);
    std::string many = "schema=1\r\nentry_count=32\r\n";
    for (unsigned i = 0; i < 32; ++i) {
        Sha256Digest unique{}; unique[0] = static_cast<std::uint8_t>(i);
        many += Record(i, FormatSha256Upper(unique).data());
    }
    RS2_CHECK(ParseGenuineManifest(many, &manifest, &error) && manifest.entries.size() == 32);
    Reject(Replace(seed, "entry_count=1", "entry_count=0"));
    Reject(Replace(seed, "entry_count=1", "entry_count=33"));
    std::string exactLimit;
    while (exactLimit.size() + 3 <= 65536) exactLimit += "x\r\n";
    exactLimit.insert(0, 65536 - exactLimit.size(), 'x');
    Reject(exactLimit, "unexpected_field");
    Reject(exactLimit + "x", "input_oversize");
    Reject(std::string(1024, 'x') + "\r\n", "unexpected_field");
    Reject(std::string(1025, 'x') + "\r\n", "line_too_long");
    Reject(std::string("\xEF\xBB\xBF") + seed);
    Reject(std::string(1, '\0') + seed);
    Reject(std::string(1, static_cast<char>(128)) + seed);
    Reject(Replace(seed, "schema=1\r\n", "schema=1\n"));
    Reject("\r\n" + seed);
    Reject(seed.substr(0, seed.size() - 2));
    Reject("schema=1\r\n" + seed);
    Reject(Replace(seed, "entry.0.machine", "entry.0.unknown"));
    Reject(Replace(seed, "entry.0.machine=AMD64\r\n", ""));
    Reject(Replace(seed, "entry.0.state=qualified\r\nentry.0.sha256=", "entry.0.sha256=qualified\r\nentry.0.state="));
    Reject(seed + "trailing=value\r\n");
    Reject(Replace(seed, "entry.0.state", "entry.1.state"));
    Reject(Replace(seed, "entry.0.sha256=9460", "entry.0.sha256=abcd"));
    Reject(Replace(seed, "entry.0.sha256=9460", "entry.0.sha256=946"));
    Reject(Replace(seed, "entry.0.sha256=9460", "entry.0.sha256=94600"));
    for (const std::string& value : {"0", "024920", "18446744073709551616", "-1", "+1", " 1"})
        Reject(Replace(seed, "file_size=24920", "file_size=" + value));
    Reject(Replace(seed, "size_of_image=36864", "size_of_image=4294967296"));
    Reject(Replace(seed, "0x4B6B06BE", "0x4b6B06BE"));
    Reject(Replace(seed, "0x4B6B06BE", "0x4B6B06B"));
    for (const std::string& value : {"9.28.1886", "9.28.1886.0.0", "09.28.1886.0", "9.65536.0.0", "9..0.0"})
        Reject(Replace(seed, "file_version_quad=9.28.1886.0", "file_version_quad=" + value));
    Reject(Replace(seed, "machine=AMD64", "machine=I386"));
    Reject(Replace(seed, "X3DAudioCalculate@1", "X3DAudioCalculate@2"));
    Reject(Replace(seed, "X3DAudioInitialize@2", "X3DAudioInitialize@1"));
    Reject(Replace(seed, "embedded-winverifytrust-v2-cache-only", "catalogue"));
    for (const std::string& value : {"/docs/evidence/x3audio/", "C:/docs/evidence/x3audio/", "docs\\evidence\\x3audio\\",
        "docs//evidence/x3audio/", "docs/./evidence/x3audio/", "docs/../evidence/x3audio/", "docs/evidence/x3audio/0"})
        Reject(Replace(seed, "evidence_path=docs/evidence/x3audio/", "evidence_path=" + value));
    Reject(Replace(seed, ".md\r\n", "0.md\r\n"));

    QualificationEvidence qualification{};
    qualification.manifestDigest = digest; qualification.candidateDigest = digest; qualification.controlDigest = digest;
    qualification.candidateFileSize = 24920; qualification.candidateCoffTimestamp = 0x4B6B06BE;
    qualification.candidateSizeOfImage = 36864; qualification.candidateFileVersion = {9, 28, 1886, 0};
    qualification.candidateProductVersion = {9, 28, 1886, 0};
    std::string evidenceBytes, roundtrip;
    RS2_CHECK(FormatQualificationEvidence(qualification, &evidenceBytes, &error));
    QualificationEvidence parsed{};
    RS2_CHECK(ParseQualificationEvidence(evidenceBytes, &parsed, &error));
    RS2_CHECK(FormatQualificationEvidence(parsed, &roundtrip, &error) && roundtrip == evidenceBytes);
    for (const auto& bad : {evidenceBytes + "extra=1\r\n", evidenceBytes.substr(0, evidenceBytes.size() - 2),
        Replace(evidenceBytes, "child_exit_status=0x00000000", "child_exit_status=0x00000001"),
        Replace(evidenceBytes, "abi_layout=pass\r\n", ""), Replace(evidenceBytes, "abi_layout=pass", "unknown=pass"),
        Replace(evidenceBytes, "abi_layout=pass", "abi_layout=pass\r\nabi_layout=pass")})
        RS2_CHECK(!ParseQualificationEvidence(bad, &parsed, &error));

    wchar_t temporary[32768]{};
    const DWORD temporaryLength = GetTempPathW(static_cast<DWORD>(std::size(temporary)), temporary);
    RS2_CHECK(temporaryLength > 0 && temporaryLength < std::size(temporary));
    if (!temporaryLength || temporaryLength >= std::size(temporary)) return;
    const auto root = std::wstring(temporary) + L"rs2-manifest-test-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    RS2_CHECK(CreateDirectoryW(root.c_str(), nullptr) != FALSE);
    const auto path = root + L"\\evidence.txt";
    WriterFixture state{};
    const EvidenceFileOps ops{&state, Create, Write, Flush, Close, Remove};
    for (int mode = 1; mode <= 3; ++mode) {
        state = {}; state.mode = mode;
        RS2_CHECK(!WriteQualificationEvidenceCreateNew(path.c_str(), qualification, ops, &error));
        RS2_CHECK(state.creates == 1 && state.removes == 1 && GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES);
        if (mode == 1) RS2_CHECK(state.writes == 2);
    }
    state = {};
    RS2_CHECK(WriteQualificationEvidenceCreateNew(path.c_str(), qualification, ops, &error));
    RS2_CHECK(ReadBytes(path.c_str()) == evidenceBytes);
    RS2_CHECK(!WriteQualificationEvidenceCreateNew(path.c_str(), qualification, ops, &error) && state.creates == 1);
    std::wstring normalized;
    RS2_CHECK(RequireAbsolutePlainFile(path.c_str(), &normalized, &error));
    RS2_CHECK(RequireAbsolutePlainDirectory(root.c_str(), &normalized, &error));
    RS2_CHECK(!RequireAbsolutePlainFile(root.c_str(), &normalized, &error));
    RS2_CHECK(!RequireAbsolutePlainDirectory(path.c_str(), &normalized, &error));
    RS2_CHECK(!RequireAbsolutePlainFile(L"relative.txt", &normalized, &error));
    RS2_CHECK(!RequireAbsolutePlainFile((L"\"" + path + L"\"").c_str(), &normalized, &error));
    RS2_CHECK(!RequireAbsoluteNewFileOutsideRoot((root + L"\\inside.txt").c_str(), root, &normalized, &error));
    RS2_CHECK(RequireAbsoluteNewFileOutsideRoot((root + L"\\new.txt").c_str(), {}, &normalized, &error));
    RS2_CHECK(!RequireAbsoluteNewFileOutsideRoot((root + L"\\NUL.txt").c_str(), {}, &normalized, &error));
    RS2_CHECK(!RequireAbsoluteNewFileOutsideRoot((root + L"\\COM1.evidence").c_str(), {}, &normalized, &error));
    RS2_CHECK(!RequireAbsoluteNewFileOutsideRoot((root + L"\\..\\escaped.txt").c_str(), {}, &normalized, &error));
    RS2_CHECK(IsPathWithin(root, path, false));
    RS2_CHECK(!IsPathWithin(root, root + L"-other\\file.txt", false));
    RS2_CHECK(IsPathWithin(root, root, true) && !IsPathWithin(root, root, false));
    RS2_CHECK(DeleteFileW(path.c_str()) != FALSE);
    RS2_CHECK(RemoveDirectoryW(root.c_str()) != FALSE);
#ifdef RS2_GENUINE_MANIFEST_PATH
    Sha256Digest manifestDigest{};
    RS2_CHECK(ReadGenuineManifest(RS2_GENUINE_MANIFEST_PATH, &manifest, &manifestDigest, &error));
    RS2_CHECK(manifest.entries.size() == 1 && manifest.entries[0].sha256 == digest && manifest.entries[0].fileSize == 24920);
    RS2_CHECK(ReadBytes(RS2_GENUINE_MANIFEST_PATH) == seed);
    Sha256Digest expectedManifest{};
    RS2_CHECK(ParseSha256Upper("63D96BA7F55AC05EDBEE62C2FD9EFA2DA345D785863996C63AD5452B19B80FEF", &expectedManifest));
    RS2_CHECK(manifestDigest == expectedManifest);
#ifdef RS2_DOCUMENTATION_ROOT
    RS2_CHECK(AuditManifestEvidencePaths(RS2_DOCUMENTATION_ROOT, manifest, &error));
#endif
#endif
}
}
