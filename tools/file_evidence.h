#pragma once
#include "genuine_manifest.h"
#include "pe_reader.h"
#include <wintrust.h>
namespace rs2fix::tooling {
struct VersionIdentity {
    VersionQuad fileVersion{}, productVersion{};
    std::wstring companyName, productName, fileDescription, originalFilename;
    std::wstring fileVersionText, productVersionText;
    std::vector<std::pair<WORD, WORD>> translations;
};
struct FileEvidence {
    std::uint64_t fileSize{};
    Sha256Digest sha256{};
    pe::Image image{};
    VersionQuad fileVersion{}, productVersion{};
};
bool ReadVersionIdentity(const wchar_t* absolutePath, VersionIdentity* version,
                         std::string* error, bool requireStrings = true);
bool ReadFileEvidence(const wchar_t* absolutePath, ULONGLONG hashDeadline,
                      FileEvidence* evidence, std::string* error);
struct EmbeddedSignatureResult {
    LONG verifyStatus{}, closeStatus{};
    bool closeAttempted{};
};
struct WinTrustOps {
    void* context{};
    LONG (*invoke)(void*, HWND, GUID*, WINTRUST_DATA*) noexcept{};
};
EmbeddedSignatureResult VerifyEmbeddedSignatureCacheOnly(
    const wchar_t* absolutePath, const WinTrustOps& ops) noexcept;
const WinTrustOps& ProductionWinTrustOps() noexcept;
bool MatchesGenuineManifestEntry(const FileEvidence& evidence,
    const GenuineManifestEntry& entry, std::string* error) noexcept;
}
