#pragma once
#include "shared/digest.h"
#include <Windows.h>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
namespace rs2fix::tooling {
enum class ManifestState { Provisional, Qualified };
struct VersionQuad {
    std::uint16_t major{}, minor{}, build{}, revision{};
};
bool operator==(const VersionQuad& left, const VersionQuad& right) noexcept;
struct GenuineManifestEntry {
    ManifestState state{};
    Sha256Digest sha256{};
    std::uint64_t fileSize{};
    std::uint32_t coffTimestamp{}, sizeOfImage{};
    VersionQuad fileVersion{}, productVersion{};
    std::string evidencePath;
};
struct GenuineManifest { std::vector<GenuineManifestEntry> entries; };
bool ParseGenuineManifest(std::string_view bytes, GenuineManifest* manifest,
                          std::string* error);
bool ReadGenuineManifest(const wchar_t* absolutePath, GenuineManifest* manifest,
    Sha256Digest* manifestDigest, std::string* error);
const GenuineManifestEntry* FindManifestEntry(const GenuineManifest& manifest,
    const Sha256Digest& digest, ManifestState requiredState) noexcept;
bool AuditManifestEvidencePaths(const wchar_t* absoluteRepositoryRoot,
    const GenuineManifest& manifest, std::string* error);
struct QualificationEvidence {
    Sha256Digest manifestDigest{}, candidateDigest{}, controlDigest{};
    std::uint64_t candidateFileSize{};
    std::uint32_t candidateCoffTimestamp{}, candidateSizeOfImage{};
    VersionQuad candidateFileVersion{}, candidateProductVersion{};
    DWORD childExitStatus{};
};
bool FormatQualificationEvidence(const QualificationEvidence& evidence,
    std::string* bytes, std::string* error);
bool ParseQualificationEvidence(std::string_view bytes,
    QualificationEvidence* evidence, std::string* error);
struct EvidenceFileOps {
    void* context{};
    HANDLE (*createNew)(void*, const wchar_t*, DWORD*) noexcept{};
    bool (*write)(void*, HANDLE, const void*, DWORD, DWORD*, DWORD*) noexcept{};
    bool (*flush)(void*, HANDLE, DWORD*) noexcept{};
    bool (*close)(void*, HANDLE, DWORD*) noexcept{};
    bool (*remove)(void*, const wchar_t*, DWORD*) noexcept{};
};
const EvidenceFileOps& ProductionEvidenceFileOps() noexcept;
bool WriteEvidenceBytesCreateNew(const wchar_t* absolutePath,
    std::string_view bytes, const EvidenceFileOps& ops, std::string* error);
bool WriteQualificationEvidenceCreateNew(const wchar_t* absolutePath,
    const QualificationEvidence& evidence, const EvidenceFileOps& ops,
    std::string* error);
}
