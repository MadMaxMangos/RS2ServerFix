#pragma once
#include "file_evidence.h"
#include "shared/path_identity.h"
#include <string_view>
namespace rs2fix::tooling {
enum class KnownDllState { Absent, Present, QueryFailed };
enum class SecurityDisposition { NotObservedYet, NotInstalled, NotEnforced, Allowed, Alerted, Blocked };
enum class DeploymentMode { Passive, Active };
struct PreflightInputs {
    std::wstring targetRoot, bootstrapPath, companionPath;
    Sha256Digest bootstrapSha256{}, companionSha256{};
    std::wstring genuineManifestPath, reportPath;
    DeploymentMode mode{DeploymentMode::Passive};
    bool observerCompanion{}; // Explicit production observer selection; never inferred from metadata.
    bool reportingCompanion{}; // Explicit 0.4 selection; cannot also select observer.
    SecurityDisposition avEdr{}, wdac{}, appLocker{}, eac{};
};
struct PreflightOps {
    void* context{};
    bool (*queryFileIdentity)(void*, const wchar_t*, FileIdentity*, DWORD*) noexcept{};
    EmbeddedSignatureResult (*verifySignature)(void*, const wchar_t*) noexcept{};
    KnownDllState (*queryKnownDllState)(void*, const wchar_t*, DWORD*) noexcept{};
    EvidenceFileOps reportFileOps{};
};
const PreflightOps& ProductionPreflightOps() noexcept;
int RunDeploymentPreflight(const PreflightInputs&, const PreflightOps&, std::string* diagnostic);
std::string EncodeEvidenceText(std::string_view bytes);
std::string EncodeEvidencePath(std::wstring_view path);
bool EqualEvidencePath(std::wstring_view a, std::wstring_view b) noexcept;
std::wstring EvidenceLeaf(std::wstring_view path);
const char* DeploymentModeName(DeploymentMode mode) noexcept;
bool ParseDeploymentMode(std::wstring_view text, DeploymentMode* mode) noexcept;
bool IsX3AudioImport(std::string_view name) noexcept;
bool HasRequiredHostImports(const pe::Image& image) noexcept;
}
