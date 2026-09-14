#pragma once
#include "deployment_preflight.h"
#include "companion/recon_profile.h"
#include "pe_contract_lib.h"
#include <memory>

namespace rs2fix::tooling {
enum class RuntimeExpectation { SystemControl, ProxyPass };
enum class ExpectedReconState { Original, Corrected };
enum class ObservedReconState { Unavailable, Original, Corrected, Unexpected };
struct RuntimeProcessIdentity {
    DWORD processId{};
    std::uint64_t creationTime{};
    std::wstring imagePath;
};
struct RawRuntimeModule {
    std::uintptr_t base{};
    std::uint32_t imageSize{};
    std::wstring fullPath;
};
struct RuntimeModule : RawRuntimeModule {
    FileIdentity fileIdentity{};
    pe::Image image{};
    bool x3audioExports{}, companionExports{};
};
struct RuntimeInventoryOps {
    void* context{};
    HANDLE (*openProcess)(void*, DWORD, DWORD*){};
    void (*closeProcess)(void*, HANDLE) noexcept{};
    bool (*queryProcess)(void*, HANDLE, RuntimeProcessIdentity*, DWORD*){};
    bool (*enumerate)(void*, HANDLE, DWORD, std::vector<RawRuntimeModule>*, DWORD*){};
    bool (*queryFileIdentity)(void*, const wchar_t*, FileIdentity*, DWORD*){};
    bool (*readPe)(void*, const wchar_t*, pe::Image*, std::string*){};
    bool (*readMemory)(void*, HANDLE, std::uintptr_t, void*, std::size_t, std::size_t*, DWORD*){};
    EvidenceFileOps reportFileOps{};
};
struct RuntimeProcessLease {
    HANDLE handle{};
    RuntimeInventoryOps ops{};
    RuntimeProcessLease() = default;
    RuntimeProcessLease(const RuntimeProcessLease&) = delete;
    RuntimeProcessLease& operator=(const RuntimeProcessLease&) = delete;
    ~RuntimeProcessLease();
};
struct RuntimeInventory {
    DWORD processId{};
    std::uint64_t creationTime{};
    std::wstring processImagePath;
    std::vector<RuntimeModule> modules;
    std::size_t attempts{};
    std::shared_ptr<RuntimeProcessLease> process;
};
struct RuntimeValidationInputs {
    DWORD processId{};
    std::wstring targetRoot;
    RuntimeExpectation expectation{};
    DeploymentMode mode{};
    ExpectedReconState expectedRecon{};
    Sha256Digest bootstrapSha256{}, companionSha256{};
    GenuineManifest genuineManifest;
    Sha256Digest genuineManifestSha256{}, toolSha256{};
    std::wstring reportPath;
};
struct ReconObservation {
    ObservedReconState state{ObservedReconState::Unavailable};
    Sha256Digest digest{};
    bool constantsMatch{};
};
struct RuntimeValidationResult {
    bool passed{};
    std::vector<std::string> findings;
    Sha256Digest hostSha256{}, genuineSha256{}, bootstrapSha256{}, companionSha256{};
    std::vector<std::pair<std::uintptr_t, Sha256Digest>> moduleDigests;
    ReconObservation recon;
};
// Explicit file-evidence boundaries permit own-code synthetic validation tests;
// the executable always uses ProductionRuntimeValidationOps.
struct RuntimeValidationOps {
    void* context{};
    bool (*systemGenuine)(void*, std::wstring*, FileIdentity*){};
    bool (*hashModule)(void*, const RuntimeModule&, Sha256Digest*){};
    bool (*queryIdentity)(void*, const wchar_t*, FileIdentity*, DWORD*){};
    bool (*readEvidence)(void*, const wchar_t*, FileEvidence*, std::string*){};
    EmbeddedSignatureResult (*signature)(void*, const wchar_t*){};
    bool (*artifactContract)(void*, const wchar_t*, ArtifactKind, ContractReport*){};
};
const RuntimeValidationOps& ProductionRuntimeValidationOps() noexcept;
const RuntimeInventoryOps& ProductionRuntimeInventoryOps() noexcept;
bool CaptureStableRuntimeInventory(DWORD, const RuntimeInventoryOps&, RuntimeInventory*, std::string* error);
bool ValidateRuntimeInventory(const RuntimeInventory&, const RuntimeValidationInputs&, RuntimeValidationResult*);
bool ValidateRuntimeInventoryWithOps(const RuntimeInventory&, const RuntimeValidationInputs&,
    const RuntimeValidationOps&, const ReconProfile&, RuntimeValidationResult*);
bool WriteRuntimeInventoryReport(const RuntimeInventory&, const RuntimeValidationInputs&,
    const RuntimeValidationResult&, const EvidenceFileOps&, std::string* error);
// Profile injection is a native unit-test boundary only. The public CLI always
// supplies the immutable production profile through ValidateRuntimeInventory.
bool ObserveReconState(const RuntimeInventory&, std::uintptr_t hostBase,
    std::uint32_t hostImageSize, const ReconProfile&, ExpectedReconState,
    ReconObservation*, std::string* error);
const char* ObservedReconName(ObservedReconState) noexcept;
}
