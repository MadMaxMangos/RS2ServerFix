#pragma once
#include "file_evidence.h"
namespace rs2fix::tooling {
enum class ArtifactKind { Bootstrap, CompanionPassive, CompanionActive, Harness,
    FixtureBootstrap, FixtureCompanionPassive, FixtureCompanionActive,
    MissingGenuineBootstrap, StartupFixture };
struct ContractReport {
    bool passed{};
    pe::Image image{};
    VersionIdentity version{};
    std::vector<std::string> findings;
};
bool CheckArtifactContract(const wchar_t* path, ArtifactKind kind,
                            ContractReport* report);
bool CheckBootstrapContract(const wchar_t* path, ContractReport* report);
bool CheckCompanionContract(const wchar_t* path, ContractReport* report);
bool CheckHarnessContract(const wchar_t* path, ContractReport* report);
bool ParseArtifactKind(std::wstring_view text, ArtifactKind* kind) noexcept;
}
