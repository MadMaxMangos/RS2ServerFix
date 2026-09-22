#pragma once
#include "file_evidence.h"
namespace rs2fix::tooling {
enum class ArtifactKind { Bootstrap, CompanionPassive, CompanionActive, Harness,
    FixtureBootstrap, FixtureCompanionPassive, FixtureCompanionActive,
    MissingGenuineBootstrap, StartupFixture, CompanionObserver,
    FixtureCompanionObserver, ObserverStartupFixture, CompanionReporting,
    FixtureCompanionReporting, ReportingStartupFixture };
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
// Structural descriptor only; caller must still qualify artifact version/hash
// before reading live status. PE exports do not encode a C++ object's size, so
// this verifies the full shared StatusWire extent in image data, not contents.
// Valid zero-filled data is permitted; no raw file bytes are required for it.
bool ReportingStatusExport(const pe::Image&, std::uint32_t* rva) noexcept;
}
