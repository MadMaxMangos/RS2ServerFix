#include "pe_contract_lib.h"
#include "tool_paths.h"
#include <algorithm>
#include <set>
namespace rs2fix::tooling {
namespace {
std::string Lower(std::string value) {
    for (char& ch : value) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch + ('a' - 'A'));
    return value;
}
void Require(bool condition, const char* finding, ContractReport* report) {
    if (!condition) report->findings.emplace_back(finding);
}
bool IsBootstrap(ArtifactKind kind) {
    return kind == ArtifactKind::Bootstrap || kind == ArtifactKind::FixtureBootstrap || kind == ArtifactKind::MissingGenuineBootstrap;
}
bool IsExecutable(ArtifactKind kind) { return kind == ArtifactKind::Harness || kind == ArtifactKind::StartupFixture; }
const wchar_t* Description(ArtifactKind kind) {
    switch (kind) {
    case ArtifactKind::Bootstrap: return L"RS2ServerFix X3Audio Startup Bootstrap";
    case ArtifactKind::CompanionPassive: return L"RS2ServerFix M1R Passive Companion";
    case ArtifactKind::CompanionActive: return L"RS2ServerFix M2 Active Companion";
    case ArtifactKind::Harness: return L"RS2ServerFix X3Audio Static Import Harness";
    case ArtifactKind::FixtureBootstrap: return L"RS2ServerFix Test Fixture Bootstrap";
    case ArtifactKind::FixtureCompanionPassive: return L"RS2ServerFix Test Fixture M1R Passive Companion";
    case ArtifactKind::FixtureCompanionActive: return L"RS2ServerFix Test Fixture M2 Active Companion";
    case ArtifactKind::MissingGenuineBootstrap: return L"RS2ServerFix Test Fixture Missing Genuine Bootstrap";
    case ArtifactKind::StartupFixture: return L"RS2ServerFix Test Fixture Startup Host";
    }
    return L"";
}
bool CodeExport(const pe::Image& image, const pe::ExportSymbol& symbol) {
    const auto* section = pe::FindSection(image, symbol.rva, 1);
    std::size_t raw = 0;
    return symbol.rva != 0 && symbol.forwarder.empty() && section &&
        (section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 && pe::MapImageRva(image, symbol.rva, 1, &raw);
}
void CheckExports(const pe::Image& image, bool bootstrap, ContractReport* report) {
    const std::size_t count = bootstrap ? 2 : 1;
    Require(image.exportFunctionCount == count && image.exports.size() == count, "export_count_mismatch", report);
    bool calculate = false, initialize = false, companion = false;
    for (const auto& symbol : image.exports) {
        Require(CodeExport(image, symbol), "export_not_direct_code", report);
        if (bootstrap && symbol.name == "X3DAudioCalculate" && symbol.ordinal == 1) calculate = true;
        else if (bootstrap && symbol.name == "X3DAudioInitialize" && symbol.ordinal == 2) initialize = true;
        else if (!bootstrap && symbol.name == "RS2ServerFix_InitializeV3" && symbol.ordinal == 1) companion = true;
        else Require(false, "unexpected_export", report);
    }
    Require(bootstrap ? calculate && initialize : companion, "required_export_missing", report);
}
}
bool ParseArtifactKind(std::wstring_view text, ArtifactKind* kind) noexcept {
    if (!kind) return false;
    constexpr std::pair<std::wstring_view, ArtifactKind> values[]{
        {L"bootstrap", ArtifactKind::Bootstrap}, {L"companion", ArtifactKind::CompanionPassive},
        {L"companion-passive", ArtifactKind::CompanionPassive}, {L"companion-active", ArtifactKind::CompanionActive},
        {L"harness", ArtifactKind::Harness}, {L"fixture-bootstrap", ArtifactKind::FixtureBootstrap},
        {L"fixture-companion-passive", ArtifactKind::FixtureCompanionPassive},
        {L"fixture-companion-active", ArtifactKind::FixtureCompanionActive},
        {L"missing-genuine-bootstrap", ArtifactKind::MissingGenuineBootstrap},
        {L"startup-fixture", ArtifactKind::StartupFixture}};
    for (const auto& value : values) if (value.first == text) { *kind = value.second; return true; }
    return false;
}
bool CheckArtifactContract(const wchar_t* path, ArtifactKind kind, ContractReport* report) {
    if (!report) return false;
    *report = {};
    std::string error;
    std::wstring normalized;
    if (!RequireAbsolutePlainFile(path, &normalized, &error) || !pe::ReadPeImage(normalized.c_str(), &report->image, &error)) {
        report->findings.push_back("parse:" + error); return false;
    }
    const auto& image = report->image;
    Require(image.machine == IMAGE_FILE_MACHINE_AMD64 && image.optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC,
        "image_not_amd64_pe32plus", report);
    Require(((image.characteristics & IMAGE_FILE_DLL) != 0) != IsExecutable(kind), "image_kind_mismatch", report);
    constexpr WORD flags = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    Require((image.dllCharacteristics & flags) == flags, "security_flags_missing", report);
    Require(image.tlsDirectoryRva == 0 && image.tlsDirectorySize == 0, "TLS_present", report);
    Require(image.delayImports.empty(), "delay_imports_present", report);
    std::set<std::string> expected{"kernel32.dll"};
    if (!IsBootstrap(kind) && kind != ArtifactKind::StartupFixture) expected.insert("bcrypt.dll");
    if (IsExecutable(kind)) expected.insert("x3daudio1_7.dll");
    std::set<std::string> actual;
    for (const auto& module : image.normalImports) {
        const std::string lower = Lower(module.name);
        Require(actual.insert(lower).second, "duplicate_import_module", report);
        Require(expected.count(lower) == 1, "disallowed_import_module", report);
        Require(!module.symbols.empty(), "empty_import_module", report);
    }
    Require(actual == expected, "direct_import_set_mismatch", report);
    if (!IsExecutable(kind)) CheckExports(image, IsBootstrap(kind), report);
    else {
        bool found = false;
        for (const auto& module : image.normalImports) {
            if (Lower(module.name) != "x3daudio1_7.dll") continue;
            found = true;
            Require(module.symbols.size() == 1 && !module.symbols[0].byOrdinal &&
                module.symbols[0].name == "X3DAudioInitialize", "X3_named_initializer_import_mismatch", report);
        }
        Require(found, "X3_import_missing", report);
    }
    if (!ReadVersionIdentity(normalized.c_str(), &report->version, &error)) report->findings.push_back("version:" + error);
    else {
        const auto& version = report->version;
        const VersionQuad expectedVersion{0, 2, 0, 0};
        Require(version.fileVersion == expectedVersion && version.productVersion == expectedVersion &&
            version.fileVersionText == L"0.2.0.0" && version.productVersionText == L"0.2.0.0", "version_mismatch", report);
        Require(version.translations.size() == 1 && version.translations[0] == std::pair<WORD, WORD>{WORD{0x0409}, WORD{0x04B0}},
            "version_translation_mismatch", report);
        Require(version.companyName == L"RS2ServerFix Project" && version.productName == L"RS2ServerFix" &&
            version.fileDescription == Description(kind), "version_authorship_or_mode_mismatch", report);
        const wchar_t* original = IsBootstrap(kind) ? L"X3DAudio1_7.dll" :
            kind == ArtifactKind::Harness ? L"rs2_static_import_harness.exe" :
            kind == ArtifactKind::StartupFixture ? L"rs2_startup_fixture.exe" : L"RS2ServerFix.dll";
        Require(version.originalFilename == original, "version_original_filename_mismatch", report);
    }
    report->passed = report->findings.empty();
    return report->passed;
}
bool CheckBootstrapContract(const wchar_t* path, ContractReport* report) { return CheckArtifactContract(path, ArtifactKind::Bootstrap, report); }
bool CheckCompanionContract(const wchar_t* path, ContractReport* report) { return CheckArtifactContract(path, ArtifactKind::CompanionPassive, report); }
bool CheckHarnessContract(const wchar_t* path, ContractReport* report) { return CheckArtifactContract(path, ArtifactKind::Harness, report); }
}
