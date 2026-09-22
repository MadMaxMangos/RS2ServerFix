#include "test_framework.h"
#include "pe_contract_lib.h"
#include "shared/steam_reporting_status.h"

namespace {
rs2fix::pe::Image ReportingImage() {
    rs2fix::pe::Image image;
    image.sizeOfImage = 0x5000;
    image.sections.push_back({".text", 0x1000, 0x1000, 0x400, 0x1000,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE});
    // StatusWire can occupy the virtual zero-filled data tail, so the data
    // descriptor must not accidentally require 1288 raw file-backed bytes.
    image.sections.push_back({".data", 0x3000, 0x1000, 0, 0,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE});
    image.exports.push_back({"RS2ServerFix_InitializeV3", 1, 0x1100, {}});
    image.exports.push_back({"RS2SteamReport_StatusV2", 2, 0x3100, {}});
    image.exportFunctionCount = 2;
    return image;
}
void ReportingContractChecks() {
    using namespace rs2fix::tooling;
    ArtifactKind kind{};
    RS2_CHECK(ParseArtifactKind(L"companion-reporting", &kind) && kind == ArtifactKind::CompanionReporting);
    RS2_CHECK(ParseArtifactKind(L"fixture-companion-reporting", &kind) && kind == ArtifactKind::FixtureCompanionReporting);
    RS2_CHECK(ParseArtifactKind(L"companion-observer", &kind) && kind == ArtifactKind::CompanionObserver);
    RS2_CHECK(ParseArtifactKind(L"companion-active", &kind) && kind == ArtifactKind::CompanionActive);
    RS2_CHECK(!ParseArtifactKind(L"companion-report", &kind));
    auto valid = ReportingImage();
    std::uint32_t rva{};
    RS2_CHECK(ReportingStatusExport(valid, &rva) && rva == 0x3100);
    RS2_CHECK(!ReportingStatusExport(valid, nullptr));
    valid.exports[1].rva = 0x4000 - static_cast<std::uint32_t>(sizeof(rs2fix::reporting::StatusWire));
    RS2_CHECK(ReportingStatusExport(valid, &rva)); // Exact virtual-section end.
    for (unsigned fault = 0; fault < 15; ++fault) {
        auto image = ReportingImage();
        switch (fault) {
        case 0: image.exports[1].forwarder = "OTHER.status"; break;
        case 1: image.exports[1].ordinal = 3; break;
        case 2: image.exports[1].name = "RS2SteamReport_StatusV1"; break;
        case 3: image.exports.push_back(image.exports[1]); break;
        case 4: image.exports[0].ordinal = 2; break;
        case 5: image.exports[1].rva += 4; break;
        case 6: image.exports[1].rva = 0; break;
        case 7: image.exports[1].rva = 0x3F00; break;
        case 8: image.sizeOfImage = 0x3400; break;
        case 9: image.sections[1].characteristics &= ~IMAGE_SCN_MEM_WRITE; break;
        case 10: image.sections[1].characteristics |= IMAGE_SCN_MEM_EXECUTE; break;
        case 11: image.sections[1].characteristics |= IMAGE_SCN_MEM_DISCARDABLE; break;
        case 12: image.sections[1].virtualSize = 0x200; image.sections[1].rawSize = 0x2000; break;
        case 13: image.sections.push_back({".overlap", 0x3200, 0x100, 0, 0,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE}); break;
        case 14: image.exports[1].rva = UINT32_MAX - 7; image.sizeOfImage = UINT32_MAX; break;
        }
        rva = 123;
        RS2_CHECK(!ReportingStatusExport(image, &rva) && rva == 0);
    }
}
}
namespace rs2fix::testcases { void RunProfileEvidenceTests(); void RunObserverFileProfileTests(); }
int main() {
    ReportingContractChecks();
    rs2fix::testcases::RunProfileEvidenceTests();
    rs2fix::testcases::RunObserverFileProfileTests();
    std::cout << "checks=" << rs2fix::test::g_checks << " failures=" << rs2fix::test::g_failures << '\n';
    return rs2fix::test::g_failures ? 1 : 0;
}
