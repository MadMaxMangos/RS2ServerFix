#include "runtime_inventory.h"
#include "tool_paths.h"
#include "companion/sha256.h"
#include <iostream>
#include <map>

int wmain(int argc, wchar_t** argv) {
    using namespace rs2fix; using namespace rs2fix::tooling;
    constexpr const wchar_t* help = L"rs2_runtime_inventory --pid <nonzero decimal DWORD> --target-root <absolute plain directory> --expect <system-control|proxy-pass> --mode <passive|active> --expected-recon <original|corrected> --bootstrap-sha256 <64 uppercase hex> --companion-sha256 <64 uppercase hex> --genuine-manifest <absolute plain file> --report <absolute new file outside target root> [--companion-kind <companion-observer|companion-reporting>]\nObserver/reporting selection requires active, corrected, proxy-pass. Default selects the ordinary recon companion.\nReporting DATA status is separate from the recon/artifact result and never proves backend recovery.\nRead-only reader: security rejection is a compatibility failure; no bypass.\n";
    if (argc == 2 && std::wstring_view(argv[1]) == L"--help") { std::wcout << help; return 0; }
    for (int i = 1; i < argc; ++i) if (std::wstring_view(argv[i]) == L"--help") { std::wcerr << help; return 2; }
    if (argc != 19 && argc != 21) { std::wcerr << help; return 2; }
    std::map<std::wstring, std::wstring> args;
    for (int i = 1; i < argc; i += 2) if (!args.emplace(argv[i], argv[i + 1]).second) return 2;
    constexpr const wchar_t* keys[] = { L"--pid", L"--target-root", L"--expect", L"--mode", L"--expected-recon", L"--bootstrap-sha256", L"--companion-sha256", L"--genuine-manifest", L"--report" };
    for (const auto* key : keys) if (args.find(key) == args.end()) return 2;
    RuntimeValidationInputs in;
    if (argc == 21) {
        const auto selection = args.find(L"--companion-kind");
        if (selection == args.end()) return 2;
        if (selection->second == L"companion-observer") in.observerCompanion = true;
        else if (selection->second == L"companion-reporting") in.reportingCompanion = true;
        else return 2;
    }
    const auto& pid = args[L"--pid"];
    if (pid.empty() || pid.size() > 10 || (pid.size() > 1 && pid.front() == L'0')) return 2;
    for (wchar_t c : pid) {
        if (c < L'0' || c > L'9' || in.processId > (MAXDWORD - static_cast<DWORD>(c - L'0')) / 10) return 2;
        in.processId = in.processId * 10 + static_cast<DWORD>(c - L'0');
    }
    if (!in.processId) return 2;
    if (args[L"--expect"] == L"system-control") in.expectation = RuntimeExpectation::SystemControl;
    else if (args[L"--expect"] == L"proxy-pass") in.expectation = RuntimeExpectation::ProxyPass;
    else return 2;
    if (!ParseDeploymentMode(args[L"--mode"], &in.mode)) return 2;
    if (args[L"--expected-recon"] == L"original") in.expectedRecon = ExpectedReconState::Original;
    else if (args[L"--expected-recon"] == L"corrected") in.expectedRecon = ExpectedReconState::Corrected;
    else return 2;
    if ((in.expectation == RuntimeExpectation::SystemControl || in.mode == DeploymentMode::Passive) && in.expectedRecon != ExpectedReconState::Original) return 2;
    if (in.expectation == RuntimeExpectation::ProxyPass && in.mode == DeploymentMode::Active && in.expectedRecon != ExpectedReconState::Corrected) return 2;
    if ((in.observerCompanion || in.reportingCompanion) && (in.expectation != RuntimeExpectation::ProxyPass || in.mode != DeploymentMode::Active || in.expectedRecon != ExpectedReconState::Corrected)) return 2;
    auto digest = [&](const wchar_t* key, Sha256Digest* value) {
        const auto& text = args[key];
        std::string ascii;
        for (wchar_t c : text) { if (c > 127) return false; ascii.push_back(static_cast<char>(c)); }
        return ParseSha256Upper(ascii, value);
    };
    if (!digest(L"--bootstrap-sha256", &in.bootstrapSha256) || !digest(L"--companion-sha256", &in.companionSha256)) return 2;
    std::wstring manifestPath, toolPath; std::string error; wchar_t self[kPathCapacity]{}; DWORD code{};
    if (!RequireAbsolutePlainDirectory(args[L"--target-root"].c_str(), &in.targetRoot, &error) ||
        !RequireAbsolutePlainFile(args[L"--genuine-manifest"].c_str(), &manifestPath, &error) ||
        !RequireAbsoluteNewFileOutsideRoot(args[L"--report"].c_str(), in.targetRoot, &in.reportPath, &error) ||
        !GetBoundedModulePath(nullptr, self, std::size(self), &code) || !RequireAbsolutePlainFile(self, &toolPath, &error) ||
        IsPathWithin(in.targetRoot, manifestPath, true) || IsPathWithin(in.targetRoot, toolPath, true)) { std::cerr << "usage-or-path-invalid\n"; return 2; }
    if (!ReadGenuineManifest(manifestPath.c_str(), &in.genuineManifest, &in.genuineManifestSha256, &error)) { std::cerr << "manifest-invalid\n"; return 2; }
    const auto hash = HashFileSha256(toolPath.c_str(), GetTickCount64() + 10000);
    if (!hash.digestValid) { std::cerr << "tool-hash-failed\n"; return 2; }
    in.toolSha256 = hash.digest;
    RuntimeInventory inventory; RuntimeValidationResult result;
    if (!CaptureStableRuntimeInventory(in.processId, ProductionRuntimeInventoryOps(), &inventory, &error)) result.findings.push_back(error);
    else ValidateRuntimeInventory(inventory, in, &result);
    if (in.reportingCompanion && inventory.process) {
        const RuntimeModule* companion = nullptr;
        bool ambiguous = false;
        for (const auto& module : inventory.modules) {
            if (!EqualEvidencePath(EvidenceLeaf(module.fullPath), L"RS2ServerFix.dll")) continue;
            if (companion) ambiguous = true;
            companion = &module;
        }
        if (companion && !ambiguous) {
            std::string statusError;
            if (!ReadReportingStatus(inventory, *companion, result.hostSha256,
                    in.companionSha256, &result.reporting, &statusError))
                result.reporting.detail = statusError;
        } else result.reporting.detail = "reporting-companion-missing-or-ambiguous";
    }
    if (!WriteRuntimeInventoryReport(inventory, in, result, ProductionEvidenceFileOps(), &error)) { std::cerr << "report-write-failed:" << EncodeEvidenceText(error) << '\n'; return 1; }
    for (const auto& finding : result.findings) std::cout << EncodeEvidenceText(finding) << '\n';
    if (in.reportingCompanion) std::cout << "reporting_status=" << ReportingStatusStateName(result.reporting.state)
        << "\nreporting_current_ready=" << (result.reporting.currentReady ? "true" : "false") << '\n';
    std::cout << "result=" << (result.passed ? "pass" : "unsafe") << '\n'; return result.passed ? 0 : 1;
}
