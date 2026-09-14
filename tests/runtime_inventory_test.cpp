#include "runtime_inventory.h"
#include "companion/sha256.h"
#include "test_framework.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <functional>

namespace rs2fix::testcases {
namespace {
using namespace tooling;
struct Fake {
    std::vector<std::vector<RawRuntimeModule>> snapshots;
    std::vector<DWORD> snapshotErrors;
    std::size_t enumerations{}, identityCalls{}, closes{}, reads{}, queries{};
    DWORD identityFailure{};
    bool openDenied{}, badPe{}, identityChanged{}, processChanged{}, readFailed{}, shortRead{}, constantBad{}, exitAfterRead{};
    RuntimeProcessIdentity identity{100, 1000000, L"C:\\own-fixture\\host.exe"};
    std::array<std::uint8_t, 641> code{};
    std::array<std::uint8_t, 16> constant{};
    Fake() {
        const std::vector<RawRuntimeModule> one{{0x100000, 0x4000, identity.imagePath}};
        snapshots = {one, one, one};
        for (std::size_t i = 0; i < code.size(); ++i) code[i] = static_cast<std::uint8_t>(i);
        constant.fill(42);
    }
};
HANDLE Open(void* opaque, DWORD pid, DWORD* error) {
    auto& f = *static_cast<Fake*>(opaque); *error = f.openDenied ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
    return !f.openDenied && pid == f.identity.processId ? reinterpret_cast<HANDLE>(1) : nullptr;
}
void Close(void* opaque, HANDLE) noexcept { ++static_cast<Fake*>(opaque)->closes; }
bool Process(void* opaque, HANDLE handle, RuntimeProcessIdentity* identity, DWORD* error) {
    auto& f = *static_cast<Fake*>(opaque); ++f.queries; *identity = f.identity; *error = ERROR_SUCCESS;
    RS2_CHECK(handle == reinterpret_cast<HANDLE>(1));
    if (f.processChanged && f.queries > 2) ++identity->creationTime;
    return !(f.exitAfterRead && f.reads > 0);
}
bool Enumerate(void* opaque, HANDLE handle, DWORD pid, std::vector<RawRuntimeModule>* modules, DWORD* error) {
    auto& f = *static_cast<Fake*>(opaque); RS2_CHECK(handle == reinterpret_cast<HANDLE>(1)); RS2_CHECK(pid == f.identity.processId);
    const auto index = f.enumerations++;
    *error = index < f.snapshotErrors.size() ? f.snapshotErrors[index] : ERROR_SUCCESS;
    if (*error) return false;
    if (index >= f.snapshots.size()) return false;
    *modules = f.snapshots[index]; return true;
}
bool Identity(void* opaque, const wchar_t*, FileIdentity* identity, DWORD* error) {
    auto& f = *static_cast<Fake*>(opaque); ++f.identityCalls;
    if (f.identityFailure) { *error = f.identityFailure; return false; }
    *identity = {1, 2, 3, true}; *error = ERROR_SUCCESS;
    if (f.identityChanged && f.identityCalls == 2) ++identity->fileIndexLow;
    return true;
}
bool Pe(void* opaque, const wchar_t* path, pe::Image* image, std::string*) {
    auto& f = *static_cast<Fake*>(opaque);
    *image = {}; image->machine = IMAGE_FILE_MACHINE_AMD64; image->optionalMagic = IMAGE_NT_OPTIONAL_HDR64_MAGIC; image->sizeOfImage = 0x4000;
    for (const auto& module : f.snapshots[f.enumerations - 1]) if (EqualEvidencePath(path, module.fullPath)) image->sizeOfImage = module.imageSize;
    return !f.badPe;
}
bool Read(void* opaque, HANDLE handle, std::uintptr_t address, void* output, std::size_t size, std::size_t* actual, DWORD* error) {
    auto& f = *static_cast<Fake*>(opaque); ++f.reads; RS2_CHECK(handle == reinterpret_cast<HANDLE>(1));
    *actual = f.shortRead ? size - 1 : size; *error = f.readFailed ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
    if (f.readFailed) return false;
    if (address == 0x100100 && size == f.code.size()) std::memcpy(output, f.code.data(), size);
    else if (address == 0x101000 && size == f.constant.size()) { std::memcpy(output, f.constant.data(), size); if (f.constantBad) static_cast<std::uint8_t*>(output)[0] ^= 1; }
    else { *actual = 0; *error = ERROR_PARTIAL_COPY; return false; }
    return true;
}
RuntimeInventoryOps Ops(Fake& f) { return {&f, Open, Close, Process, Enumerate, Identity, Pe, Read, ProductionEvidenceFileOps()}; }
ReconProfile Profile(const Fake& f) {
    ReconProfile p{}; p.functionRva = 0x100; p.functionSize = 641; p.constantRva = 0x1000; p.constantBytes = f.constant;
    RS2_CHECK(HashBytesSha256(f.code.data(), f.code.size(), &p.originalDigest));
    auto corrected = f.code; corrected[0] ^= 1; RS2_CHECK(HashBytesSha256(corrected.data(), corrected.size(), &p.correctedDigest));
    return p;
}
void CaptureCase(const std::function<void(Fake&)>& modify, bool expected, std::size_t attempts, const char* reason = nullptr) {
    Fake f; modify(f); RuntimeInventory inventory; std::string error;
    const bool ok = CaptureStableRuntimeInventory(100, Ops(f), &inventory, &error);
    RS2_CHECK(ok == expected); RS2_CHECK(f.enumerations == attempts);
    if (reason) RS2_CHECK(error.find(reason) != error.npos);
    inventory = {}; RS2_CHECK(f.closes == (f.openDenied ? 0U : 1U));
}
struct ValidationFake {
    Sha256Digest host{kProductionReconProfile.hostDigest}, bootstrap{}, companion{}, genuine{};
    bool badHash{}, badGenuine{}, badSignature{}, badContract{}, changedIdentity{};
    ValidationFake() { bootstrap[0] = 1; companion[0] = 2; genuine[0] = 3; }
};
bool VSystem(void*, std::wstring* path, FileIdentity* identity) { *path = L"C:\\Windows\\System32\\X3DAudio1_7.dll"; *identity = {1,2,3,true}; return true; }
bool VHash(void* context, const RuntimeModule& module, Sha256Digest* digest) {
    auto& f = *static_cast<ValidationFake*>(context);
    if (EqualEvidencePath(EvidenceLeaf(module.fullPath), L"host.exe")) *digest = f.host;
    else if (EqualEvidencePath(EvidenceLeaf(module.fullPath), L"RS2ServerFix.dll")) *digest = f.companion;
    else *digest = f.bootstrap;
    if (f.badHash) (*digest)[0] ^= 0x80; return true;
}
bool VIdentity(void* context, const wchar_t*, FileIdentity* identity, DWORD* error) {
    *identity = {1,2,3,true}; *error = ERROR_SUCCESS;
    if (static_cast<ValidationFake*>(context)->changedIdentity) ++identity->fileIndexLow; return true;
}
bool VEvidence(void* context, const wchar_t*, FileEvidence* evidence, std::string*) {
    auto& f = *static_cast<ValidationFake*>(context); *evidence = {};
    evidence->sha256 = f.genuine; evidence->fileSize = 0x2100;
    auto& image = evidence->image; image.machine = IMAGE_FILE_MACHINE_AMD64; image.optionalMagic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    image.characteristics = IMAGE_FILE_DLL; image.sizeOfImage = 0x4000; image.coffTimestamp = 1; image.exportFunctionCount = 2;
    image.exports = {{"X3DAudioCalculate", 1, 0x100, {}}, {"X3DAudioInitialize", 2, 0x200, {}}};
    image.sections.push_back({".text", 0x100, 0x2000, 0x100, 0x2000, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ});
    image.rawBytes.resize(0x2100, 0xC3);
    if (f.badGenuine) evidence->sha256[0] ^= 0x80; return true;
}
EmbeddedSignatureResult VSignature(void* context, const wchar_t*) { return {static_cast<ValidationFake*>(context)->badSignature ? TRUST_E_NOSIGNATURE : ERROR_SUCCESS, ERROR_SUCCESS, true}; }
bool VContract(void* context, const wchar_t*, ArtifactKind, ContractReport*) { return !static_cast<ValidationFake*>(context)->badContract; }
RuntimeValidationOps VOps(ValidationFake& f) { return {&f, VSystem, VHash, VIdentity, VEvidence, VSignature, VContract}; }
RuntimeModule Module(const wchar_t* path, std::uintptr_t base) {
    RuntimeModule module; module.base = base; module.imageSize = 0x4000; module.fullPath = path;
    module.fileIdentity = {1,2,3,true}; module.image.machine = IMAGE_FILE_MACHINE_AMD64; module.image.optionalMagic = IMAGE_NT_OPTIONAL_HDR64_MAGIC; module.image.sizeOfImage = module.imageSize;
    return module;
}
void ValidationCase(bool proxy, bool expected,
    const std::function<void(RuntimeInventory&, RuntimeValidationInputs&, ValidationFake&, Fake&)>& modify) {
    Fake process; RuntimeInventory inventory; std::string error;
    RS2_CHECK(CaptureStableRuntimeInventory(100, Ops(process), &inventory, &error));
    inventory.modules[0].image.normalImports.push_back({"X3DAudio1_7.dll", {{false,0,"X3DAudioInitialize",0}}});
    inventory.modules.push_back(Module(L"C:\\Windows\\System32\\X3DAudio1_7.dll", 0x200000));
    if (proxy) {
        inventory.modules.push_back(Module(L"C:\\own-fixture\\X3DAudio1_7.dll", 0x300000));
        inventory.modules.push_back(Module(L"C:\\own-fixture\\RS2ServerFix.dll", 0x400000));
    }
    ValidationFake files; RuntimeValidationInputs in;
    in.processId = 100; in.targetRoot = L"C:\\own-fixture"; in.expectation = proxy ? RuntimeExpectation::ProxyPass : RuntimeExpectation::SystemControl;
    in.bootstrapSha256 = files.bootstrap; in.companionSha256 = files.companion;
    GenuineManifestEntry entry; entry.state = ManifestState::Qualified; entry.sha256 = files.genuine; entry.fileSize = 0x2100; entry.coffTimestamp = 1; entry.sizeOfImage = 0x4000;
    in.genuineManifest.entries.push_back(entry);
    const auto profile = Profile(process); modify(inventory, in, files, process);
    RuntimeValidationResult result;
    const bool ok = ValidateRuntimeInventoryWithOps(inventory, in, VOps(files), profile, &result);
    if (ok != expected) for (const auto& finding : result.findings) std::cerr << "validation-case: " << finding << '\n';
    RS2_CHECK(ok == expected); RS2_CHECK(result.passed == expected);
    if (!expected) RS2_CHECK(!result.findings.empty());
}
struct ReportFake { std::string bytes; bool shortWrite{}, removed{}; };
HANDLE ReportCreate(void*, const wchar_t*, DWORD*) noexcept { return reinterpret_cast<HANDLE>(2); }
bool ReportWrite(void* context, HANDLE, const void* bytes, DWORD size, DWORD* written, DWORD*) noexcept {
    auto& f = *static_cast<ReportFake*>(context); *written = f.shortWrite ? 0 : size;
    f.bytes.append(static_cast<const char*>(bytes), *written); return !f.shortWrite;
}
bool ReportFlush(void*, HANDLE, DWORD*) noexcept { return true; }
bool ReportClose(void*, HANDLE, DWORD*) noexcept { return true; }
bool ReportRemove(void* context, const wchar_t*, DWORD*) noexcept { static_cast<ReportFake*>(context)->removed = true; return true; }
}
void RunRuntimeInventoryTests() {
    CaptureCase([](auto&) {}, true, 2);
    CaptureCase([](auto& f) { f.snapshots[0][0].base += 0x10000; }, true, 3);
    CaptureCase([](auto& f) { f.snapshots[1][0].base += 0x10000; f.snapshots[2][0].base += 0x20000; }, false, 3, "unstable");
    CaptureCase([](auto& f) { f.snapshots[0][0].imageSize += 0x1000; }, true, 3);
    CaptureCase([](auto& f) { f.snapshots[0][0].fullPath = L"C:\\own-fixture\\other.exe"; }, true, 3);
    CaptureCase([](auto& f) { f.snapshotErrors = {ERROR_BAD_LENGTH, ERROR_SUCCESS, ERROR_SUCCESS}; }, true, 3);
    CaptureCase([](auto& f) { f.snapshotErrors = {ERROR_BAD_LENGTH, ERROR_BAD_LENGTH, ERROR_BAD_LENGTH}; }, false, 3, "unstable");
    CaptureCase([](auto& f) { f.snapshotErrors = {ERROR_ACCESS_DENIED}; }, false, 1, "compatibility-failure-no-bypass");
    CaptureCase([](auto& f) { f.identityChanged = true; }, true, 3);
    CaptureCase([](auto& f) { f.openDenied = true; }, false, 0, "compatibility-failure-no-bypass");
    CaptureCase([](auto& f) { f.processChanged = true; }, false, 1, "identity-changed");
    CaptureCase([](auto& f) { f.identityFailure = ERROR_FILE_NOT_FOUND; }, false, 3, "unstable");
    CaptureCase([](auto& f) { f.identityFailure = ERROR_ACCESS_DENIED; }, false, 1, "unreadable-or-reparse");
    CaptureCase([](auto& f) { f.identityFailure = ERROR_INVALID_NAME; }, false, 1, "unreadable-or-reparse");
    CaptureCase([](auto& f) { f.badPe = true; }, false, 1, "pe-incomplete");
    CaptureCase([](auto& f) { f.snapshots[0][0].fullPath.clear(); }, false, 1, "path-base-or-size");
    CaptureCase([](auto& f) { f.snapshots[0][0].base = 0; }, false, 1, "path-base-or-size");
    CaptureCase([](auto& f) { f.snapshots[0].push_back(f.snapshots[0][0]); }, false, 1, "path-base-or-size");
    CaptureCase([](auto& f) { f.snapshots[0].resize(4096, f.snapshots[0][0]); }, false, 1, "count-incomplete");
    Fake f; RuntimeInventory inventory; std::string error; RS2_CHECK(CaptureStableRuntimeInventory(100, Ops(f), &inventory, &error));
    const auto profile = Profile(f); ReconObservation observation;
    RS2_CHECK(ObserveReconState(inventory, 0x100000, 0x4000, profile, ExpectedReconState::Original, &observation, &error));
    RS2_CHECK(observation.state == ObservedReconState::Original && observation.constantsMatch && f.reads == 2);
    f.code[0] ^= 1;
    RS2_CHECK(ObserveReconState(inventory, 0x100000, 0x4000, profile, ExpectedReconState::Corrected, &observation, &error));
    RS2_CHECK(observation.state == ObservedReconState::Corrected);
    RS2_CHECK(!ObserveReconState(inventory, 0x100000, 0x4000, profile, ExpectedReconState::Original, &observation, &error));
    f.code[0] ^= 2;
    RS2_CHECK(!ObserveReconState(inventory, 0x100000, 0x4000, profile, ExpectedReconState::Original, &observation, &error));
    RS2_CHECK(observation.state == ObservedReconState::Unexpected);
    f.code[0] ^= 3; f.constantBad = true;
    RS2_CHECK(!ObserveReconState(inventory, 0x100000, 0x4000, profile, ExpectedReconState::Original, &observation, &error));
    RS2_CHECK(error == "recon-constant-mismatch");
    f.constantBad = false; f.readFailed = true;
    RS2_CHECK(!ObserveReconState(inventory, 0x100000, 0x4000, profile, ExpectedReconState::Original, &observation, &error));
    RS2_CHECK(error.find("compatibility-failure-no-bypass") != error.npos);
    f.readFailed = false; f.shortRead = true;
    RS2_CHECK(!ObserveReconState(inventory, 0x100000, 0x4000, profile, ExpectedReconState::Original, &observation, &error));
    f.shortRead = false; f.exitAfterRead = true; f.reads = 0;
    RS2_CHECK(!ObserveReconState(inventory, 0x100000, 0x4000, profile, ExpectedReconState::Original, &observation, &error));
    RS2_CHECK(error == "process-exited-or-identity-changed"); f.exitAfterRead = false;
    auto invalid = profile; invalid.functionSize = 642;
    RS2_CHECK(!ObserveReconState(inventory, 0x100000, 0x4000, invalid, ExpectedReconState::Original, &observation, &error));
    RS2_CHECK(!ObserveReconState(inventory, UINTPTR_MAX - 10, 0x4000, profile, ExpectedReconState::Original, &observation, &error));
    RS2_CHECK(!ObserveReconState(inventory, 0x100000, 0x1001, profile, ExpectedReconState::Original, &observation, &error));
    pe::Image host; pe::ImportModule normal; normal.name = "X3DAudio1_7.dll"; normal.symbols.push_back({false, 0, "X3DAudioInitialize", 0}); host.normalImports.push_back(normal);
    RS2_CHECK(HasRequiredHostImports(host)); host.delayImports.push_back(normal); RS2_CHECK(!HasRequiredHostImports(host)); host.delayImports.clear();
    host.normalImports[0].symbols.push_back({false, 0, "X3DAudioCalculate", 0}); RS2_CHECK(!HasRequiredHostImports(host));
    host.normalImports[0].symbols.resize(1); host.normalImports[0].symbols[0].byOrdinal = true; RS2_CHECK(!HasRequiredHostImports(host));
    RuntimeValidationInputs inputs; inputs.processId = 100; inputs.targetRoot = L"C:\\wrong-root"; RuntimeValidationResult result;
    RS2_CHECK(!ValidateRuntimeInventory(inventory, inputs, &result)); RS2_CHECK(!result.findings.empty());
    auto unchanged = [](auto&, auto&, auto&, auto&) {};
    ValidationCase(false, true, unchanged);
    ValidationCase(true, true, unchanged);
    ValidationCase(true, true, [](auto&, auto& in, auto&, auto& process) { in.mode = DeploymentMode::Active; in.expectedRecon = ExpectedReconState::Corrected; process.code[0] ^= 1; });
    ValidationCase(true, false, [](auto&, auto& in, auto&, auto&) { in.mode = DeploymentMode::Active; });
    ValidationCase(false, false, [](auto&, auto& in, auto&, auto&) { in.expectedRecon = ExpectedReconState::Corrected; });
    ValidationCase(true, false, [](auto& inv, auto&, auto&, auto&) { inv.modules.pop_back(); });
    ValidationCase(false, false, [](auto& inv, auto&, auto&, auto&) { inv.modules.push_back(Module(L"C:\\own-fixture\\RS2ServerFix.dll", 0x400000)); });
    ValidationCase(false, false, [](auto& inv, auto&, auto&, auto&) { auto renamed = Module(L"C:\\own-fixture\\renamed.dll", 0x500000); renamed.x3audioExports = true; inv.modules.push_back(renamed); });
    ValidationCase(true, false, [](auto& inv, auto&, auto&, auto&) { auto renamed = Module(L"C:\\own-fixture\\renamed-fix.dll", 0x500000); renamed.companionExports = true; inv.modules.push_back(renamed); });
    ValidationCase(false, false, [](auto& inv, auto&, auto&, auto&) { inv.modules[1].fullPath = L"C:\\elsewhere\\X3DAudio1_7.dll"; });
    ValidationCase(true, false, [](auto& inv, auto&, auto&, auto&) { inv.modules.push_back(Module(L"C:\\extra\\X3DAudio1_7.dll", 0x500000)); });
    ValidationCase(false, false, [](auto& inv, auto&, auto&, auto&) { inv.modules[1].image.delayImports = inv.modules[0].image.normalImports; });
    ValidationCase(false, false, [](auto& inv, auto&, auto&, auto&) { inv.modules[1].image.normalImports = inv.modules[0].image.normalImports; });
    ValidationCase(false, false, [](auto& inv, auto&, auto&, auto&) { inv.modules[0].image.normalImports[0].symbols[0].byOrdinal = true; });
    ValidationCase(false, false, [](auto& inv, auto&, auto&, auto&) { inv.modules[0].image.tlsDirectoryRva = 1; });
    ValidationCase(false, false, [](auto&, auto&, auto& files, auto&) { files.badHash = true; });
    ValidationCase(true, false, [](auto&, auto& in, auto&, auto&) { ++in.bootstrapSha256[0]; });
    ValidationCase(true, false, [](auto&, auto& in, auto&, auto&) { ++in.companionSha256[0]; });
    ValidationCase(true, false, [](auto&, auto&, auto& files, auto&) { files.badContract = true; });
    ValidationCase(false, false, [](auto&, auto&, auto& files, auto&) { files.badGenuine = true; });
    ValidationCase(false, false, [](auto&, auto&, auto& files, auto&) { files.badSignature = true; });
    ValidationCase(false, false, [](auto&, auto&, auto& files, auto&) { files.changedIdentity = true; });
    ValidationCase(false, false, [](auto&, auto& in, auto&, auto&) { in.genuineManifest.entries[0].state = ManifestState::Provisional; });
    ValidationCase(true, false, [](auto& inv, auto&, auto&, auto&) { inv.modules.back().fullPath = L"C:\\elsewhere\\RS2ServerFix.dll"; });
    ValidationCase(true, false, [](auto&, auto&, auto&, auto& process) { process.shortRead = true; });
    wchar_t reportTemp[kPathCapacity]{};
    RS2_CHECK(GetTempPathW(static_cast<DWORD>(std::size(reportTemp)), reportTemp) != 0);
    const std::wstring reportRoot = std::wstring(reportTemp) + L"RS2.inventory.fixture.root." + std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(GetTickCount64());
    RS2_CHECK(CreateDirectoryW(reportRoot.c_str(), nullptr) != FALSE);
    inputs.targetRoot = reportRoot; inputs.reportPath = reportRoot + L".txt";
    inventory.modules.push_back(Module(L"C:\\Users\\private-account\\vendor-secret\\plugin.dll", 0x600000));
    ReportFake report;
    EvidenceFileOps reportOps{&report, ReportCreate, ReportWrite, ReportFlush, ReportClose, ReportRemove};
    RS2_CHECK(WriteRuntimeInventoryReport(inventory, inputs, result, reportOps, &error));
    RS2_CHECK(report.bytes.find("private-account") == report.bytes.npos && report.bytes.find("vendor-secret") == report.bytes.npos);
    RS2_CHECK(report.bytes.find("<OTHER>/plugin.dll#full_path_sha256=") != report.bytes.npos);
    RS2_CHECK(report.bytes.find("process_creation_filetime=1000000\r\n") != report.bytes.npos);
    report.shortWrite = true;
    RS2_CHECK(!WriteRuntimeInventoryReport(inventory, inputs, result, reportOps, &error)); RS2_CHECK(report.removed);
    inputs.reportPath = reportRoot + L"\\bad-report.txt";
    RS2_CHECK(!WriteRuntimeInventoryReport(inventory, inputs, result, reportOps, &error));
    RS2_CHECK(RemoveDirectoryW(reportRoot.c_str()) != FALSE);
    // Read-only production integration touches only this own-code test process.
    wchar_t system[512]{}; DWORD code{}; RS2_CHECK(BuildSystemX3AudioPath(system, std::size(system), &code));
    HMODULE genuine = LoadLibraryExW(system, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32); RS2_CHECK(genuine != nullptr);
    RuntimeInventory live;
    const bool captured = CaptureStableRuntimeInventory(GetCurrentProcessId(), ProductionRuntimeInventoryOps(), &live, &error);
    if (!captured) std::cerr << "own-process-inventory: " << error << '\n';
    RS2_CHECK(captured);
    bool hasSelf = false, hasGenuine = false;
    for (const auto& module : live.modules) { hasSelf |= EqualEvidencePath(module.fullPath, live.processImagePath); hasGenuine |= EqualEvidencePath(module.fullPath, system); }
    RS2_CHECK(hasSelf && hasGenuine); live = {}; if (genuine) FreeLibrary(genuine);
}
}
