#include "runtime_inventory.h"
#include "tool_paths.h"
#include "pe_contract_lib.h"
#include "companion/build_identity.h"
#include "companion/sha256.h"
#include "companion/steam_reporting_types.h"
#include <TlHelp32.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <limits>
#include <sstream>

namespace rs2fix::tooling {
namespace {
constexpr std::size_t kMaxModules = 4096, kMaxReport = 8U * 1024U * 1024U;
bool Fail(std::string* error, const char* reason) { if (error) *error = reason; return false; }
HANDLE OpenReader(void*, DWORD pid, DWORD* error) {
    HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    *error = handle ? ERROR_SUCCESS : GetLastError(); return handle;
}
void CloseReader(void*, HANDLE handle) noexcept { CloseHandle(handle); }
bool QueryProcess(void*, HANDLE handle, RuntimeProcessIdentity* identity, DWORD* error) {
    DWORD exitCode{}; FILETIME creation{}, exit{}, kernel{}, user{};
    wchar_t path[kPathCapacity]{}; DWORD length = static_cast<DWORD>(std::size(path));
    if (!GetExitCodeProcess(handle, &exitCode) || exitCode != STILL_ACTIVE ||
        !GetProcessTimes(handle, &creation, &exit, &kernel, &user) || exit.dwLowDateTime != 0 || exit.dwHighDateTime != 0 ||
        !QueryFullProcessImageNameW(handle, 0, path, &length) || length == 0 || length >= std::size(path)) {
        *error = GetLastError(); if (*error == ERROR_SUCCESS) *error = ERROR_PROCESS_ABORTED; return false;
    }
    std::string ignored;
    if (!RequireAbsolutePlainFile(path, &identity->imagePath, &ignored)) { *error = ERROR_INVALID_NAME; return false; }
    identity->processId = GetProcessId(handle);
    identity->creationTime = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
    *error = ERROR_SUCCESS; return identity->processId != 0 && identity->creationTime != 0;
}
bool Enumerate(void*, HANDLE handle, DWORD pid, std::vector<RawRuntimeModule>* modules, DWORD* error) {
    modules->clear();
    if (GetProcessId(handle) != pid) { *error = ERROR_INVALID_PARAMETER; return false; }
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) { *error = GetLastError(); return false; }
    MODULEENTRY32W entry{}; entry.dwSize = sizeof(entry);
    BOOL found = Module32FirstW(snapshot, &entry);
    if (!found) { *error = GetLastError(); CloseHandle(snapshot); return false; }
    do {
        if (modules->size() + 1 >= kMaxModules) { *error = ERROR_BUFFER_OVERFLOW; CloseHandle(snapshot); return false; }
        if (wcsnlen_s(entry.szExePath, std::size(entry.szExePath)) >= std::size(entry.szExePath) - 1) { *error = ERROR_BAD_PATHNAME; CloseHandle(snapshot); return false; }
        modules->push_back({reinterpret_cast<std::uintptr_t>(entry.modBaseAddr), entry.modBaseSize, entry.szExePath});
    } while (Module32NextW(snapshot, &entry));
    *error = GetLastError(); CloseHandle(snapshot);
    return *error == ERROR_NO_MORE_FILES && !modules->empty();
}
bool QueryFile(void*, const wchar_t* path, FileIdentity* identity, DWORD* error) {
    std::wstring normalized; std::string why;
    if (!RequireAbsolutePlainFile(path, &normalized, &why)) { *error = GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_INVALID_NAME; return false; }
    return QueryFileIdentity(normalized.c_str(), identity, error);
}
bool ReadPe(void*, const wchar_t* path, pe::Image* image, std::string* error) { return pe::ReadPeImage(path, image, error); }
bool ReadMemory(void*, HANDLE handle, std::uintptr_t address, void* output, std::size_t size, std::size_t* read, DWORD* error) {
    SIZE_T actual{};
    const bool ok = ReadProcessMemory(handle, reinterpret_cast<const void*>(address), output, size, &actual) != FALSE;
    *read = actual; *error = ok ? ERROR_SUCCESS : GetLastError(); return ok;
}
bool SameProcess(const RuntimeProcessIdentity& identity, const RuntimeInventory& inventory) {
    return identity.processId == inventory.processId && identity.creationTime == inventory.creationTime && EqualEvidencePath(identity.imagePath, inventory.processImagePath);
}
bool ProcessUnchanged(const RuntimeInventory& inventory) {
    if (!inventory.process || !inventory.process->handle || !inventory.process->ops.queryProcess) return false;
    RuntimeProcessIdentity current; DWORD error{};
    return inventory.process->ops.queryProcess(inventory.process->ops.context, inventory.process->handle, &current, &error) && SameProcess(current, inventory);
}
bool SameReportingExport(const RuntimeReportingExport&,const RuntimeReportingExport&);
bool SameModules(const std::vector<RuntimeModule>& a, const std::vector<RuntimeModule>& b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) if (a[i].base != b[i].base || a[i].imageSize != b[i].imageSize ||
        !EqualEvidencePath(a[i].fullPath, b[i].fullPath) || !SameFileIdentity(a[i].fileIdentity, b[i].fileIdentity) ||
        !SameReportingExport(a[i].reportingStatus,b[i].reportingStatus)) return false;
    return true;
}
RuntimeReportingExport RetainReportingExport(const pe::Image& image) {
    RuntimeReportingExport result{};
    for (const auto& symbol:image.exports) result.present|=symbol.name=="RS2SteamReport_StatusV2";
    if (!result.present || image.sections.size()>96 || !ReportingStatusExport(image,&result.rva)) return result;
    const auto* section=pe::FindSection(image,result.rva,sizeof(reporting::StatusWire));
    if (!section) { result.rva=0; return result; }
    result.valid=true; result.bytes=sizeof(reporting::StatusWire);
    result.sectionIndex=static_cast<std::uint32_t>(section-image.sections.data());
    result.sectionRva=section->virtualAddress; result.sectionBytes=section->virtualSize;
    result.sectionCharacteristics=section->characteristics;
    return result;
}
bool SameReportingExport(const RuntimeReportingExport& a,const RuntimeReportingExport& b) {
    return a.present==b.present && a.valid==b.valid && a.rva==b.rva && a.bytes==b.bytes &&
        a.sectionIndex==b.sectionIndex && a.sectionRva==b.sectionRva &&
        a.sectionBytes==b.sectionBytes && a.sectionCharacteristics==b.sectionCharacteristics;
}
bool StatusClock(void*,std::uint64_t* frequency,std::uint64_t* now) noexcept {
    LARGE_INTEGER rate{}, counter{};
    if (!QueryPerformanceFrequency(&rate) || !QueryPerformanceCounter(&counter) ||
        rate.QuadPart<=0 || counter.QuadPart<0) return false;
    *frequency=static_cast<std::uint64_t>(rate.QuadPart);
    *now=static_cast<std::uint64_t>(counter.QuadPart); return true;
}
std::string Utc(std::uint64_t value) {
    if (!value) return "unavailable";
    FILETIME file{static_cast<DWORD>(value), static_cast<DWORD>(value >> 32)}; SYSTEMTIME time{};
    if (!FileTimeToSystemTime(&file, &time)) return "unavailable";
    char text[40]{};
    sprintf_s(text, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
    return text;
}
std::uint64_t Now() { FILETIME value{}; GetSystemTimeAsFileTime(&value); return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime; }
bool StableHash(const RuntimeModule& module, Sha256Digest* digest) {
    FileIdentity before{}, after{}; DWORD error{}; std::wstring normalized; std::string why;
    if (!RequireAbsolutePlainFile(module.fullPath.c_str(), &normalized, &why) || !QueryFileIdentity(normalized.c_str(), &before, &error) || !SameFileIdentity(before, module.fileIdentity)) return false;
    const auto hash = HashFileSha256(normalized.c_str(), GetTickCount64() + 10000);
    if (!hash.digestValid || !QueryFileIdentity(normalized.c_str(), &after, &error) || !SameFileIdentity(before, after)) return false;
    *digest = hash.digest; return true;
}
bool SystemGenuine(void*, std::wstring* path, FileIdentity* identity) {
    wchar_t buffer[512]{}; DWORD error{};
    if (!BuildSystemX3AudioPath(buffer, std::size(buffer), &error) || !QueryFileIdentity(buffer, identity, &error)) return false;
    *path = buffer; return true;
}
bool ModuleHash(void*, const RuntimeModule& module, Sha256Digest* digest) { return StableHash(module, digest); }
bool Evidence(void*, const wchar_t* path, FileEvidence* evidence, std::string* error) { return ReadFileEvidence(path, GetTickCount64() + 10000, evidence, error); }
EmbeddedSignatureResult Signature(void*, const wchar_t* path) { return VerifyEmbeddedSignatureCacheOnly(path, ProductionWinTrustOps()); }
bool Contract(void*, const wchar_t* path, ArtifactKind kind, ContractReport* report) { return CheckArtifactContract(path, kind, report); }
std::string Categorize(const std::wstring& path, const std::wstring& root) {
    if (IsPathWithin(root, path, false)) return "<TARGET_ROOT>/" + EncodeEvidencePath(path.substr(root.size() + 1));
    wchar_t system[512]{}, windows[512]{};
    const UINT sn = GetSystemDirectoryW(system, static_cast<UINT>(std::size(system)));
    if (sn > 0 && sn < std::size(system) && IsPathWithin(system, path, false)) return "<SYSTEM32>/" + EncodeEvidencePath(path.substr(sn + 1));
    const UINT wn = GetWindowsDirectoryW(windows, static_cast<UINT>(std::size(windows)));
    if (wn > 0 && wn < std::size(windows) && IsPathWithin(windows, path, false)) return "<WINDOWS>/" + EncodeEvidencePath(path.substr(wn + 1));
    Sha256Digest hash{};
    if (!HashBytesSha256(path.data(), path.size() * sizeof(wchar_t), &hash)) return {};
    return "<OTHER>/" + EncodeEvidencePath(EvidenceLeaf(path)) + "#full_path_sha256=" + FormatSha256Upper(hash).data();
}
}
RuntimeProcessLease::~RuntimeProcessLease() { if (handle && ops.closeProcess) ops.closeProcess(ops.context, handle); }
const RuntimeInventoryOps& ProductionRuntimeInventoryOps() noexcept {
    static const RuntimeInventoryOps ops{nullptr, OpenReader, CloseReader, QueryProcess, Enumerate, QueryFile, ReadPe, ReadMemory, ProductionEvidenceFileOps()}; return ops;
}
const RuntimeValidationOps& ProductionRuntimeValidationOps() noexcept {
    static const RuntimeValidationOps ops{nullptr, SystemGenuine, ModuleHash, QueryFile, Evidence, Signature, Contract}; return ops;
}
bool CaptureStableRuntimeInventory(DWORD pid, const RuntimeInventoryOps& ops, RuntimeInventory* inventory, std::string* error) {
    if (!inventory) return Fail(error, "invalid-inventory-output");
    *inventory = {};
    if (!pid || !ops.openProcess || !ops.closeProcess || !ops.queryProcess || !ops.enumerate || !ops.queryFileIdentity || !ops.readPe || !ops.readMemory) return Fail(error, "invalid-capture-input");
    DWORD code{}; auto lease = std::make_shared<RuntimeProcessLease>(); lease->ops = ops;
    lease->handle = ops.openProcess(ops.context, pid, &code);
    if (!lease->handle) return Fail(error, "reader-access-rejected-compatibility-failure-no-bypass");
    RuntimeProcessIdentity identity;
    if (!ops.queryProcess(ops.context, lease->handle, &identity, &code) || identity.processId != pid || identity.creationTime == 0 || !IsAbsoluteToolPath(identity.imagePath.c_str())) return Fail(error, "process-identity-unavailable");
    inventory->process = lease; inventory->processId = pid; inventory->creationTime = identity.creationTime; inventory->processImagePath = identity.imagePath;
    // Require two consecutive complete module sets for this process instance.
    // This is an observation window, not a lock against later module changes.
    std::vector<RuntimeModule> previous;
    for (std::size_t attempt = 1; attempt <= 3; ++attempt) {
        inventory->attempts = attempt;
        if (!ProcessUnchanged(*inventory)) return Fail(error, "process-exited-or-identity-changed");
        std::vector<RawRuntimeModule> raw;
        if (!ops.enumerate(ops.context, lease->handle, pid, &raw, &code)) {
            if (code == ERROR_BAD_LENGTH) { previous.clear(); continue; }
            return Fail(error, code == ERROR_ACCESS_DENIED ? "module-enumeration-access-rejected-compatibility-failure-no-bypass" : "module-enumeration-incomplete");
        }
        if (raw.empty() || raw.size() >= kMaxModules) return Fail(error, "module-count-incomplete");
        std::sort(raw.begin(), raw.end(), [](const auto& a, const auto& b) { return a.base < b.base; });
        std::vector<RuntimeModule> current; bool invalidated = false; std::size_t reportBudget = 0;
        for (const auto& item : raw) {
            if (!item.base || !item.imageSize || !IsAbsoluteToolPath(item.fullPath.c_str()) || item.fullPath.size() >= kPathCapacity ||
                (!current.empty() && current.back().base + current.back().imageSize > item.base) || item.base > UINTPTR_MAX - item.imageSize) return Fail(error, "module-path-base-or-size-invalid");
            RuntimeModule module; static_cast<RawRuntimeModule&>(module) = item;
            // Normalization is independent of object access so injected snapshots can model vanished files.
            wchar_t normalized[kPathCapacity]{};
            const DWORD n = GetFullPathNameW(item.fullPath.c_str(), static_cast<DWORD>(std::size(normalized)), normalized, nullptr);
            if (n == 0 || n >= std::size(normalized)) return Fail(error, "module-path-normalization-failed");
            module.fullPath.assign(normalized, n);
            if (EncodeEvidencePath(module.fullPath) == "invalid-unicode-path") return Fail(error, "module-path-unrepresentable");
            FileIdentity after{}; std::string peError;
            if (!ops.queryFileIdentity(ops.context, module.fullPath.c_str(), &module.fileIdentity, &code)) {
                if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) { invalidated = true; break; }
                return Fail(error, "module-file-unreadable-or-reparse");
            }
            if (!module.fileIdentity.valid) return Fail(error, "module-file-identity-invalid");
            if (!ops.readPe(ops.context, module.fullPath.c_str(), &module.image, &peError)) {
                if (!ops.queryFileIdentity(ops.context, module.fullPath.c_str(), &after, &code) && (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)) { invalidated = true; break; }
                if (error) *error = "module-pe-incomplete:" + EncodeEvidencePath(EvidenceLeaf(module.fullPath)) + ":" + EncodeEvidenceText(peError);
                return false;
            }
            if (!ops.queryFileIdentity(ops.context, module.fullPath.c_str(), &after, &code)) {
                if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) { invalidated = true; break; }
                return Fail(error, "module-file-unreadable-after-parse");
            }
            if (!SameFileIdentity(module.fileIdentity, after)) { invalidated = true; break; }
            if (module.image.machine != IMAGE_FILE_MACHINE_AMD64 || module.image.optionalMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || module.image.sizeOfImage != module.imageSize) return Fail(error, "module-mapped-file-header-mismatch");
            bool calculate = false, initialize = false;
            for (const auto& symbol : module.image.exports) {
                calculate |= symbol.name == "X3DAudioCalculate";
                initialize |= symbol.name == "X3DAudioInitialize";
                module.companionExports |= symbol.name == "RS2ServerFix_InitializeV3";
            }
            module.x3audioExports = calculate && initialize;
            module.reportingStatus=RetainReportingExport(module.image);
            // Raw images serve the parser only. Keeping all loaded images would be an unbounded inventory.
            std::vector<std::uint8_t>().swap(module.image.rawBytes);
            std::vector<pe::ExportSymbol>().swap(module.image.exports);
            std::vector<pe::Section>().swap(module.image.sections);
            reportBudget += 512 + module.fullPath.size() * 12;
            for (const auto* list : { &module.image.normalImports, &module.image.delayImports }) for (const auto& imported : *list) if (IsX3AudioImport(imported.name)) for (const auto& symbol : imported.symbols) reportBudget += symbol.name.size() * 3 + 128;
            if (reportBudget >= kMaxReport) return Fail(error, "module-report-bound-incomplete");
            current.push_back(std::move(module));
        }
        if (invalidated) { previous.clear(); continue; }
        if (!ProcessUnchanged(*inventory)) return Fail(error, "process-exited-or-identity-changed");
        if (!previous.empty() && SameModules(previous, current)) { inventory->modules = std::move(current); return true; }
        previous = std::move(current);
    }
    return Fail(error, "module-inventory-unstable-after-three-snapshots");
}
const char* ObservedReconName(ObservedReconState state) noexcept {
    switch (state) { case ObservedReconState::Original: return "original"; case ObservedReconState::Corrected: return "corrected"; case ObservedReconState::Unexpected: return "unexpected"; default: return "unavailable"; }
}
bool ObserveReconState(const RuntimeInventory& inventory, std::uintptr_t base, std::uint32_t imageSize,
    const ReconProfile& profile, ExpectedReconState expected, ReconObservation* observation, std::string* error) {
    if (!observation) return Fail(error, "recon-output-invalid");
    *observation = {};
    if (!inventory.process || !inventory.process->ops.readMemory || profile.functionSize == 0 || profile.functionSize > 641 ||
        profile.functionRva > imageSize || profile.functionSize > imageSize - profile.functionRva ||
        profile.constantRva > imageSize || profile.constantBytes.size() > imageSize - profile.constantRva || base > UINTPTR_MAX - imageSize)
        return Fail(error, "recon-range-invalid");
    if (!ProcessUnchanged(inventory)) return Fail(error, "process-exited-or-identity-changed");
    std::array<std::uint8_t, 641> code{}; std::array<std::uint8_t, 16> constant{};
    // The retained process handle and creation-time checks bind these reads to
    // the captured process instance rather than a later process reusing its PID.
    const auto& lease = *inventory.process; std::size_t actual{}; DWORD readError{};
    if (!lease.ops.readMemory(lease.ops.context, lease.handle, base + profile.functionRva, code.data(), profile.functionSize, &actual, &readError) || actual != profile.functionSize)
        return Fail(error, "recon-read-rejected-or-partial-compatibility-failure-no-bypass");
    if (!lease.ops.readMemory(lease.ops.context, lease.handle, base + profile.constantRva, constant.data(), constant.size(), &actual, &readError) || actual != constant.size())
        return Fail(error, "constant-read-rejected-or-partial-compatibility-failure-no-bypass");
    if (!ProcessUnchanged(inventory)) return Fail(error, "process-exited-or-identity-changed");
    if (!HashBytesSha256(code.data(), profile.functionSize, &observation->digest)) return Fail(error, "recon-digest-failed");
    observation->constantsMatch = constant == profile.constantBytes;
    observation->state = observation->digest == profile.originalDigest ? ObservedReconState::Original :
        observation->digest == profile.correctedDigest ? ObservedReconState::Corrected : ObservedReconState::Unexpected;
    if (!observation->constantsMatch) return Fail(error, "recon-constant-mismatch");
    if (observation->state != (expected == ExpectedReconState::Original ? ObservedReconState::Original : ObservedReconState::Corrected)) return Fail(error, "recon-state-mismatch");
    return true;
}

namespace {
bool Zero(const void* data,std::size_t bytes) {
    const auto* p=static_cast<const unsigned char*>(data);
    for (std::size_t i=0;i<bytes;++i) if (p[i]) return false;
    return true;
}
bool StatusRead(const RuntimeInventory& inventory,const RuntimeModule& module,
    std::uint32_t rva,void* out,std::size_t bytes) {
    if (!out || !bytes || !inventory.process || !inventory.process->ops.readMemory ||
        rva>=module.imageSize || bytes>module.imageSize-rva || module.base>UINTPTR_MAX-module.imageSize)
        return false;
    auto& process=*inventory.process; std::size_t actual{}; DWORD error{};
    return process.ops.readMemory(process.ops.context,process.handle,module.base+rva,
        out,bytes,&actual,&error) && actual==bytes;
}
bool ResidentStatusModule(const RuntimeInventory& inventory,const RuntimeModule& module) {
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS64 nt{};
    if (!StatusRead(inventory,module,0,&dos,sizeof(dos)) || dos.e_magic!=IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew<sizeof(dos) || dos.e_lfanew>0x100000 ||
        !StatusRead(inventory,module,static_cast<DWORD>(dos.e_lfanew),&nt,sizeof(nt)) ||
        nt.Signature!=IMAGE_NT_SIGNATURE || nt.FileHeader.Machine!=module.image.machine ||
        nt.FileHeader.Characteristics!=module.image.characteristics ||
        nt.FileHeader.TimeDateStamp!=module.image.coffTimestamp ||
        nt.FileHeader.SizeOfOptionalHeader!=sizeof(IMAGE_OPTIONAL_HEADER64) ||
        !nt.FileHeader.NumberOfSections || nt.FileHeader.NumberOfSections>96 ||
        nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.SizeOfImage!=module.imageSize ||
        nt.OptionalHeader.SizeOfHeaders!=module.image.sizeOfHeaders ||
        nt.OptionalHeader.CheckSum!=module.image.checksum ||
        module.reportingStatus.sectionIndex>=nt.FileHeader.NumberOfSections) return false;
    const auto sectionTable=static_cast<std::uint64_t>(dos.e_lfanew)+sizeof(nt);
    const auto sectionsEnd=sectionTable+nt.FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER);
    if (sectionsEnd>nt.OptionalHeader.SizeOfHeaders || sectionsEnd>module.imageSize) return false;
    IMAGE_SECTION_HEADER section{};
    const auto sectionRva=sectionTable+module.reportingStatus.sectionIndex*sizeof(section);
    return StatusRead(inventory,module,static_cast<DWORD>(sectionRva),&section,sizeof(section)) &&
        section.VirtualAddress==module.reportingStatus.sectionRva &&
        section.Misc.VirtualSize==module.reportingStatus.sectionBytes &&
        section.Characteristics==module.reportingStatus.sectionCharacteristics;
}
bool StatusModuleUnchanged(const RuntimeInventory& inventory,const RuntimeModule& module,
    const Sha256Digest& expected,const RuntimeValidationOps& validation) {
    if (!ProcessUnchanged(inventory) || !inventory.process->ops.enumerate ||
        !validation.queryIdentity || !validation.hashModule) return false;
    auto& process=*inventory.process; DWORD error{};
    std::vector<RawRuntimeModule> modules;
    if (!process.ops.enumerate(process.ops.context,process.handle,inventory.processId,&modules,&error) ||
        modules.empty() || modules.size()>=kMaxModules) return false;
    unsigned matches{};
    for (const auto& current:modules) {
        if (current.base!=module.base && !EqualEvidencePath(current.fullPath,module.fullPath)) continue;
        if (current.base!=module.base || current.imageSize!=module.imageSize ||
            !EqualEvidencePath(current.fullPath,module.fullPath)) return false;
        ++matches;
    }
    FileIdentity file{}; Sha256Digest hash{};
    return matches==1 && validation.queryIdentity(validation.context,module.fullPath.c_str(),&file,&error) &&
        SameFileIdentity(file,module.fileIdentity) && validation.hashModule(validation.context,module,&hash) &&
        hash==expected && ProcessUnchanged(inventory) && ResidentStatusModule(inventory,module);
}
struct StatusSticky {
    std::uint64_t revokeReasons,lossReasons,stopping,stoppedQpc,recordsWritten,lastFlushedSequence;
};
static_assert(sizeof(StatusSticky)==48);
bool ReadSticky(const RuntimeInventory& inventory,const RuntimeModule& module,StatusSticky* value) {
    // Independent words, not a purported second seqlocked payload. Sticky
    // adverse observations are accumulated across BOTH sides and all retries.
    std::uint64_t words[6]{};
    for (unsigned i=0;i<6;++i) if (!StatusRead(inventory,module,module.reportingStatus.rva+
        static_cast<DWORD>(offsetof(reporting::StatusWire,revokeReasons)+i*sizeof(std::uint64_t)),
        &words[i],sizeof(words[i]))) return false;
    std::memcpy(value,words,sizeof(*value)); return true;
}
void AccumulateSticky(ReportingStatusObservation& out,const StatusSticky& words) {
    out.revokeReasons|=words.revokeReasons; out.lossReasons|=words.lossReasons;
    out.stopping|=words.stopping;
    out.stoppedQpc=(std::max)(out.stoppedQpc,words.stoppedQpc);
    out.recordsWritten=(std::max)(out.recordsWritten,words.recordsWritten);
    out.lastFlushedSequence=(std::max)(out.lastFlushedSequence,words.lastFlushedSequence);
}
bool StatusHeaderValid(const reporting::StatusHeader& h,const RuntimeInventory& inventory,
    const Sha256Digest& host,std::uint64_t frequency) {
    using namespace reporting;
    if (h.magic!=kStatusMagic || h.schema!=kStatusSchema || h.bytes!=sizeof(StatusWire) ||
        h.artifactVersion!=kReportingArtifactVersion || (h.validity&~CompleteHeaderIdentity) ||
        !Zero(h.reserved,sizeof(h.reserved)) || h.configuredMode>static_cast<std::uint32_t>(Mode::Repair)) return false;
    if ((h.pid && h.pid!=inventory.processId) || (h.processCreation && h.processCreation!=inventory.creationTime)) return false;
    if ((h.validity&ProcessIdentityValid) && (h.pid!=inventory.processId || h.processCreation!=inventory.creationTime)) return false;
    if ((h.validity&RunIdentityValid) ? Zero(h.runId,sizeof(h.runId)) : !Zero(h.runId,sizeof(h.runId))) return false;
    if ((h.validity&HostIdentityValid) && std::memcmp(h.hostDigest,host.data(),host.size())) return false;
    if (!(h.validity&HostIdentityValid) && !Zero(h.hostDigest,sizeof(h.hostDigest)) &&
        std::memcmp(h.hostDigest,host.data(),host.size())) return false;
    if ((h.validity&ClockIdentityValid) && (!h.qpcFrequency || h.qpcFrequency!=frequency)) return false;
    if ((h.validity&ConfigurationValid) && h.configuredMode==static_cast<std::uint32_t>(Mode::Invalid)) return false;
    return true;
}
} // namespace

const RuntimeStatusClockOps& ProductionRuntimeStatusClockOps() noexcept {
    static const RuntimeStatusClockOps ops{nullptr,StatusClock}; return ops;
}
const char* ReportingStatusStateName(ReportingStatusState state) noexcept {
    switch (state) {
    case ReportingStatusState::Uninitialized:return "uninitialized";
    case ReportingStatusState::Initializing:return "initializing";
    case ReportingStatusState::Busy:return "busy";
    case ReportingStatusState::Invalid:return "invalid";
    case ReportingStatusState::Rejected:return "rejected";
    case ReportingStatusState::Disabled:return "disabled";
    case ReportingStatusState::Revoked:return "revoked";
    case ReportingStatusState::Stopped:return "stopped";
    case ReportingStatusState::Stale:return "stale";
    case ReportingStatusState::NotReady:return "not-ready";
    case ReportingStatusState::Ready:return "ready";
    default:return "unavailable";
    }
}
bool ReadReportingStatus(const RuntimeInventory& inventory,const RuntimeModule& module,
    const Sha256Digest& host,const Sha256Digest& companion,
    ReportingStatusObservation* observation,std::string* error) {
    return ReadReportingStatusWithOps(inventory,module,host,companion,ProductionRuntimeValidationOps(),
        ProductionRuntimeStatusClockOps(),observation,error);
}
bool ReadReportingStatusWithOps(const RuntimeInventory& inventory,const RuntimeModule& module,
    const Sha256Digest& host,const Sha256Digest& companion,const RuntimeValidationOps& validation,
    const RuntimeStatusClockOps& clock,ReportingStatusObservation* out,std::string* error) {
    using namespace reporting;
    if (!out) return Fail(error,"reporting-status-output-invalid");
    *out={};
    auto reject=[&](const char* reason) { out->state=ReportingStatusState::Invalid;
        out->detail=reason; out->currentReady=false; return Fail(error,reason); };
    if (!inventory.process || !inventory.process->handle || !validation.artifactContract ||
        !clock.read || Zero(host.data(),host.size()) || Zero(companion.data(),companion.size()))
        return reject("reporting-status-input-invalid");
    const auto& exportInfo=module.reportingStatus;
    if (!exportInfo.present) { out->detail="reporting-status-export-absent"; return Fail(error,out->detail.c_str()); }
    if (!exportInfo.valid || exportInfo.bytes!=sizeof(StatusWire) || (exportInfo.rva&7) ||
        exportInfo.rva>=module.imageSize || sizeof(StatusWire)>module.imageSize-exportInfo.rva ||
        !module.base || module.base>UINTPTR_MAX-module.imageSize || ((module.base+exportInfo.rva)&7))
        return reject("reporting-status-export-invalid");
    unsigned capturedModule{};
    for (const auto& entry:inventory.modules) if (entry.base==module.base && entry.imageSize==module.imageSize &&
        EqualEvidencePath(entry.fullPath,module.fullPath) && SameFileIdentity(entry.fileIdentity,module.fileIdentity) &&
        SameReportingExport(entry.reportingStatus,exportInfo)) ++capturedModule;
    if (capturedModule!=1) return reject("reporting-status-module-not-captured");
    ContractReport contract;
    if (!validation.artifactContract(validation.context,module.fullPath.c_str(),ArtifactKind::CompanionReporting,&contract) ||
        !SameReportingExport(exportInfo,RetainReportingExport(contract.image)))
        return reject("reporting-status-artifact-contract-mismatch");
    if (!StatusModuleUnchanged(inventory,module,companion,validation))
        return reject("reporting-status-module-or-process-changed");
    std::uint64_t frequency{}, firstQpc{};
    if (!clock.read(clock.context,&frequency,&firstQpc) || !frequency ||
        frequency>static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)())/45)
        return reject("reporting-status-clock-unavailable");
    std::uint64_t lastHeaderReady{}, highestSequence{};
    for (unsigned attempt=1;attempt<=3;++attempt) {
        out->attempts=attempt;
        std::uint64_t readyBefore{}, readyAfter{}, before{}, after{};
        StatusHeader header{}, headerAfter{};
        StatusPayload payload{};
        StatusSticky sticky{};
        const auto read=[&](std::size_t offset,void* target,std::size_t bytes) {
            return offset<=sizeof(StatusWire) && bytes<=sizeof(StatusWire)-offset &&
                StatusRead(inventory,module,exportInfo.rva+static_cast<DWORD>(offset),target,bytes);
        };
        if (!read(offsetof(StatusWire,headerReady),&readyBefore,8) ||
            !ReadSticky(inventory,module,&sticky)) return reject("reporting-status-read-rejected-or-partial-no-bypass");
        AccumulateSticky(*out,sticky);
        if (readyBefore>2) return reject("reporting-status-header-ready-invalid");
        if (readyBefore==1 && !read(0,&header,sizeof(header)))
            return reject("reporting-status-header-read-partial");
        if (!read(offsetof(StatusWire,ownerSequence),&before,8)) return reject("reporting-status-sequence-read-partial");
        const bool sampled=readyBefore==1 && before>=2 && !(before&1);
        if (sampled && !read(offsetof(StatusWire,owner),&payload,sizeof(payload)))
            return reject("reporting-status-payload-read-partial");
        if (!read(offsetof(StatusWire,ownerSequence),&after,8) ||
            !ReadSticky(inventory,module,&sticky) ||
            !read(offsetof(StatusWire,headerReady),&readyAfter,8))
            return reject("reporting-status-final-read-partial");
        AccumulateSticky(*out,sticky); lastHeaderReady=readyAfter;
        if (readyAfter>2) return reject("reporting-status-header-ready-invalid");
        if (after<before || before<highestSequence) return reject("reporting-status-sequence-decreased");
        highestSequence=(std::max)(highestSequence,after);
        if (readyBefore!=1 || readyAfter!=1) continue;
        if (!read(0,&headerAfter,sizeof(headerAfter))) return reject("reporting-status-final-header-read-partial");
        if (std::memcmp(&header,&headerAfter,sizeof(header)) ||
            !StatusHeaderValid(header,inventory,host,frequency)) return reject("reporting-status-header-identity-mismatch");
        if (out->headerValid && std::memcmp(&out->header,&header,sizeof(header)))
            return reject("reporting-status-header-changed-across-attempts");
        out->header=header; out->headerValid=true;
        out->identityComplete=header.validity==CompleteHeaderIdentity;
        if (!sampled || before!=after || (after&1)) continue;
        if (payload.phase>static_cast<std::uint64_t>(ReportPhase::Faulted) ||
            payload.reason>=kReasonCount || payload.pending>1 || payload.fresh>1 || payload.builderBound>1 ||
            payload.ownerThreadId>MAXDWORD) return reject("reporting-status-payload-schema-invalid");
        out->owner=payload; out->ownerValid=true; out->ownerSequence=after; break;
    }
    if (!StatusModuleUnchanged(inventory,module,companion,validation))
        return reject("reporting-status-module-or-process-changed-after-read");
    if (out->headerValid) {
        std::uint64_t finalReady{}; StatusHeader finalHeader{};
        if (!StatusRead(inventory,module,exportInfo.rva+static_cast<DWORD>(offsetof(StatusWire,headerReady)),&finalReady,8) ||
            finalReady!=1 || !StatusRead(inventory,module,exportInfo.rva,&finalHeader,sizeof(finalHeader)) ||
            std::memcmp(&finalHeader,&out->header,sizeof(finalHeader)))
            return reject("reporting-status-header-changed-after-qualification");
    }
    StatusSticky finalSticky{};
    if (!ReadSticky(inventory,module,&finalSticky)) return reject("reporting-status-final-latch-read-partial");
    AccumulateSticky(*out,finalSticky);
    std::uint64_t finalFrequency{}, now{};
    if (!clock.read(clock.context,&finalFrequency,&now) || finalFrequency!=frequency || now<firstQpc)
        return reject("reporting-status-clock-changed");
    out->observedQpc=now; out->captured=true;
    const auto stoppingMask=1ULL<<static_cast<unsigned>(Reason::Stopping);
    if (out->lossReasons || (out->revokeReasons&~stoppingMask)) out->state=ReportingStatusState::Revoked;
    else if (out->stopping || out->revokeReasons ||
        (out->ownerValid && out->owner.phase==static_cast<std::uint64_t>(ReportPhase::Stopping)))
        out->state=ReportingStatusState::Stopped;
    else if (!out->headerValid) out->state=lastHeaderReady==0 ? ReportingStatusState::Uninitialized : ReportingStatusState::Initializing;
    else if (!out->ownerValid) out->state=ReportingStatusState::Busy;
    else if (out->owner.phase==static_cast<std::uint64_t>(ReportPhase::Rejected)) out->state=ReportingStatusState::Rejected;
    else if (out->header.configuredMode<static_cast<std::uint32_t>(Mode::Observe)) out->state=ReportingStatusState::Disabled;
    else if (!out->identityComplete) out->state=ReportingStatusState::NotReady;
    else if (!out->owner.lastOwnerQpc || now<out->owner.lastOwnerQpc || now-out->owner.lastOwnerQpc>2*frequency)
        out->state=ReportingStatusState::Stale;
    else {
        const auto desired=out->header.configuredMode==static_cast<std::uint32_t>(Mode::Observe) ? ReportPhase::Observing : ReportPhase::Repairing;
        out->currentReady=out->owner.phase==static_cast<std::uint64_t>(desired) &&
            out->owner.ownerThreadId && out->owner.sourceEpoch && out->owner.bindingEpoch &&
            out->owner.readyQpc && out->owner.readyQpc<=now && out->owner.builderBound==1;
        out->state=out->currentReady ? ReportingStatusState::Ready : ReportingStatusState::NotReady;
    }
    out->detail=ReportingStatusStateName(out->state);
    if (error) error->clear();
    return true;
}

bool ValidateRuntimeInventory(const RuntimeInventory& inventory, const RuntimeValidationInputs& inputs, RuntimeValidationResult* result) {
    return ValidateRuntimeInventoryWithOps(inventory, inputs, ProductionRuntimeValidationOps(), kProductionReconProfile, result);
}
bool ValidateRuntimeInventoryWithOps(const RuntimeInventory& inventory, const RuntimeValidationInputs& inputs,
    const RuntimeValidationOps& ops, const ReconProfile& profile, RuntimeValidationResult* result) {
    if (!result) return false;
    *result = {};
    auto finding = [&](const char* text) { result->findings.emplace_back(text); };
    if (!ops.systemGenuine || !ops.hashModule || !ops.queryIdentity || !ops.readEvidence || !ops.signature || !ops.artifactContract) { finding("runtime-validation-adapter-invalid"); return false; }
    if (inventory.processId != inputs.processId || inventory.modules.empty() || !IsPathWithin(inputs.targetRoot, inventory.processImagePath, false) || !ProcessUnchanged(inventory)) { finding("runtime-host-identity-invalid"); return false; }
    if ((inputs.expectation == RuntimeExpectation::SystemControl || inputs.mode == DeploymentMode::Passive) && inputs.expectedRecon != ExpectedReconState::Original) finding("control-or-passive-requires-original-recon");
    if (inputs.expectation == RuntimeExpectation::ProxyPass && inputs.mode == DeploymentMode::Active && inputs.expectedRecon != ExpectedReconState::Corrected) finding("active-proxy-requires-corrected-recon");
    if (inputs.observerCompanion && (inputs.expectation != RuntimeExpectation::ProxyPass || inputs.mode != DeploymentMode::Active || inputs.expectedRecon != ExpectedReconState::Corrected)) finding("observer-requires-active-corrected-proxy");
    if (inputs.reportingCompanion && (inputs.observerCompanion || inputs.expectation!=RuntimeExpectation::ProxyPass ||
        inputs.mode!=DeploymentMode::Active || inputs.expectedRecon!=ExpectedReconState::Corrected))
        finding("reporting-requires-explicit-active-corrected-proxy");
    const RuntimeModule* host = nullptr; const RuntimeModule* genuine = nullptr; const RuntimeModule* bootstrap = nullptr; const RuntimeModule* companion = nullptr;
    std::size_t importers = 0, audio = 0, companions = 0, hosts = 0;
    std::wstring systemPath; DWORD error{}; FileIdentity systemIdentity{};
    const bool systemOk = ops.systemGenuine(ops.context, &systemPath, &systemIdentity);
    if (!systemOk) finding("system32-identity-unavailable");
    const auto directoryEnd = inventory.processImagePath.find_last_of(L"\\/");
    const std::wstring directory = inventory.processImagePath.substr(0, directoryEnd);
    for (const auto& module : inventory.modules) {
        if (EqualEvidencePath(module.fullPath, inventory.processImagePath)) { host = &module; ++hosts; }
        bool imports = false;
        for (const auto* list : { &module.image.normalImports, &module.image.delayImports }) for (const auto& imported : *list) if (IsX3AudioImport(imported.name)) imports = true;
        if (imports) { ++importers; if (!EqualEvidencePath(module.fullPath, inventory.processImagePath) || !HasRequiredHostImports(module.image)) finding("unexpected-x3audio-importer"); }
        const auto leaf = EvidenceLeaf(module.fullPath);
        if (IsPathWithin(inputs.targetRoot, module.fullPath, false)) {
            if (module.x3audioExports && !EqualEvidencePath(leaf, L"X3DAudio1_7.dll")) finding("renamed-local-x3audio-artifact");
            if (module.companionExports && !EqualEvidencePath(leaf, L"RS2ServerFix.dll")) finding("renamed-local-companion-artifact");
        }
        if (EqualEvidencePath(leaf, L"X3DAudio1_7.dll")) {
            ++audio;
            if (systemOk && EqualEvidencePath(module.fullPath, systemPath) && SameFileIdentity(module.fileIdentity, systemIdentity)) { if (genuine) finding("duplicate-genuine-module"); genuine = &module; }
            else if (EqualEvidencePath(module.fullPath, directory + L"\\X3DAudio1_7.dll")) { if (bootstrap) finding("duplicate-bootstrap-module"); bootstrap = &module; }
            else finding("unexpected-x3audio-path-or-identity");
        }
        if (EqualEvidencePath(leaf, L"RS2ServerFix.dll")) {
            ++companions; companion = &module;
            if (!EqualEvidencePath(module.fullPath, directory + L"\\RS2ServerFix.dll")) finding("unexpected-companion-path");
        }
    }
    if (hosts != 1 || importers != 1 || !host) finding("expected-single-host-and-importer");
    if (inputs.expectation == RuntimeExpectation::SystemControl) {
        if (audio != 1 || !genuine || bootstrap || companions != 0) finding("system-control-module-set-mismatch");
    } else if (audio != 2 || !genuine || !bootstrap || companions != 1 || !companion) finding("proxy-pass-module-set-mismatch");
    if (host) {
        if (!ops.hashModule(ops.context, *host, &result->hostSha256)) finding("host-hash-or-identity-failed");
        else result->moduleDigests.emplace_back(host->base, result->hostSha256);
        const auto build = ClassifyBuild(result->hostSha256, true);
        if (build != BuildIdentity::CurrentStock && build != BuildIdentity::CurrentFullDump) finding("unapproved-host-hash");
        if (inputs.mode == DeploymentMode::Active && build != BuildIdentity::CurrentFullDump) finding("active-requires-current-full-dump");
        if (host->image.tlsDirectoryRva || host->image.tlsDirectorySize || !HasRequiredHostImports(host->image)) finding("host-startup-contract-mismatch");
    }
    auto artifact = [&](const RuntimeModule* module, const Sha256Digest& wanted, ArtifactKind kind, Sha256Digest* actual) {
        if (!module) return;
        ContractReport contract;
        const bool hashed = ops.hashModule(ops.context, *module, actual);
        if (hashed) result->moduleDigests.emplace_back(module->base, *actual);
        const bool valid = ops.artifactContract(ops.context, module->fullPath.c_str(), kind, &contract);
        if (!hashed || *actual != wanted || !valid) finding("artifact-hash-contract-or-identity-failed");
        if (!valid && !inputs.observerCompanion && contract.version.fileDescription == L"RS2ServerFix Active Recon Steam Observer Companion")
            finding("observer-artifact-requires-explicit---companion-kind-companion-observer");
        if (!valid && !inputs.reportingCompanion && contract.version.fileDescription == L"RS2ServerFix Active Recon Steam Reporting Companion")
            finding("reporting-artifact-requires-explicit---companion-kind-companion-reporting");
        FileIdentity after{};
        if (!ops.queryIdentity(ops.context, module->fullPath.c_str(), &after, &error) || !SameFileIdentity(module->fileIdentity, after)) finding("artifact-identity-changed-after-contract");
    };
    artifact(bootstrap, inputs.bootstrapSha256, ArtifactKind::Bootstrap, &result->bootstrapSha256);
    artifact(companion, inputs.companionSha256, inputs.reportingCompanion ? ArtifactKind::CompanionReporting :
        inputs.observerCompanion ? ArtifactKind::CompanionObserver : inputs.mode == DeploymentMode::Passive ? ArtifactKind::CompanionPassive : ArtifactKind::CompanionActive, &result->companionSha256);
    if (inputs.observerCompanion || inputs.reportingCompanion) {
        const RuntimeModule* sdk = nullptr;
        std::size_t sdkCount = 0;
        for (const auto& module : inventory.modules) if (EqualEvidencePath(EvidenceLeaf(module.fullPath), L"steam_api64.dll")) { sdk = &module; ++sdkCount; }
        Sha256Digest expectedSdk{};
        ParseSha256Upper("A44E5537939AE4EEBC69000589AA9B2437A667813A1657CC779198BAE9B815A9", &expectedSdk);
        if (sdkCount != 1 || !sdk || !EqualEvidencePath(sdk->fullPath, directory + L"\\steam_api64.dll") ||
            !ops.hashModule(ops.context, *sdk, &result->sdkSha256) || result->sdkSha256 != expectedSdk)
            finding(inputs.reportingCompanion ? "reporting-sdk-disk-identity-mismatch" : "observer-sdk-disk-identity-mismatch");
        else result->moduleDigests.emplace_back(sdk->base, result->sdkSha256);
    }
    if (inputs.reportingCompanion) {
        const RuntimeModule* client=nullptr; unsigned clients{};
        for (const auto& module:inventory.modules) if (EqualEvidencePath(EvidenceLeaf(module.fullPath),L"steamclient64.dll")) {
            client=&module; ++clients;
        }
        Sha256Digest expectedClient{};
        ParseSha256Upper("8165D2A8E82753E5CD5AD985D6D08C2379E0AA8D0340669BCF05890584F51ACE",&expectedClient);
        if (clients!=1 || !client || client->imageSize!=0x1766000 ||
            client->image.coffTimestamp!=0x685F401F || client->image.checksum!=0x17153E7 ||
            !ops.hashModule(ops.context,*client,&result->steamClientSha256) ||
            result->steamClientSha256!=expectedClient) finding("reporting-loaded-steamclient-identity-mismatch");
        else result->moduleDigests.emplace_back(client->base,result->steamClientSha256);
        // DATA capture is a separate result: an absent/uninitialized/rejected
        // reporting surface must not falsely label an intact recon patch failed.
    }
    if (genuine) {
        FileEvidence evidence; std::string why;
        if (!ops.readEvidence(ops.context, genuine->fullPath.c_str(), &evidence, &why)) finding("genuine-evidence-failed");
        else {
            result->genuineSha256 = evidence.sha256;
            result->moduleDigests.emplace_back(genuine->base, evidence.sha256);
            const auto* entry = FindManifestEntry(inputs.genuineManifest, evidence.sha256, ManifestState::Qualified);
            const auto signature = ops.signature(ops.context, genuine->fullPath.c_str());
            FileIdentity after{};
            if (!entry || !MatchesGenuineManifestEntry(evidence, *entry, &why) || signature.verifyStatus != ERROR_SUCCESS || !signature.closeAttempted || signature.closeStatus != ERROR_SUCCESS || !ops.queryIdentity(ops.context, genuine->fullPath.c_str(), &after, &error) || !SameFileIdentity(genuine->fileIdentity, after)) finding("genuine-manifest-trust-or-identity-mismatch");
        }
    }
    if (result->findings.empty() && host) {
        std::string why;
        if (!ObserveReconState(inventory, host->base, host->imageSize, profile, inputs.expectedRecon, &result->recon, &why)) result->findings.push_back(why);
    }
    if (!ProcessUnchanged(inventory)) finding("process-exited-or-identity-changed");
    result->passed = result->findings.empty(); return result->passed;
}
bool WriteRuntimeInventoryReport(const RuntimeInventory& inventory, const RuntimeValidationInputs& inputs,
    const RuntimeValidationResult& result, const EvidenceFileOps& ops, std::string* error) {
    std::wstring report;
    if (!RequireAbsoluteNewFileOutsideRoot(inputs.reportPath.c_str(), inputs.targetRoot, &report, error)) return false;
    std::ostringstream out;
    out << "schema=1\r\nmode=runtime-inventory\r\npid=" << inputs.processId << "\r\nprocess_creation_filetime=" << inventory.creationTime
        << "\r\nprocess_creation_utc=" << Utc(inventory.creationTime) << "\r\nobserved_utc=" << Utc(Now())
        << "\r\nexpect=" << (inputs.expectation == RuntimeExpectation::SystemControl ? "system-control" : "proxy-pass")
        << "\r\ndeployment_mode=" << DeploymentModeName(inputs.mode)
        << "\r\ntool_sha256=" << FormatSha256Upper(inputs.toolSha256).data() << "\r\nmanifest_sha256=" << FormatSha256Upper(inputs.genuineManifestSha256).data()
        << "\r\nhost_sha256=" << FormatSha256Upper(result.hostSha256).data() << "\r\ngenuine_sha256=" << FormatSha256Upper(result.genuineSha256).data()
        << "\r\nbootstrap_sha256=" << FormatSha256Upper(inputs.bootstrapSha256).data() << "\r\ncompanion_sha256=" << FormatSha256Upper(inputs.companionSha256).data()
        << "\r\nartifact_hash_arguments=operator-expected\r\nobserved_bootstrap_sha256=" << FormatSha256Upper(result.bootstrapSha256).data()
        << "\r\nobserved_companion_sha256=" << FormatSha256Upper(result.companionSha256).data()
        << "\r\nexpected_recon=" << (inputs.expectedRecon == ExpectedReconState::Original ? "original" : "corrected")
        << "\r\nobserved_recon=" << ObservedReconName(result.recon.state) << "\r\nrecon_sha256=" << FormatSha256Upper(result.recon.digest).data()
        << "\r\nconstant_match=" << (result.recon.constantsMatch ? "true" : "false") << "\r\nsnapshot_attempts=" << inventory.attempts << "\r\nmodule_count=" << inventory.modules.size() << "\r\n";
    if (inputs.observerCompanion || inputs.reportingCompanion) out << "companion_kind=" <<
        (inputs.reportingCompanion ? "companion-reporting" : "companion-observer") << "\r\nprocess_image_path=" << EncodeEvidencePath(inventory.processImagePath)
        << "\r\nsdk_sha256=" << FormatSha256Upper(result.sdkSha256).data() << "\r\nidentity_hash_scope=disk-files-not-resident-images\r\n";
    if (inputs.reportingCompanion) {
        const auto& status=result.reporting;
        const auto boolean=[](bool value) { return value ? "true" : "false"; };
        out << "steamclient_sha256=" << FormatSha256Upper(result.steamClientSha256).data()
            << "\r\nreporting.state=" << ReportingStatusStateName(status.state)
            << "\r\nreporting.detail=" << EncodeEvidenceText(status.detail)
            << "\r\nreporting.captured=" << boolean(status.captured)
            << "\r\nreporting.header_valid=" << boolean(status.headerValid)
            << "\r\nreporting.owner_valid=" << boolean(status.ownerValid)
            << "\r\nreporting.identity_complete=" << boolean(status.identityComplete)
            << "\r\nreporting.current_ready=" << boolean(status.currentReady)
            << "\r\nreporting.read_attempts=" << status.attempts
            << "\r\nreporting.observed_qpc=" << status.observedQpc
            << "\r\nreporting.owner_sequence=" << status.ownerSequence
            << "\r\nreporting.revoke_reasons=" << status.revokeReasons
            << "\r\nreporting.loss_reasons=" << status.lossReasons
            << "\r\nreporting.stopping=" << status.stopping
            << "\r\nreporting.stopped_qpc=" << status.stoppedQpc
            << "\r\nreporting.records_written=" << status.recordsWritten
            << "\r\nreporting.last_flushed_sequence=" << status.lastFlushedSequence << "\r\n";
        if (status.headerValid) {
            char run[33]{}; constexpr char hex[]="0123456789abcdef";
            for (unsigned i=0;i<16;++i) { run[2*i]=hex[status.header.runId[i]>>4]; run[2*i+1]=hex[status.header.runId[i]&15]; }
            out << "reporting.schema=" << status.header.schema << "\r\nreporting.bytes=" << status.header.bytes
                << "\r\nreporting.artifact_version=" << status.header.artifactVersion
                << "\r\nreporting.mode=" << status.header.configuredMode
                << "\r\nreporting.pid=" << status.header.pid
                << "\r\nreporting.process_creation=" << status.header.processCreation
                << "\r\nreporting.header_validity=" << status.header.validity
                << "\r\nreporting.qpc_frequency=" << status.header.qpcFrequency
                << "\r\nreporting.run_id=" << run << "\r\n";
        }
        if (status.ownerValid) {
            const auto& owner=status.owner;
#define RS2_STATUS_FIELD(field) out << "reporting." #field "=" << owner.field << "\r\n"
            RS2_STATUS_FIELD(phase); RS2_STATUS_FIELD(reason); RS2_STATUS_FIELD(ownerThreadId);
            RS2_STATUS_FIELD(sourceEpoch); RS2_STATUS_FIELD(bindingEpoch); RS2_STATUS_FIELD(lastOwnerQpc);
            RS2_STATUS_FIELD(timingAccountedThroughQpc);
            RS2_STATUS_FIELD(lastManagementQpc); RS2_STATUS_FIELD(lastBuilderQpc); RS2_STATUS_FIELD(readyQpc);
            RS2_STATUS_FIELD(pendingSinceQpc); RS2_STATUS_FIELD(freshSinceQpc); RS2_STATUS_FIELD(requestSequence);
            RS2_STATUS_FIELD(witnessSequence); RS2_STATUS_FIELD(buildSequence); RS2_STATUS_FIELD(pending);
            RS2_STATUS_FIELD(fresh); RS2_STATUS_FIELD(pi); RS2_STATUS_FIELD(bots); RS2_STATUS_FIELD(maximum);
            RS2_STATUS_FIELD(normalAttempts); RS2_STATUS_FIELD(fullSelected); RS2_STATUS_FIELD(selectedTrue);
            RS2_STATUS_FIELD(normalReturns); RS2_STATUS_FIELD(falseReturns); RS2_STATUS_FIELD(nativeUnwinds);
            RS2_STATUS_FIELD(managementCalls); RS2_STATUS_FIELD(normalPumpClassifications);
            RS2_STATUS_FIELD(normalBuilderClassifications); RS2_STATUS_FIELD(builderBound);
            RS2_STATUS_FIELD(reportSequence); RS2_STATUS_FIELD(lastSelectedWitness); RS2_STATUS_FIELD(distinctSelectedWitnesses);
#undef RS2_STATUS_FIELD
            for (std::size_t i=0;i<reporting::kStatusReasonSlots;++i)
                out << "reporting.reason_count." << i << '=' << owner.reasons[i] << "\r\n";
            for (std::size_t i=0;i<reporting::kStatusDurationClasses;++i) {
                const auto& duration=owner.durations[i];
                out << "reporting.duration." << i << ".calls=" << duration.calls
                    << "\r\nreporting.duration." << i << ".elapsed_ticks=" << duration.elapsedTicks
                    << "\r\nreporting.duration." << i << ".maximum_ticks=" << duration.maximumTicks
                    << "\r\nreporting.duration." << i << ".over_five_ms=" << duration.overFiveMilliseconds << "\r\n";
                for (std::size_t n=0;n<reporting::kStatusDurationBuckets;++n)
                    out << "reporting.duration." << i << ".bucket." << n << '=' << duration.buckets[n] << "\r\n";
            }
        }
        out << "reporting.limitation=Current-DATA-observation-is-not-trial-coverage-or-backend-effect\r\n";
    }
    for (std::size_t i = 0; i < inventory.modules.size(); ++i) {
        const auto& m = inventory.modules[i]; const auto path = Categorize(m.fullPath, inputs.targetRoot);
        if (path.empty()) return Fail(error, "path-discriminator-hash-failed");
        out << "module." << i << "=" << std::hex << m.base << std::dec << '|' << m.imageSize << '|' << m.fileIdentity.volumeSerial << ':' << m.fileIdentity.fileIndexHigh << ':' << m.fileIdentity.fileIndexLow << '|' << path << "\r\n";
        for (const auto& digest : result.moduleDigests) if (digest.first == m.base) out << "module_sha256." << i << '=' << FormatSha256Upper(digest.second).data() << "\r\n";
        std::size_t importIndex = 0;
        for (const auto* list : { &m.image.normalImports, &m.image.delayImports }) for (const auto& imported : *list) if (IsX3AudioImport(imported.name)) for (const auto& symbol : imported.symbols)
            out << "import." << i << '.' << importIndex++ << '=' << (list == &m.image.normalImports ? "normal" : "delay") << "|X3DAudio1_7.dll|" << EncodeEvidenceText(symbol.byOrdinal ? "#" + std::to_string(symbol.ordinal) : symbol.name) << "\r\n";
        if (out.tellp() >= static_cast<std::streamoff>(kMaxReport - 16384)) return Fail(error, "report-bound-incomplete");
    }
    out << "limitation.datafile=Tool-Help-does-not-enumerate-LOAD_LIBRARY_AS_DATAFILE-non-executable-views\r\nlimitation.dynamic=Static-inventory-cannot-rule-out-dynamic-GetProcAddress-from-another-DllMain\r\nreader_security_policy=Read-rejection-is-compatibility-failure-no-bypass\r\nfinding_count=" << result.findings.size() << "\r\n";
    for (std::size_t i = 0; i < result.findings.size(); ++i) out << "finding." << i << '=' << EncodeEvidenceText(result.findings[i]) << "\r\n";
    const bool unchanged = !result.passed || ProcessUnchanged(inventory);
    if (inputs.reportingCompanion) out << "recon_artifact_result=" << (result.passed && unchanged ? "pass" : "unsafe") << "\r\n";
    out << "result=" << (result.passed && unchanged ? "pass" : "unsafe") << "\r\n";
    if (!unchanged) return Fail(error, "process-exited-before-report");
    const auto bytes = out.str();
    if (bytes.size() >= kMaxReport) return Fail(error, "report-bound-incomplete");
    return WriteEvidenceBytesCreateNew(report.c_str(), bytes, ops, error);
}
}
