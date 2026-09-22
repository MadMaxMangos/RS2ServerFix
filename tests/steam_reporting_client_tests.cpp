#include "companion/steam_reporting_client.h"
#include "companion/sha256.h"
#include "test_framework.h"

#include <array>
#include <cstring>
#include <cwchar>
#include <vector>

#if !defined(RS2_REPORTING_TESTING)
#error The inert client qualifier adapters belong only in the reporting test target.
#endif

namespace {
using namespace rs2fix;
using namespace rs2fix::reporting;
constexpr std::uintptr_t kModule = 0x230000000ULL;
constexpr std::uint32_t kSize = 0x5000;
constexpr std::uint32_t kStamp = 0x12345678;
constexpr std::uint32_t kChecksum = 0xABCD;
constexpr wchar_t kLeaf[] = L"rs2_fixture_client.dll";
constexpr wchar_t kPath[] = L"C:\\RS2InertFixture\\rs2_fixture_client.dll";

struct Fixture {
    std::array<unsigned char, 4096> image{};
    std::vector<unsigned char> file;
    ClientTestIdentity identity{};
    ULONGLONG now{100};
    unsigned enumerations{}, retains{}, releases{}, paths{}, opens{}, closes{}, metadata{}, reads{};
    unsigned candidateCount{1};
    unsigned failEnumerationAt{}, failPathAt{}, changePathAt{}, changeMetadataAt{}, failMetadataAt{};
    bool failRetain{}, wrongRetain{}, failRelease{}, failOpen{}, failRead{}, wrongDigest{};
    bool changedModule{}, changedImageSize{}, changedHeader{}, changedUnpinnedHeader{};
    bool badPath{}, unterminatedPath{}, failMemoryRead{}, wrongMemoryType{}, wrongProtection{};
    bool expireInRead{}, expireAfterRelease{}, regressAfterRelease{}, delayedEnumeration{};
    bool held{}, fileOpen{}, ownershipError{};
    std::size_t cursor{};

    Fixture() : file(70001) {
        for (std::size_t i = 0; i < file.size(); ++i) file[i] = static_cast<unsigned char>(i % 251);
        identity = {kLeaf, {}, kSize, kStamp, kChecksum};
        RS2_CHECK(HashBytesSha256(file.data(), file.size(), &identity.digest));
        IMAGE_DOS_HEADER dos{}; dos.e_magic = IMAGE_DOS_SIGNATURE; dos.e_lfanew = 0x80;
        Put(0, dos);
        IMAGE_NT_HEADERS64 nt{};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = 3;
        nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.FileHeader.TimeDateStamp = kStamp;
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.SizeOfImage = kSize;
        nt.OptionalHeader.SizeOfHeaders = 0x400;
        nt.OptionalHeader.CheckSum = kChecksum;
        nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        Put(0x80, nt);
    }
    template<class T> void Put(std::size_t offset, const T& value) noexcept {
        if (offset > image.size() || sizeof(value) > image.size() - offset) { ownershipError = true; return; }
        std::memcpy(image.data() + offset, &value, sizeof(value));
    }
    template<class T> T Get(std::size_t offset) noexcept {
        T value{};
        if (offset > image.size() || sizeof(value) > image.size() - offset) { ownershipError = true; return value; }
        std::memcpy(&value, image.data() + offset, sizeof(value)); return value;
    }
    static bool Enumerate(void* context, const wchar_t* leaf, ClientModuleCandidate* output,
        std::uint32_t* count, DWORD* error) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        ++f.enumerations;
        if (std::wcscmp(leaf, kLeaf)) f.ownershipError = true;
        if (f.enumerations > 1 && (!f.held || !f.fileOpen)) f.ownershipError = true;
        if (f.enumerations == f.failEnumerationAt) { *error = ERROR_BAD_LENGTH; return false; }
        if (f.delayedEnumeration && f.enumerations == 1) f.now += 5000;
        *count = f.candidateCount;
        *output = {kModule + (f.changedModule && f.enumerations > 1 ? 0x10000 : 0),
            f.changedImageSize && f.enumerations > 1 ? kSize + 0x1000 : kSize};
        *error = ERROR_SUCCESS; return true;
    }
    static bool Retain(void* context, std::uintptr_t base, HMODULE* output, DWORD* error) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        ++f.retains;
        if (base != kModule || f.held) f.ownershipError = true;
        *output = nullptr;
        if (f.failRetain) { *error = ERROR_MOD_NOT_FOUND; return false; }
        f.held = true;
        *output = reinterpret_cast<HMODULE>(kModule + (f.wrongRetain ? 0x10000 : 0));
        *error = ERROR_SUCCESS; return true;
    }
    static bool Release(void* context, HMODULE module, DWORD* error) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        ++f.releases;
        const auto expected = kModule + (f.wrongRetain ? 0x10000 : 0);
        if (!f.held || f.fileOpen || reinterpret_cast<std::uintptr_t>(module) != expected) f.ownershipError = true;
        if (f.expireAfterRelease) f.now += kHostHashSoftBudgetMs + 1;
        if (f.regressAfterRelease) f.now = 50;
        if (f.failRelease) { *error = ERROR_INVALID_HANDLE; return false; }
        f.held = false;
        *error = ERROR_SUCCESS; return true;
    }
    static bool Path(void* context, HMODULE module, wchar_t* output, std::size_t capacity, DWORD* error) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        ++f.paths;
        if (!f.held || reinterpret_cast<std::uintptr_t>(module) != kModule || (f.paths > 1 && !f.fileOpen))
            f.ownershipError = true;
        if (f.paths == f.failPathAt) { *error = ERROR_INSUFFICIENT_BUFFER; return false; }
        if (f.unterminatedPath) {
            for (std::size_t i = 0; i < capacity; ++i) output[i] = L'X';
            *error = ERROR_SUCCESS; return true;
        }
        const wchar_t* path = f.badPath ? L"relative\\rs2_fixture_client.dll" :
            f.paths == f.changePathAt ? L"D:\\Changed\\rs2_fixture_client.dll" : kPath;
        if (wcscpy_s(output, capacity, path)) { *error = ERROR_INSUFFICIENT_BUFFER; return false; }
        if (f.paths == 3) {
            if (f.changedHeader) {
                auto nt = f.Get<IMAGE_NT_HEADERS64>(0x80); ++nt.FileHeader.TimeDateStamp; f.Put(0x80, nt);
            }
            if (f.changedUnpinnedHeader) {
                auto dos = f.Get<IMAGE_DOS_HEADER>(0); dos.e_res[0] = 1; f.Put(0, dos);
            }
        }
        *error = ERROR_SUCCESS; return true;
    }
    static bool Query(void* context, std::uintptr_t address, MemoryRegion* output, DWORD* error) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        if (!f.held || !f.fileOpen) f.ownershipError = true;
        if (address < kModule || address - kModule >= f.image.size()) { *error = ERROR_NOACCESS; return false; }
        *output = {kModule, kModule, f.image.size(), MEM_COMMIT,
            f.wrongMemoryType ? DWORD{MEM_PRIVATE} : DWORD{MEM_IMAGE},
            f.wrongProtection ? DWORD{PAGE_READWRITE} : DWORD{PAGE_READONLY}};
        *error = ERROR_SUCCESS; return true;
    }
    static bool ReadMemory(void* context, std::uintptr_t address, void* output, std::size_t size, DWORD* error) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        if (!f.held || !f.fileOpen) f.ownershipError = true;
        if (f.failMemoryRead || address < kModule || address - kModule > f.image.size() ||
            size > f.image.size() - (address - kModule)) { *error = ERROR_PARTIAL_COPY; return false; }
        std::memcpy(output, f.image.data() + address - kModule, size);
        *error = ERROR_SUCCESS; return true;
    }
    static ULONGLONG Ticks(void* context) noexcept { return static_cast<Fixture*>(context)->now; }
    static HANDLE Open(void* context, const wchar_t* path, DWORD* error) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        ++f.opens;
        if (!f.held || f.fileOpen || std::wcscmp(path, kPath)) f.ownershipError = true;
        if (f.failOpen) { *error = ERROR_SHARING_VIOLATION; return INVALID_HANDLE_VALUE; }
        f.fileOpen = true; f.cursor = 0;
        *error = ERROR_SUCCESS; return reinterpret_cast<HANDLE>(0x1234);
    }
    static bool Metadata(void* context, HANDLE fileHandle, BY_HANDLE_FILE_INFORMATION* info, DWORD* error) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        ++f.metadata;
        if (!f.held || !f.fileOpen || fileHandle != reinterpret_cast<HANDLE>(0x1234)) f.ownershipError = true;
        if (f.metadata == f.failMetadataAt) { *error = ERROR_ACCESS_DENIED; return false; }
        *info = {};
        info->nNumberOfLinks = 1;
        info->nFileIndexLow = f.metadata == f.changeMetadataAt ? 42 : 41;
        info->dwVolumeSerialNumber = 7;
        info->nFileSizeLow = static_cast<DWORD>(f.file.size());
        *error = ERROR_SUCCESS; return true;
    }
    static bool ReadFile(void* context, HANDLE fileHandle, void* output, DWORD capacity, DWORD* got, DWORD* error) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        ++f.reads;
        if (!f.held || !f.fileOpen || fileHandle != reinterpret_cast<HANDLE>(0x1234)) f.ownershipError = true;
        if (f.expireInRead && f.reads == 1) f.now += f.delayedEnumeration ? 6000 : kHostHashSoftBudgetMs;
        if (f.failRead) { *error = ERROR_READ_FAULT; return false; }
        const auto remaining = f.file.size() - f.cursor;
        *got = static_cast<DWORD>(remaining < capacity ? remaining : capacity);
        if (*got) std::memcpy(output, f.file.data() + f.cursor, *got);
        f.cursor += *got;
        *error = ERROR_SUCCESS; return true;
    }
    static void Close(void* context, HANDLE fileHandle) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        ++f.closes;
        if (!f.fileOpen || !f.held || fileHandle != reinterpret_cast<HANDLE>(0x1234)) f.ownershipError = true;
        f.fileOpen = false;
    }
    ClientModuleTestOps Modules() noexcept { return {this, Enumerate, Retain, Release, Path}; }
    MemoryOps Memory() noexcept { return {this, Query, ReadMemory}; }
    HostHashOps Hash() noexcept { return {this, Ticks, Open, Metadata, ReadFile, Close}; }
    ClientQualification Run() {
        auto expected = identity;
        if (wrongDigest) expected.digest[0] ^= 1;
        const auto result = QualifyLoadedSteamClientForTest(expected, Modules(), Memory(), Hash());
        RS2_CHECK(!ownershipError && !fileOpen);
        RS2_CHECK(closes == (opens && !failOpen ? 1U : 0U));
        RS2_CHECK(releases == (retains && !failRetain ? 1U : 0U));
        RS2_CHECK(held == (failRelease && result.referenceAcquired));
        return result;
    }
};

void QualifiedAndCleaned() {
    Fixture f;
    const auto result = f.Run();
    RS2_CHECK(result.reason == Reason::None && result.error == ERROR_SUCCESS);
    RS2_CHECK(result.referenceAcquired && result.referenceReleased && f.releases == 1 && f.closes == 1);
    RS2_CHECK(result.moduleToken == kModule && result.fileSize == f.file.size() && result.digest == f.identity.digest);
    RS2_CHECK(result.imageSize == kSize && result.timestamp == kStamp && result.checksum == kChecksum);
    RS2_CHECK(f.enumerations == 2 && f.paths == 3 && f.metadata == 3 && result.elapsedMs == 0);
}
void ModuleAndPathFailures() {
    for (const auto count : {0U, 2U}) {
        Fixture f; f.candidateCount = count;
        const auto result = f.Run();
        RS2_CHECK(result.reason == Reason::SteamClientMismatch && !result.referenceAcquired && result.referenceReleased);
        RS2_CHECK(f.retains == 0 && f.opens == 0);
    }
    for (unsigned scenario = 0; scenario < 12; ++scenario) {
        Fixture f;
        switch (scenario) {
        case 0: f.failEnumerationAt = 1; break;
        case 1: f.failRetain = true; break;
        case 2: f.wrongRetain = true; break;
        case 3: f.failPathAt = 1; break;
        case 4: f.badPath = true; break;
        case 5: f.unterminatedPath = true; break;
        case 6: f.failEnumerationAt = 2; break;
        case 7: f.changePathAt = 2; break;
        case 8: f.changePathAt = 3; break;
        case 9: f.changedModule = true; break;
        case 10: f.changedImageSize = true; break;
        case 11: f.failPathAt = 3; break;
        }
        const auto result = f.Run();
        RS2_CHECK(result.reason == Reason::SteamClientMismatch && result.referenceReleased);
        RS2_CHECK(result.digest == Sha256Digest{} && result.moduleToken == 0);
    }
}
void HashHeaderAndLeaseFailures() {
    for (unsigned scenario = 0; scenario < 11; ++scenario) {
        Fixture f;
        switch (scenario) {
        case 0: f.failOpen = true; break;
        case 1: f.failRead = true; break;
        case 2: f.failMetadataAt = 1; break;
        case 3: f.changeMetadataAt = 2; break;
        case 4: f.changeMetadataAt = 3; break;
        case 5: f.wrongDigest = true; break;
        case 6: f.failMemoryRead = true; break;
        case 7: f.wrongMemoryType = true; break;
        case 8: f.wrongProtection = true; break;
        case 9: f.changedHeader = true; break;
        case 10: f.changedUnpinnedHeader = true; break;
        }
        const auto result = f.Run();
        RS2_CHECK(result.reason == Reason::SteamClientMismatch && result.referenceReleased);
    }
    { Fixture f; auto nt = f.Get<IMAGE_NT_HEADERS64>(0x80); nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386; f.Put(0x80, nt);
      RS2_CHECK(f.Run().reason == Reason::SteamClientMismatch); }
    { Fixture f; auto nt = f.Get<IMAGE_NT_HEADERS64>(0x80);
      nt.FileHeader.Characteristics = static_cast<WORD>(nt.FileHeader.Characteristics & ~IMAGE_FILE_DLL); f.Put(0x80, nt);
      RS2_CHECK(f.Run().reason == Reason::SteamClientMismatch); }
    { Fixture f; auto nt = f.Get<IMAGE_NT_HEADERS64>(0x80); ++nt.OptionalHeader.CheckSum; f.Put(0x80, nt);
      RS2_CHECK(f.Run().reason == Reason::SteamClientMismatch); }
    { Fixture f; auto dos = f.Get<IMAGE_DOS_HEADER>(0); dos.e_lfanew = 0x7FFFFFFF; f.Put(0, dos);
      RS2_CHECK(f.Run().reason == Reason::SteamClientMismatch); }
}
void BudgetAndReleaseFailures() {
    for (unsigned scenario = 0; scenario < 3; ++scenario) {
        Fixture f;
        if (scenario < 2) f.expireInRead = true;
        if (scenario == 1) f.delayedEnumeration = true;
        if (scenario == 2) f.expireAfterRelease = true;
        const auto result = f.Run();
        RS2_CHECK(result.reason == Reason::SteamClientMismatch && result.error == ERROR_TIMEOUT);
        RS2_CHECK(result.elapsedMs >= kHostHashSoftBudgetMs && result.referenceReleased);
        RS2_CHECK(result.moduleToken == 0 && result.digest == Sha256Digest{});
    }
    { Fixture f; f.regressAfterRelease = true; RS2_CHECK(f.Run().reason == Reason::ClockFailed); }
    { Fixture f; f.failRelease = true;
      const auto result = f.Run();
      RS2_CHECK(result.reason == Reason::SteamClientMismatch && result.referenceAcquired && !result.referenceReleased);
      RS2_CHECK(result.error == ERROR_INVALID_HANDLE && f.releases == 1 && f.closes == 1); }
    { Fixture f; auto ops = f.Modules(); ops.release = nullptr;
      const auto result = QualifyLoadedSteamClientForTest(f.identity, ops, f.Memory(), f.Hash());
      RS2_CHECK(result.reason == Reason::PreparationFailed && f.enumerations == 0 && f.opens == 0); }
}
} // namespace

void ReportingClientTests() {
    QualifiedAndCleaned();
    ModuleAndPathFailures();
    HashHeaderAndLeaseFailures();
    BudgetAndReleaseFailures();
}
