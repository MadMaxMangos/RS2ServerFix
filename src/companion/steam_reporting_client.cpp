#include "companion/steam_reporting_client.h"
#include "companion/steam_reporting_profile.h"
#include "shared/selected_reporting_profile.h"
#include "shared/path_identity.h"

#include <TlHelp32.h>
#include <cstring>
#include <cwchar>
#include <limits>

namespace rs2fix::reporting {
namespace {
constexpr std::size_t kModuleLimit = 4096;
struct Identity {
    const wchar_t* leaf;
    Sha256Digest digest;
    std::uint32_t imageSize;
    std::uint32_t timestamp;
    std::uint32_t checksum;
};
#if defined(RS2_REPORTING_TESTING)
using Candidate = ClientModuleCandidate;
using ModuleOps = ClientModuleTestOps;
#else
struct Candidate { std::uintptr_t base; std::uint32_t imageSize; };
struct ModuleOps {
    void* context;
    bool (*enumerate)(void*, const wchar_t*, Candidate*, std::uint32_t*, DWORD*) noexcept;
    bool (*retain)(void*, std::uintptr_t, HMODULE*, DWORD*) noexcept;
    bool (*release)(void*, HMODULE, DWORD*) noexcept;
    bool (*path)(void*, HMODULE, wchar_t*, std::size_t, DWORD*) noexcept;
};
#endif

bool SameText(const wchar_t* a, const wchar_t* b) noexcept {
    return CompareStringOrdinal(a, -1, b, -1, TRUE) == CSTR_EQUAL;
}
bool Enumerate(void*, const wchar_t* leaf, Candidate* output, std::uint32_t* matches, DWORD* error) noexcept {
    *output = {}; *matches = 0;
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) { *error = GetLastError(); return false; }
    MODULEENTRY32W entry{}; entry.dwSize = sizeof(entry);
    bool ok = Module32FirstW(snapshot, &entry) != FALSE;
    DWORD failure = ok ? ERROR_SUCCESS : GetLastError();
    std::size_t seen{};
    while (ok) {
        if (++seen > kModuleLimit || wcsnlen_s(entry.szModule, MAX_MODULE_NAME32 + 1) >= MAX_MODULE_NAME32 + 1) {
            failure = ERROR_BUFFER_OVERFLOW; ok = false; break;
        }
        if (SameText(entry.szModule, leaf)) {
            ++*matches;
            *output = {reinterpret_cast<std::uintptr_t>(entry.modBaseAddr), entry.modBaseSize};
        }
        if (!Module32NextW(snapshot, &entry)) {
            failure = GetLastError();
            ok = failure == ERROR_NO_MORE_FILES;
            if (ok) failure = ERROR_SUCCESS;
            break;
        }
    }
    if (!CloseHandle(snapshot)) { failure = GetLastError(); ok = false; }
    *error = failure;
    return ok;
}
bool Retain(void*, std::uintptr_t base, HMODULE* output, DWORD* error) noexcept {
    *output = nullptr;
    HMODULE module{};
    const bool ok = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        reinterpret_cast<LPCWSTR>(base), &module) != FALSE;
    *error = ok ? ERROR_SUCCESS : GetLastError();
    if (ok) *output = module;
    return ok;
}
bool Release(void*, HMODULE module, DWORD* error) noexcept {
    const bool ok = FreeLibrary(module) != FALSE;
    *error = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}
bool Path(void*, HMODULE module, wchar_t* output, std::size_t capacity, DWORD* error) noexcept {
    return GetBoundedModulePath(module, output, capacity, error);
}
constexpr ModuleOps kModules{nullptr, Enumerate, Retain, Release, Path};

class ModuleLease {
public:
    explicit ModuleLease(const ModuleOps& ops) noexcept : ops_(ops) {}
    ~ModuleLease() noexcept { DWORD ignored{}; Close(&ignored); }
    bool Acquire(std::uintptr_t base, DWORD* error) noexcept {
        return ops_.retain(ops_.context, base, &module_, error) && module_ != nullptr;
    }
    HMODULE Get() const noexcept { return module_; }
    bool Close(DWORD* error) noexcept {
        if (attempted_) return released_;
        attempted_ = true;
        released_ = !module_ || ops_.release(ops_.context, module_, error);
        // A failed FreeLibrary is not retried blindly. Its uncertain outstanding
        // reference is reported and disqualifies the result, never called Ready.
        return released_;
    }
private:
    const ModuleOps& ops_;
    HMODULE module_{};
    bool attempted_{};
    bool released_{};
};
class PathStorage {
public:
    PathStorage() noexcept : bytes_(static_cast<wchar_t*>(VirtualAlloc(nullptr,
        2 * kPathCapacity * sizeof(wchar_t), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {}
    ~PathStorage() noexcept { if (bytes_) VirtualFree(bytes_, 0, MEM_RELEASE); }
    wchar_t* First() const noexcept { return bytes_; }
    wchar_t* Second() const noexcept { return bytes_ ? bytes_ + kPathCapacity : nullptr; }
private:
    wchar_t* bytes_;
};

class Budget {
public:
    explicit Budget(const HostHashOps& hash) noexcept : hash_(hash), start_(hash.ticks(hash.context)), last_(start_) {}
    Reason Check(DWORD* error) noexcept {
        const auto now = hash_.ticks(hash_.context);
        if (now < last_) { *error = ERROR_INVALID_TIME; return Reason::ClockFailed; }
        last_ = now;
        if (now - start_ >= kHostHashSoftBudgetMs) { *error = ERROR_TIMEOUT; return Reason::SteamClientMismatch; }
        return Reason::None;
    }
    std::uint64_t Elapsed() const noexcept { return last_ - start_; }
private:
    const HostHashOps& hash_;
    ULONGLONG start_;
    ULONGLONG last_;
};

bool QualifiedPath(const wchar_t* path, const wchar_t* leaf) noexcept {
    const auto length = wcsnlen_s(path, kPathCapacity);
    if (length < 4 || length >= kPathCapacity || path[1] != L':' || path[2] != L'\\' ||
        !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'))) return false;
    std::size_t start = 3;
    for (std::size_t i = 3; i < length; ++i) {
        if (path[i] == L'\\') {
            if (i == start) return false;
            start = i + 1;
        } else if (path[i] < 32 || path[i] == L':' || path[i] == L'/' || path[i] == L'*' || path[i] == L'?') return false;
    }
    return start < length && SameText(path + start, leaf);
}
bool ResidentHeaders(std::uintptr_t base, const Identity& identity, const MemoryOps& memory,
    IMAGE_DOS_HEADER& dos, IMAGE_NT_HEADERS64& nt, DWORD* error) noexcept {
    const auto size = identity.imageSize;
    if (!base || !size || size > (std::numeric_limits<std::uintptr_t>::max)() - base ||
        !ImageRangeProtection(base, size, 0, sizeof(dos), PAGE_READONLY, memory, error) ||
        !ReadImageRange(base, size, 0, &dos, sizeof(dos), memory, error) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < static_cast<LONG>(sizeof(dos)) || dos.e_lfanew > 0x100000)
        return false;
    const auto rva = static_cast<std::uint32_t>(dos.e_lfanew);
    if (!ImageRangeProtection(base, size, rva, sizeof(nt), PAGE_READONLY, memory, error) ||
        !ReadImageRange(base, size, rva, &nt, sizeof(nt), memory, error)) return false;
    return nt.Signature == IMAGE_NT_SIGNATURE && nt.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
        (nt.FileHeader.Characteristics & IMAGE_FILE_DLL) && (nt.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) &&
        nt.FileHeader.NumberOfSections > 0 && nt.FileHeader.NumberOfSections <= 96 &&
        nt.FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64) &&
        nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        nt.FileHeader.TimeDateStamp == identity.timestamp && nt.OptionalHeader.SizeOfImage == size &&
        nt.OptionalHeader.CheckSum == identity.checksum && nt.OptionalHeader.SizeOfHeaders <= size &&
        rva <= nt.OptionalHeader.SizeOfHeaders && sizeof(nt) <= nt.OptionalHeader.SizeOfHeaders - rva &&
        nt.OptionalHeader.NumberOfRvaAndSizes == IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
}

Reason Inspect(const Identity& identity, const ModuleOps& modules, const MemoryOps& memory,
    const HostHashOps& hashOps, Budget& budget, ModuleLease& module, ClientQualification& result) noexcept {
    Candidate before{};
    std::uint32_t count{};
    if (!modules.enumerate(modules.context, identity.leaf, &before, &count, &result.error) ||
        count != 1 || !before.base || before.imageSize != identity.imageSize) return Reason::SteamClientMismatch;
    auto reason = budget.Check(&result.error);
    if (reason != Reason::None) return reason;
    if (!module.Acquire(before.base, &result.error)) return Reason::SteamClientMismatch;
    result.referenceAcquired = true;
    if (reinterpret_cast<std::uintptr_t>(module.Get()) != before.base) return Reason::SteamClientMismatch;
    PathStorage paths;
    if (!paths.First()) { result.error = ERROR_NOT_ENOUGH_MEMORY; return Reason::PreparationFailed; }
    if (!modules.path(modules.context, module.Get(), paths.First(), kPathCapacity, &result.error) ||
        !QualifiedPath(paths.First(), identity.leaf)) return Reason::SteamClientMismatch;
    reason = budget.Check(&result.error);
    if (reason != Reason::None) return reason;
    HostHashLease file;
    const auto hashed = AcquireHostHash(paths.First(), &file, hashOps);
    if (hashed.reason != FixReason::None || !hashed.hash.digestValid || !file.valid()) {
        result.error = hashed.hash.error;
        return Reason::SteamClientMismatch;
    }
    if (hashed.hash.digest != identity.digest) { result.error = ERROR_INVALID_DATA; return Reason::SteamClientMismatch; }
    reason = budget.Check(&result.error);
    if (reason != Reason::None) return reason;
    // Initial path resolution was needed to open the file. These two identity
    // observations are both under its retained lease as well as the module ref.
    if (!modules.path(modules.context, module.Get(), paths.Second(), kPathCapacity, &result.error) ||
        !QualifiedPath(paths.Second(), identity.leaf) || !SameText(paths.First(), paths.Second())) return Reason::SteamClientMismatch;
    IMAGE_DOS_HEADER dosBefore{};
    IMAGE_NT_HEADERS64 ntBefore{};
    if (!ResidentHeaders(before.base, identity, memory, dosBefore, ntBefore, &result.error)) return Reason::SteamClientMismatch;
    Candidate after{};
    count = 0;
    if (!modules.enumerate(modules.context, identity.leaf, &after, &count, &result.error) ||
        count != 1 || after.base != before.base || after.imageSize != before.imageSize ||
        !modules.path(modules.context, module.Get(), paths.Second(), kPathCapacity, &result.error) ||
        !QualifiedPath(paths.Second(), identity.leaf) || !SameText(paths.First(), paths.Second())) return Reason::SteamClientMismatch;
    IMAGE_DOS_HEADER dosAfter{};
    IMAGE_NT_HEADERS64 ntAfter{};
    if (!ResidentHeaders(before.base, identity, memory, dosAfter, ntAfter, &result.error) ||
        std::memcmp(&dosBefore, &dosAfter, sizeof(dosBefore)) ||
        std::memcmp(&ntBefore, &ntAfter, sizeof(ntBefore)) ||
        file.ValidateStable(&result.error) != FixReason::None) return Reason::SteamClientMismatch;
    result.digest = hashed.hash.digest;
    result.fileSize = file.fileSize();
    result.moduleToken = before.base;
    result.imageSize = identity.imageSize;
    result.timestamp = identity.timestamp;
    result.checksum = identity.checksum;
    return Reason::None;
}

ClientQualification Qualify(const Identity& identity, const ModuleOps& modules,
    const MemoryOps& memory, const HostHashOps& hashOps) noexcept {
    ClientQualification result{};
    result.reason = Reason::PreparationFailed;
    result.error = ERROR_INVALID_PARAMETER;
    result.referenceReleased = true; // No reference exists yet.
    if (!identity.leaf || !identity.leaf[0] || !identity.imageSize || !modules.enumerate ||
        !modules.retain || !modules.release || !modules.path || !memory.read || !memory.query ||
        !hashOps.ticks || !hashOps.open || !hashOps.metadata || !hashOps.read || !hashOps.close) return result;
    Budget budget(hashOps);
    {
        ModuleLease module(modules);
        result.reason = Inspect(identity, modules, memory, hashOps, budget, module, result);
        // Inspect's file/path leases have already left scope. Release our module
        // reference explicitly so release failure is known BEFORE returning Ready.
        DWORD releaseError{};
        result.referenceReleased = module.Close(&releaseError);
        if (!result.referenceReleased) {
            result.reason = Reason::SteamClientMismatch;
            result.error = releaseError ? releaseError : ERROR_INVALID_HANDLE;
        }
    }
    DWORD timeError{};
    const auto timed = budget.Check(&timeError);
    result.elapsedMs = budget.Elapsed();
    if (timed != Reason::None && result.referenceReleased) { result.reason = timed; result.error = timeError; }
    if (result.reason == Reason::None) result.error = ERROR_SUCCESS;
    else {
        if (!result.error) result.error = ERROR_INVALID_DATA;
        result.digest = {}; result.fileSize = 0; result.moduleToken = 0;
        result.imageSize = 0; result.timestamp = 0; result.checksum = 0;
    }
    return result;
}
} // namespace

ClientQualification QualifyLoadedSteamClient() noexcept {
    const auto& expected = SelectedReportingIdentities();
    const Identity identity{kSelectedSteamClientLeaf, expected.steamClientDigest,
        expected.steamClientImageSize, expected.steamClientTimestamp, expected.steamClientChecksum};
    return Qualify(identity, kModules, ProductionMemoryOps(), ProductionHostHashOps());
}
#if defined(RS2_REPORTING_TESTING)
ClientQualification QualifyLoadedSteamClientForTest(const ClientTestIdentity& expected,
    const ClientModuleTestOps& modules, const MemoryOps& memory, const HostHashOps& hashOps) noexcept {
    const Identity identity{expected.leaf, expected.digest, expected.imageSize, expected.timestamp, expected.checksum};
    return Qualify(identity, modules, memory, hashOps);
}
#endif
} // namespace rs2fix::reporting
