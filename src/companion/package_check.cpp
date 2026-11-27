#include "companion/package_check.h"

#include "companion/host_hash.h"
#include "companion/sha256.h"
#include "shared/path_identity.h"
#include "shared/version.h"

#include <cstdio>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <limits>

namespace rs2fix {
namespace {

bool Protect(void*, std::uintptr_t address, std::size_t size, DWORD protection,
             DWORD* previous, DWORD* error) noexcept {
    if (!VirtualProtect(reinterpret_cast<void*>(address), size, protection, previous)) {
        *error = GetLastError();
        return false;
    }
    *error = ERROR_SUCCESS;
    return true;
}
bool WriteBytes(void*, std::uintptr_t address, const void* bytes, std::size_t size,
                DWORD* error) noexcept {
    // Only on the startup thread inside the exe CRT initializer (proved by the
    // caller immediately before): TickServerRanking cannot have run, so no
    // thread can execute these bytes while they are partially written.
    std::memcpy(reinterpret_cast<void*>(address), bytes, size);
    *error = ERROR_SUCCESS;
    return true;
}
bool Flush(void*, std::uintptr_t address, std::size_t size, DWORD* error) noexcept {
    if (!FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<const void*>(address), size)) {
        *error = GetLastError();
        return false;
    }
    *error = ERROR_SUCCESS;
    return true;
}
FixReason Stable(void* context, DWORD* error) noexcept {
    if (!context) return FixReason::HostIdentityChanged;
    return static_cast<HostHashLease*>(context)->ValidateStable(error);
}

using FunctionBytes = std::array<std::uint8_t, kPackageCheckFunctionCapacity>;

bool InImage(const StartupProfile& startup, std::uint32_t rva, std::size_t size) noexcept {
    return static_cast<std::uint64_t>(rva) + size <= startup.imageSize;
}
bool Inside(const PackageCheckProfile& profile, std::uint32_t rva, std::size_t size) noexcept {
    return rva >= profile.functionRva && static_cast<std::uint64_t>(rva) + size <=
        static_cast<std::uint64_t>(profile.functionRva) + profile.functionSize;
}
bool ProfileValid(const PackageCheckProfile& profile, const StartupProfile& startup) noexcept {
    return profile.functionSize >= kPackageCheckStubSize &&
        profile.functionSize <= kPackageCheckFunctionCapacity &&
        InImage(startup, profile.functionRva, profile.functionSize) &&
        Inside(profile, profile.passedStoreRva, kPackageCheckStoreSize) &&
        Inside(profile, profile.greyStoreRva, kPackageCheckStoreSize) &&
        Inside(profile, profile.clearRva, kPackageCheckClearSize) &&
        InImage(startup, profile.passedRva, 4) && InImage(startup, profile.greyRva, 4) &&
        InImage(startup, profile.waitingRva, 16) && InImage(startup, profile.removeRva, 1) &&
        !Inside(profile, profile.removeRva, 1);
}

// rel32 of an instruction that ends at nextRva and addresses targetRva.
bool Displacement(std::uint64_t targetRva, std::uint64_t nextRva, std::int32_t* output) noexcept {
    const auto delta = static_cast<std::int64_t>(targetRva) - static_cast<std::int64_t>(nextRva);
    if (delta < (std::numeric_limits<std::int32_t>::min)() ||
        delta > (std::numeric_limits<std::int32_t>::max)()) return false;
    *output = static_cast<std::int32_t>(delta);
    return true;
}
// The ORIGINAL instruction at rva is opcode, then a rel32 resolving to target.
bool Reference(const FunctionBytes& code, const PackageCheckProfile& profile, std::uint32_t rva,
    const std::uint8_t* opcode, std::size_t opcodeSize, std::size_t length,
    std::uint64_t target) noexcept {
    const std::size_t offset = rva - profile.functionRva;
    std::int32_t actual{}, expected{};
    std::memcpy(&actual, code.data() + offset + opcodeSize, sizeof(actual));
    return std::memcmp(code.data() + offset, opcode, opcodeSize) == 0 &&
        Displacement(target, static_cast<std::uint64_t>(rva) + length, &expected) && actual == expected;
}
// The stub's targets are exactly the ones the original function itself uses.
bool ReferencesMatch(const FunctionBytes& code, const PackageCheckProfile& profile) noexcept {
    constexpr std::uint8_t store[]{0x44, 0x89, 0x35};      // mov dword [rel], r14d
    constexpr std::uint8_t loadCount[]{0x44, 0x8B, 0x05};  // mov r8d, dword [rel]
    constexpr std::uint8_t zeroIndex[]{0x33, 0xD2};        // xor edx, edx
    constexpr std::uint8_t loadArray[]{0x48, 0x8D, 0x0D};  // lea rcx, [rel]
    constexpr std::uint8_t call[]{0xE8};
    const std::size_t clear = profile.clearRva - profile.functionRva;
    return Reference(code, profile, profile.passedStoreRva, store, 3, 7, profile.passedRva) &&
        Reference(code, profile, profile.greyStoreRva, store, 3, 7, profile.greyRva) &&
        Reference(code, profile, profile.clearRva, loadCount, 3, 7,
            static_cast<std::uint64_t>(profile.waitingRva) + 8) &&
        std::memcmp(code.data() + clear + 7, zeroIndex, sizeof(zeroIndex)) == 0 &&
        Reference(code, profile, profile.clearRva + 9, loadArray, 3, 7, profile.waitingRva) &&
        Reference(code, profile, profile.clearRva + 16, call, 1, 5, profile.removeRva);
}

bool BytesEqual(std::uintptr_t base, const StartupProfile& startup,
    const PackageCheckProfile& profile, const FunctionBytes& expected,
    FunctionBytes* scratch, const PackageCheckOps& ops, DWORD* error) noexcept {
    return ReadImageRange(base, startup.imageSize, profile.functionRva,
        scratch->data(), profile.functionSize, ops.memory, error) &&
        std::memcmp(scratch->data(), expected.data(), profile.functionSize) == 0;
}
bool WritableCode(std::uintptr_t base, const StartupProfile& startup,
    const PackageCheckProfile& profile, const PackageCheckOps& ops, DWORD* error) noexcept {
    return ImageRangeProtection(base, startup.imageSize, profile.functionRva,
               kPackageCheckStubSize, PAGE_EXECUTE_READWRITE, ops.memory, error) ||
        ImageRangeProtection(base, startup.imageSize, profile.functionRva,
               kPackageCheckStubSize, PAGE_EXECUTE_WRITECOPY, ops.memory, error);
}
bool OriginalProtection(std::uintptr_t base, const StartupProfile& startup,
    const PackageCheckProfile& profile, const PackageCheckOps& ops, DWORD* error) noexcept {
    return ImageRangeProtection(base, startup.imageSize, profile.functionRva,
        profile.functionSize, PAGE_EXECUTE_READ, ops.memory, error);
}
bool TargetsMatch(std::uintptr_t base, const StartupProfile& startup,
    const PackageCheckProfile& profile, const PackageCheckOps& ops, DWORD* error) noexcept {
    constexpr DWORD code = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    constexpr DWORD notCode = IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_DISCARDABLE;
    constexpr DWORD data = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    constexpr DWORD notData = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_DISCARDABLE;
    const auto size = startup.imageSize;
    return ImageSectionMatches(base, size, profile.functionRva, profile.functionSize,
            code, notCode, ops.memory) &&
        ImageSectionMatches(base, size, profile.removeRva, 1, code, notCode, ops.memory) &&
        ImageRangeProtection(base, size, profile.removeRva, 1, PAGE_EXECUTE_READ, ops.memory, error) &&
        ImageSectionMatches(base, size, profile.passedRva, 4, data, notData, ops.memory) &&
        ImageSectionMatches(base, size, profile.greyRva, 4, data, notData, ops.memory) &&
        ImageSectionMatches(base, size, profile.waitingRva, 16, data, notData, ops.memory);
}

bool RecoverWithoutWrite(std::uintptr_t base, const StartupProfile& startup,
    const PackageCheckProfile& profile, const FunctionBytes& original, FunctionBytes* scratch,
    const PackageCheckOps& ops, DWORD* error) noexcept {
    const auto originalState = [&]() noexcept {
        return OriginalProtection(base, startup, profile, ops, error) &&
            BytesEqual(base, startup, profile, original, scratch, ops, error);
    };
    if (originalState() || originalState()) return true;
    if (!WritableCode(base, startup, profile, ops, error)) return false;
    DWORD ignored{};
    (void)ops.protect(ops.context, base + profile.functionRva, kPackageCheckStubSize,
        PAGE_EXECUTE_READ, &ignored, error);
    // No byte write was attempted, so there is no new code to flush.
    return originalState() || originalState();
}

bool Rollback(std::uintptr_t base, const StartupProfile& startup,
    const PackageCheckProfile& profile, const FunctionBytes& original, FunctionBytes* scratch,
    const PackageCheckOps& ops, DWORD* error) noexcept {
    DWORD ignored{};
    // One bounded rollback attempt. An API failure is not converted into success.
    if (!ops.protect(ops.context, base + profile.functionRva, kPackageCheckStubSize,
            PAGE_EXECUTE_READWRITE, &ignored, error) ||
        !WritableCode(base, startup, profile, ops, error) ||
        !ops.writeBytes(ops.context, base + profile.functionRva, original.data(),
            kPackageCheckStubSize, error) ||
        !BytesEqual(base, startup, profile, original, scratch, ops, error)) return false;
    return ops.protect(ops.context, base + profile.functionRva, kPackageCheckStubSize,
            PAGE_EXECUTE_READ, &ignored, error) &&
        OriginalProtection(base, startup, profile, ops, error) &&
        BytesEqual(base, startup, profile, original, scratch, ops, error) &&
        ops.flush(ops.context, base + profile.functionRva, profile.functionSize, error);
}

constexpr wchar_t kConfigLeaf[] = L"RS2PackageCheck.ini";
constexpr std::size_t kConfigBytes = 256;
bool Space(char c) noexcept { return c == ' ' || c == '\t'; }
// ASCII-only, locale-independent; UE3-style INI keys and booleans are case-insensitive.
bool EqualIgnoreCase(const char* data, std::size_t count, const char* word) noexcept {
    const auto size = std::strlen(word);
    if (count != size) return false;
    for (std::size_t i = 0; i < size; ++i) {
        char left = data[i], right = word[i];
        if (left >= 'A' && left <= 'Z') left = static_cast<char>(left - 'A' + 'a');
        if (right >= 'A' && right <= 'Z') right = static_cast<char>(right - 'A' + 'a');
        if (left != right) return false;
    }
    return true;
}

bool WriteLog(const wchar_t* directory, DWORD processId, const ConsoleReportContext& line,
    const MarkerFileOps& ops) noexcept {
    if (!directory || !ops.createAlways || !ops.write || !ops.flush || !ops.close || !ops.remove)
        return false;
    wchar_t leaf[64]{};
    const int leafLength = swprintf_s(leaf, L"RS2ServerFix.packagecheck.%lu.log",
        static_cast<unsigned long>(processId));
    auto* path = static_cast<wchar_t*>(VirtualAlloc(nullptr, kPathCapacity * sizeof(wchar_t),
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (leafLength <= 0 || !path) {
        if (path) VirtualFree(path, 0, MEM_RELEASE);
        return false;
    }
    DWORD error{};
    bool written = false;
    if (AppendPathLeaf(directory, kPathCapacity, leaf, std::size(leaf), path, kPathCapacity, &error)) {
        const HANDLE file = ops.createAlways(ops.context, path, &error);
        if (file && file != INVALID_HANDLE_VALUE) {
            DWORD count{};
            written = ops.write(ops.context, file, line.line, line.bytes, &count, &error) &&
                count == line.bytes && ops.flush(ops.context, file, &error);
            written = ops.close(ops.context, file, &error) && written;
            // Never leave a truncated line that could be read as a verdict.
            if (!written) (void)ops.remove(ops.context, path, &error);
        }
    }
    VirtualFree(path, 0, MEM_RELEASE);
    return written;
}

ReporterStorage g_packageReporter{};

} // namespace

PackageCheckOps ProductionPackageCheckOps(HostHashLease* lease) noexcept {
    return {ProductionMemoryOps(), lease, Protect, WriteBytes, Flush, Stable};
}

const PackageCheckProfile* SelectedPackageCheckProfile(const Sha256Digest& hostDigest) noexcept {
#if defined(RS2_STARTUP_TEST_PROFILE)
    (void)hostDigest;
    return nullptr;
#else
    if (hostDigest == kFullDumpPackageCheckProfile.hostDigest) return &kFullDumpPackageCheckProfile;
    if (hostDigest == kStockPackageCheckProfile.hostDigest) return &kStockPackageCheckProfile;
    return nullptr;
#endif
}

bool BuildPackageCheckStub(const PackageCheckProfile& profile, PackageCheckStub* stub) noexcept {
    if (!stub) return false;
    *stub = {};
    const std::uint64_t at = profile.functionRva;
    std::int32_t passed{}, grey{}, count{}, array{}, remove{};
    if (!Displacement(profile.passedRva, at + 10, &passed) ||
        !Displacement(profile.greyRva, at + 20, &grey) ||
        !Displacement(static_cast<std::uint64_t>(profile.waitingRva) + 8, at + 27, &count) ||
        !Displacement(profile.waitingRva, at + 36, &array) ||
        !Displacement(profile.removeRva, at + kPackageCheckStubSize, &remove)) return false;
    std::size_t cursor = 0;
    const auto put = [&](const void* bytes, std::size_t size) noexcept {
        std::memcpy(stub->data() + cursor, bytes, size);
        cursor += size;
    };
    constexpr std::uint8_t storeImmediate[]{0xC7, 0x05};
    constexpr std::uint8_t loadCount[]{0x44, 0x8B, 0x05};
    constexpr std::uint8_t zeroIndex[]{0x33, 0xD2};
    constexpr std::uint8_t loadArray[]{0x48, 0x8D, 0x0D};
    constexpr std::uint8_t jump[]{0xE9};
    constexpr std::uint32_t passedValue = 1, greyValue = 0;
    put(storeImmediate, 2); put(&passed, 4); put(&passedValue, 4); // mov dword [passed], 1
    put(storeImmediate, 2); put(&grey, 4); put(&greyValue, 4);     // mov dword [grey], 0
    put(loadCount, 3); put(&count, 4);                             // mov r8d, [Waiting.ArrayNum]
    put(zeroIndex, 2);                                             // xor edx, edx
    put(loadArray, 3); put(&array, 4);                             // lea rcx, [Waiting]
    put(jump, 1); put(&remove, 4);                                 // jmp TArray<FString>::Remove
    return cursor == kPackageCheckStubSize;
}

ReconResult RunPackageCheckBypass(const BootstrapContextV3& context,
    const StartupProfile& startup, const PackageCheckProfile& profile, ReconMode mode,
    const Sha256Digest& hostDigest, const PackageCheckOps& ops) noexcept {
    ReconResult result{};
    if ((mode != ReconMode::Passive && mode != ReconMode::Active) ||
        !ops.protect || !ops.writeBytes || !ops.flush || !ops.validateHostIdentity ||
        !ProfileValid(profile, startup)) return result;
    if (hostDigest != profile.hostDigest) {
        result.reason = FixReason::UnsupportedHost;
        return result;
    }
    if (CheckStartupOpportunity(context, startup, ops.memory) != StartupGateResult::Ready) {
        result.reason = FixReason::StartupRejected;
        return result;
    }
    const auto base = reinterpret_cast<std::uintptr_t>(context.hostModule);
    if (!OriginalProtection(base, startup, profile, ops, &result.error) ||
        !TargetsMatch(base, startup, profile, ops, &result.error)) {
        result.reason = FixReason::ProtectionMismatch;
        return result;
    }
    FunctionBytes original{}, expected{}, scratch{};
    if (!ReadImageRange(base, startup.imageSize, profile.functionRva,
            original.data(), profile.functionSize, ops.memory, &result.error)) {
        result.reason = FixReason::CodeUnreadable;
        return result;
    }
    Sha256Digest digest{};
    if (!HashBytesSha256(original.data(), profile.functionSize, &digest, &result.error) ||
        digest != profile.originalDigest || !ReferencesMatch(original, profile)) {
        result.reason = FixReason::FunctionMismatch;
        return result;
    }
    PackageCheckStub stub{};
    expected = original;
    if (!BuildPackageCheckStub(profile, &stub)) {
        result.reason = FixReason::PreparedDigestMismatch;
        return result;
    }
    std::memcpy(expected.data(), stub.data(), stub.size());
    if (!HashBytesSha256(expected.data(), profile.functionSize, &digest, &result.error) ||
        digest != profile.patchedDigest) {
        result.reason = FixReason::PreparedDigestMismatch;
        return result;
    }
    result.reason = ops.validateHostIdentity(ops.context, &result.error);
    if (result.reason != FixReason::None) return result;
    if (CheckStartupOpportunity(context, startup, ops.memory) != StartupGateResult::Ready) {
        result.reason = FixReason::StartupRejected;
        return result;
    }
    if (!OriginalProtection(base, startup, profile, ops, &result.error) ||
        !BytesEqual(base, startup, profile, original, &scratch, ops, &result.error)) {
        result.reason = FixReason::ReadbackFailed;
        return result;
    }
    result.qualified = true;
    if (mode == ReconMode::Passive) {
        result.outcome = ReconOutcome::Passive;
        result.reason = FixReason::None;
        result.error = ERROR_SUCCESS;
        return result;
    }

    // All hashing, allocation and file work is finished before changing protection.
    DWORD oldProtection{};
    FixReason failure = FixReason::ProtectFailed;
    bool writeAttempted = false;
    const auto writeStub = [&]() noexcept {
        // An API failure may still have changed bytes; claim the attempt first.
        writeAttempted = true;
        return ops.writeBytes(ops.context, base + profile.functionRva, stub.data(),
            stub.size(), &result.error);
    };
    if (!ops.protect(ops.context, base + profile.functionRva, kPackageCheckStubSize,
            PAGE_EXECUTE_READWRITE, &oldProtection, &result.error)) {
        const DWORD protectError = result.error;
        if (OriginalProtection(base, startup, profile, ops, &result.error) &&
            BytesEqual(base, startup, profile, original, &scratch, ops, &result.error)) {
            result.reason = failure;
            result.error = protectError;
            return result;
        }
    } else if (oldProtection != PAGE_EXECUTE_READ ||
               !WritableCode(base, startup, profile, ops, &result.error)) {
        failure = FixReason::ProtectionMismatch;
    } else {
        DWORD stage{};
        if (GetCurrentThreadId() != context.startupThreadId ||
            !ReadImageRange(base, startup.imageSize, startup.stateRva, &stage,
                sizeof(stage), ops.memory, &result.error) || stage != startup.stateValue) {
            failure = FixReason::StartupRejected;
        } else if (!BytesEqual(base, startup, profile, original, &scratch, ops, &result.error)) {
            failure = FixReason::ReadbackFailed;
        } else if (!writeStub()) {
            failure = FixReason::WriteFailed;
        } else if (!BytesEqual(base, startup, profile, expected, &scratch, ops, &result.error)) {
            failure = FixReason::ReadbackFailed;
        } else {
            DWORD ignored{};
            if (!ops.protect(ops.context, base + profile.functionRva, kPackageCheckStubSize,
                    PAGE_EXECUTE_READ, &ignored, &result.error) ||
                !OriginalProtection(base, startup, profile, ops, &result.error) ||
                !BytesEqual(base, startup, profile, expected, &scratch, ops, &result.error)) {
                failure = FixReason::RestoreFailed;
            } else if (!ops.flush(ops.context, base + profile.functionRva,
                       profile.functionSize, &result.error)) {
                failure = FixReason::FlushFailed;
            } else {
                // Validate the SAME retained host handle again before publishing active.
                failure = ops.validateHostIdentity(ops.context, &result.error);
                if (failure == FixReason::None) {
                    result.outcome = ReconOutcome::Active;
                    result.reason = FixReason::None;
                    result.error = ERROR_SUCCESS;
                    return result;
                }
            }
        }
    }
    const DWORD failureError = result.error;
    if (!writeAttempted) {
        if (RecoverWithoutWrite(base, startup, profile, original, &scratch, ops, &result.error)) {
            result.outcome = ReconOutcome::Disabled;
            result.reason = failure;
            result.error = failureError;
        } else {
            result.outcome = ReconOutcome::Fatal;
            result.reason = FixReason::RollbackFailed;
        }
        return result;
    }
    if (Rollback(base, startup, profile, original, &scratch, ops, &result.error)) {
        result.outcome = ReconOutcome::RolledBack;
        result.reason = failure;
        result.error = failureError;
    } else {
        result.outcome = ReconOutcome::Fatal;
        result.reason = FixReason::RollbackFailed;
    }
    return result;
}

PackageCheckConfig ParsePackageCheckConfig(const char* bytes, std::size_t size) noexcept {
    if ((!bytes && size) || size > kConfigBytes) return PackageCheckConfig::Invalid;
    PackageCheckConfig selected = PackageCheckConfig::Absent;
    bool seen = false;
    std::size_t cursor = 0;
    // Notepad's "UTF-8 with BOM"; the content itself must still be plain ASCII.
    if (size >= 3 && static_cast<unsigned char>(bytes[0]) == 0xEF &&
        static_cast<unsigned char>(bytes[1]) == 0xBB && static_cast<unsigned char>(bytes[2]) == 0xBF)
        cursor = 3;
    while (cursor < size) {
        const auto start = cursor;
        while (cursor < size && bytes[cursor] != '\n') {
            const auto c = static_cast<unsigned char>(bytes[cursor]);
            if (c > 126 || (c < 32 && c != '\t' && c != '\r')) return PackageCheckConfig::Invalid;
            ++cursor;
        }
        auto first = start, last = cursor;
        if (cursor < size) ++cursor;
        if (last > first && bytes[last - 1] == '\r') --last;
        while (first < last && Space(bytes[first])) ++first;
        while (first < last && Space(bytes[last - 1])) --last;
        if (first == last || bytes[first] == ';' || bytes[first] == '#') continue;
        if (bytes[first] == '[') {
            if (bytes[last - 1] != ']') return PackageCheckConfig::Invalid;
            continue;
        }
        auto equal = first;
        while (equal < last && bytes[equal] != '=') ++equal;
        if (equal == last || seen) return PackageCheckConfig::Invalid;
        auto keyEnd = equal, value = equal + 1;
        while (keyEnd > first && Space(bytes[keyEnd - 1])) --keyEnd;
        while (value < last && Space(bytes[value])) ++value;
        if (!EqualIgnoreCase(bytes + first, keyEnd - first, "AllowAnyMutator"))
            return PackageCheckConfig::Invalid;
        const std::size_t count = last - value;
        if (EqualIgnoreCase(bytes + value, count, "true") || EqualIgnoreCase(bytes + value, count, "1"))
            selected = PackageCheckConfig::Enabled;
        else if (EqualIgnoreCase(bytes + value, count, "false") || EqualIgnoreCase(bytes + value, count, "0"))
            selected = PackageCheckConfig::Disabled;
        else return PackageCheckConfig::Invalid;
        seen = true;
    }
    return selected;
}

PackageCheckConfig ReadPackageCheckConfig(const wchar_t* directory, DWORD* error) noexcept {
    DWORD localError = ERROR_INVALID_PARAMETER;
    PackageCheckConfig result = PackageCheckConfig::Invalid;
    auto* path = directory ? static_cast<wchar_t*>(VirtualAlloc(nullptr,
        kPathCapacity * sizeof(wchar_t), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) : nullptr;
    if (directory && !path) localError = GetLastError();
    if (path && AppendPathLeaf(directory, kPathCapacity, kConfigLeaf, std::size(kConfigLeaf),
            path, kPathCapacity, &localError)) {
        const HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        localError = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        if (file == INVALID_HANDLE_VALUE) {
            // Absent keeps the stock check (opt-in). Other open failures are
            // reported as invalid; both leave the stock game untouched.
            if (localError == ERROR_FILE_NOT_FOUND) {
                result = PackageCheckConfig::Absent;
                localError = ERROR_SUCCESS;
            }
        } else {
            BY_HANDLE_FILE_INFORMATION info{};
            LARGE_INTEGER size{};
            char bytes[kConfigBytes]{};
            DWORD read{};
            if (GetFileInformationByHandle(file, &info) &&
                !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
                GetFileSizeEx(file, &size) && size.QuadPart >= 0 && size.QuadPart <= kConfigBytes &&
                (size.QuadPart == 0 ||
                    (ReadFile(file, bytes, static_cast<DWORD>(size.QuadPart), &read, nullptr) &&
                     read == static_cast<DWORD>(size.QuadPart)))) {
                result = ParsePackageCheckConfig(bytes, read);
            } else {
                localError = ERROR_INVALID_DATA;
            }
            if (!CloseHandle(file)) {
                result = PackageCheckConfig::Invalid;
                localError = GetLastError();
            }
            if (result == PackageCheckConfig::Invalid && localError == ERROR_SUCCESS)
                localError = ERROR_INVALID_DATA;
        }
    }
    if (path) VirtualFree(path, 0, MEM_RELEASE);
    if (error) *error = localError;
    return result;
}

const char* PackageCheckConfigName(PackageCheckConfig config) noexcept {
    switch (config) {
    case PackageCheckConfig::Unread: return "unread";
    case PackageCheckConfig::Absent: return "absent";
    case PackageCheckConfig::Enabled: return "true";
    case PackageCheckConfig::Disabled: return "false";
    case PackageCheckConfig::Invalid: return "invalid";
    }
    return "invalid";
}

bool FormatPackageCheckLine(const PackageCheckReport& report, ConsoleReportContext* output) noexcept {
    if (!output) return false;
    *output = {};
    if (static_cast<unsigned>(report.host) > static_cast<unsigned>(BuildIdentity::Indeterminate) ||
        static_cast<unsigned>(report.mode) > static_cast<unsigned>(ReconMode::Active) ||
        static_cast<unsigned>(report.config) > static_cast<unsigned>(PackageCheckConfig::Invalid) ||
        static_cast<unsigned>(report.result.outcome) > static_cast<unsigned>(ReconOutcome::Fatal) ||
        static_cast<unsigned>(report.result.reason) > static_cast<unsigned>(FixReason::RollbackFailed))
        return false;
    const char* outcome = ReconOutcomeName(report.result.outcome);
    const char* reason = FixReasonName(report.result.reason);
    switch (report.stage) {
    case PackageCheckStage::Skipped: outcome = "skipped"; reason = "recon_not_accepted"; break;
    case PackageCheckStage::ConfigOff:
        outcome = "off";
        reason = report.config == PackageCheckConfig::Disabled ? "allow_any_mutator_false" :
            report.config == PackageCheckConfig::Absent ? "allow_any_mutator_absent" : "config_invalid";
        break;
    case PackageCheckStage::Ran: break;
    default: return false;
    }
    const int size = std::snprintf(output->line, sizeof(output->line),
        "[RS2PackageCheck] v%s package_check=%s reason=%s mode=%s allow_any_mutator=%s host=%s pid=%lu error=%lu\r\n",
        RS2FIX_VERSION_ASCII, outcome, reason, ReconModeName(report.mode),
        PackageCheckConfigName(report.config), BuildIdentityName(report.host),
        static_cast<unsigned long>(report.processId), static_cast<unsigned long>(report.result.error));
    if (size <= 0 || static_cast<std::size_t>(size) >= sizeof(output->line)) {
        *output = {};
        return false;
    }
    output->bytes = static_cast<DWORD>(size);
    if (!ValidConsoleReport(*output)) {
        *output = {};
        return false;
    }
    return true;
}

PackageCheckReport RunPackageCheckStartup(const BootstrapContextV3& context,
    const StartupProfile& startup, const MarkerData& marker, bool reconAccepted,
    HostHashLease* lease, const wchar_t* hostDirectory, ConsoleReportContext* line,
    const MarkerFileOps& fileOps) noexcept {
    PackageCheckReport report{};
    report.mode = marker.mode;
    report.host = marker.buildIdentity;
    report.processId = marker.processId;
    if (reconAccepted && lease && hostDirectory) {
        DWORD error{};
        report.config = ReadPackageCheckConfig(hostDirectory, &error);
        if (report.config != PackageCheckConfig::Enabled) {
            report.stage = PackageCheckStage::ConfigOff;
            report.result = {ReconOutcome::Disabled, FixReason::None, error, false};
        } else {
            report.stage = PackageCheckStage::Ran;
            const PackageCheckProfile* profile = SelectedPackageCheckProfile(marker.digest);
            report.result = profile
                ? RunPackageCheckBypass(context, startup, *profile, marker.mode, marker.digest,
                    ProductionPackageCheckOps(lease))
                : ReconResult{ReconOutcome::Disabled, FixReason::UnsupportedHost, ERROR_SUCCESS, false};
        }
    }
    ConsoleReportContext local{};
    ConsoleReportContext* formatted = line ? line : &local;
    if (FormatPackageCheckLine(report, formatted)) {
        (void)WriteLog(hostDirectory, report.processId, *formatted, fileOps);
        // Fatal is reported by the caller on its ready-console path, then fails fast.
        if (report.result.outcome != ReconOutcome::Fatal)
            (void)TryStartReporter(&g_packageReporter, *formatted, ProductionConsoleStatusOps());
    }
    return report;
}

} // namespace rs2fix
