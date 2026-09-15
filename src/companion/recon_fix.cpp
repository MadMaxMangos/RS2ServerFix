#include "companion/recon_fix.h"

#include "companion/host_hash.h"
#include "companion/sha256.h"

#include <array>
#include <cstring>
#include <intrin.h>

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
bool WriteDword(void*, std::uintptr_t address, std::uint32_t value, DWORD* error) noexcept {
    // The profile requires DWORD alignment; never replace or swallow arbitrary AVs.
    InterlockedExchange(reinterpret_cast<volatile LONG*>(address), static_cast<LONG>(value));
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

bool ProfileValid(const ReconProfile& profile, const StartupProfile& startup) noexcept {
    const auto end = static_cast<std::uint64_t>(profile.functionRva) + profile.functionSize;
    const auto constantEnd = static_cast<std::uint64_t>(profile.constantRva) + profile.constantBytes.size();
    return profile.functionSize > 0 && profile.functionSize <= kReconFunctionCapacity &&
        end <= startup.imageSize && constantEnd <= startup.imageSize &&
        profile.loadRva >= profile.functionRva &&
        static_cast<std::uint64_t>(profile.loadRva) + profile.originalWindow.size() <= end &&
        profile.operandRva == profile.loadRva + 4 && (profile.operandRva & 3) == 0 &&
        static_cast<std::int64_t>(profile.loadRva) + 8 +
            static_cast<std::int32_t>(profile.newDisplacement) == profile.constantRva;
}

using FunctionBytes = std::array<std::uint8_t, kReconFunctionCapacity>;

bool BytesEqual(std::uintptr_t base, const StartupProfile& startup,
    const ReconProfile& profile, const FunctionBytes& expected,
    FunctionBytes* scratch, const ReconOps& ops, DWORD* error) noexcept {
    return ReadImageRange(base, startup.imageSize, profile.functionRva,
        scratch->data(), profile.functionSize, ops.memory, error) &&
        std::memcmp(scratch->data(), expected.data(), profile.functionSize) == 0;
}

bool WritableCode(std::uintptr_t base, const StartupProfile& startup,
    const ReconProfile& profile, const ReconOps& ops, DWORD* error) noexcept {
    return ImageRangeProtection(base, startup.imageSize, profile.operandRva, 4,
               PAGE_EXECUTE_READWRITE, ops.memory, error) ||
        ImageRangeProtection(base, startup.imageSize, profile.operandRva, 4,
               PAGE_EXECUTE_WRITECOPY, ops.memory, error);
}

bool OriginalProtection(std::uintptr_t base, const StartupProfile& startup,
    const ReconProfile& profile, const ReconOps& ops, DWORD* error) noexcept {
    return ImageRangeProtection(base, startup.imageSize, profile.functionRva,
        profile.functionSize, PAGE_EXECUTE_READ, ops.memory, error);
}

bool ConstantMatches(std::uintptr_t base, const StartupProfile& startup,
    const ReconProfile& profile, const ReconOps& ops, DWORD* error) noexcept {
    std::array<std::uint8_t, 16> bytes{};
    return ImageRangeProtection(base, startup.imageSize, profile.constantRva,
            bytes.size(), PAGE_READONLY, ops.memory, error) &&
        ReadImageRange(base, startup.imageSize, profile.constantRva,
            bytes.data(), bytes.size(), ops.memory, error) && bytes == profile.constantBytes;
}

bool RecoverWithoutWrite(std::uintptr_t base, const StartupProfile& startup,
    const ReconProfile& profile, const FunctionBytes& original, FunctionBytes* scratch,
    const ReconOps& ops, DWORD* error) noexcept {
    const auto originalState = [&]() noexcept {
        return OriginalProtection(base, startup, profile, ops, error) &&
            BytesEqual(base, startup, profile, original, scratch, ops, error);
    };
    // A refused/no-op protection change can leave a perfectly coherent original
    // image. Retry read-only proof once for transient read/query failures.
    if (originalState() || originalState()) return true;
    if (!WritableCode(base, startup, profile, ops, error)) return false;
    DWORD ignored{};
    (void)ops.protect(ops.context, base + profile.operandRva, 4,
        PAGE_EXECUTE_READ, &ignored, error);
    // No instruction write was attempted, so there is no new code to flush.
    // Never continue if original bytes AND original protection cannot be proved.
    return originalState() || originalState();
}

bool Rollback(std::uintptr_t base, const StartupProfile& startup,
    const ReconProfile& profile, const FunctionBytes& original, FunctionBytes* scratch,
    const ReconOps& ops, DWORD* error) noexcept {
    DWORD ignored{};
    // One bounded rollback attempt. An API failure is not converted into success.
    if (!ops.protect(ops.context, base + profile.operandRva, 4,
            PAGE_EXECUTE_READWRITE, &ignored, error) ||
        !WritableCode(base, startup, profile, ops, error) ||
        !ops.writeDword(ops.context, base + profile.operandRva,
            profile.oldDisplacement, error) ||
        !BytesEqual(base, startup, profile, original, scratch, ops, error)) return false;
    if (!ops.protect(ops.context, base + profile.operandRva, 4,
            PAGE_EXECUTE_READ, &ignored, error) ||
        !OriginalProtection(base, startup, profile, ops, error) ||
        !BytesEqual(base, startup, profile, original, scratch, ops, error) ||
        !ops.flush(ops.context, base + profile.functionRva, profile.functionSize, error))
        return false;
    return true;
}

} // namespace

ReconOps ProductionReconOps(HostHashLease* lease) noexcept {
    return {ProductionMemoryOps(), lease, Protect, WriteDword, Flush, Stable};
}

ReconResult RunReconFix(const BootstrapContextV3& context,
    const StartupProfile& startup, const ReconProfile& profile, ReconMode mode,
    const Sha256Digest& hostDigest, const ReconOps& ops) noexcept {
    ReconResult result{};
    if ((mode != ReconMode::Passive && mode != ReconMode::Active) ||
        !ops.protect || !ops.writeDword || !ops.flush || !ops.validateHostIdentity ||
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
        !ImageSectionMatches(base, startup.imageSize, profile.functionRva, profile.functionSize,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
            IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_DISCARDABLE, ops.memory) ||
        !ImageRangeProtection(base, startup.imageSize, profile.constantRva,
            profile.constantBytes.size(), PAGE_READONLY, ops.memory, &result.error) ||
        !ImageSectionMatches(base, startup.imageSize, profile.constantRva, profile.constantBytes.size(),
            IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE |
            IMAGE_SCN_MEM_DISCARDABLE, ops.memory)) {
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
        digest != profile.originalDigest ||
        std::memcmp(original.data() + profile.loadRva - profile.functionRva,
            profile.originalWindow.data(), profile.originalWindow.size()) != 0 ||
        std::memcmp(original.data() + profile.operandRva - profile.functionRva,
            &profile.oldDisplacement, sizeof(profile.oldDisplacement)) != 0) {
        result.reason = FixReason::FunctionMismatch;
        return result;
    }
    std::array<std::uint8_t, 16> constant{};
    if (!ReadImageRange(base, startup.imageSize, profile.constantRva,
            constant.data(), constant.size(), ops.memory, &result.error) ||
        constant != profile.constantBytes) {
        result.reason = FixReason::ConstantMismatch;
        return result;
    }
    expected = original;
    std::memcpy(expected.data() + profile.operandRva - profile.functionRva,
        &profile.newDisplacement, sizeof(profile.newDisplacement));
    if (!HashBytesSha256(expected.data(), profile.functionSize, &digest, &result.error) ||
        digest != profile.correctedDigest) {
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
        !BytesEqual(base, startup, profile, original, &scratch, ops, &result.error) ||
        !ConstantMatches(base, startup, profile, ops, &result.error)) {
        result.reason = FixReason::ReadbackFailed;
        return result;
    }
    // Passive mode reaches the same qualification boundary as active mode;
    // qualified records readiness, not proof that a correction was installed.
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
    const auto writeCorrection = [&]() noexcept {
        // An API failure may still have changed bytes; claim the attempt first.
        writeAttempted = true;
        return ops.writeDword(ops.context, base + profile.operandRva,
            profile.newDisplacement, &result.error);
    };
    if (!ops.protect(ops.context, base + profile.operandRva, 4,
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
        } else if (!writeCorrection()) {
            failure = FixReason::WriteFailed;
        } else if (!BytesEqual(base, startup, profile, expected, &scratch, ops, &result.error)) {
            failure = FixReason::ReadbackFailed;
        } else if (!ConstantMatches(base, startup, profile, ops, &result.error)) {
            failure = FixReason::ConstantMismatch;
        } else {
            DWORD ignored{};
            if (!ops.protect(ops.context, base + profile.operandRva, 4,
                    PAGE_EXECUTE_READ, &ignored, &result.error) ||
                !OriginalProtection(base, startup, profile, ops, &result.error) ||
                !BytesEqual(base, startup, profile, expected, &scratch, ops, &result.error)) {
                failure = FixReason::RestoreFailed;
            } else if (!ConstantMatches(base, startup, profile, ops, &result.error)) {
                failure = FixReason::ConstantMismatch;
            } else if (!ops.flush(ops.context, base + profile.functionRva,
                       profile.functionSize, &result.error)) {
                failure = FixReason::FlushFailed;
            } else {
                // The writable interval is over. Validate the SAME retained file
                // handle again before publishing active; no re-open or new hash.
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
            // Still fatal when even a no-write path cannot restore/prove RX.
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

[[noreturn]] void FailFastRecon() noexcept {
    RaiseFailFastException(nullptr, nullptr, 0);
    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
}

} // namespace rs2fix
