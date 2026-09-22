#pragma once

#include "shared/startup_profile.h"
#include "companion/sha256.h"
#include <cstddef>
#include <cstdint>

namespace rs2fix::reporting {
inline constexpr std::size_t kProfileSpanLimit = 64;
inline constexpr std::size_t kProfileSpanBytes = 8192;
inline constexpr std::size_t kProfileReadChunk = 512;
inline constexpr std::size_t kProfileByteBudget = 65536;
// The three additional metadata getter slots qualify read-only scheduler
// diagnostics; they do not authorize calling a getter or deriving native time.
inline constexpr std::size_t kProfilePointerLimit = 12;
inline constexpr std::size_t kProfileExceptionLimit = 14;

enum class SpanKind : std::uint32_t { Code, ImmutableData };
struct ReportingSpan { ByteSpan span; SpanKind kind; };
struct PointerRvaRecipe { std::uint32_t slotRva; std::uint32_t targetRva; };
struct RuntimeFunctionRecipe {
    std::uint32_t entryRva;
    std::uint32_t beginRva;
    std::uint32_t endRva;
    std::uint32_t unwindRva;
};
struct PumpImportRecipe {
    std::uint32_t slotRva;
    const char* module;
    const char* name;
};
struct ReportingProfile {
    const ReportingSpan* spans;
    std::size_t spanCount;
    const PointerRvaRecipe* pointers;
    std::size_t pointerCount;
    const RuntimeFunctionRecipe* exceptions;
    std::size_t exceptionCount;
    PumpImportRecipe pump;
};
struct ReportingIdentities {
    Sha256Digest hostDigest;
    Sha256Digest steamApiDigest;
    Sha256Digest steamClientDigest;
    std::uint32_t steamClientImageSize;
    std::uint32_t steamClientTimestamp;
    std::uint32_t steamClientChecksum;
};
enum class ProfileResult : std::uint32_t {
    Ready, InvalidProfile, ImageMismatch, ProtectionMismatch, BytesMismatch,
    PointerMismatch, UnwindMismatch, ImportMismatch
};

const ReportingProfile& ProductionReportingProfile() noexcept;
const ReportingIdentities& ProductionReportingIdentities() noexcept;
const char* ReportingProfileInventorySha256() noexcept;

// Startup-only and read-only. Caller owns the already-qualified host hash/lease
// and cold-start opportunity. This deliberately does not reuse/relax the legacy
// verifier's 1024-byte whole-span limit. No native host/SDK function is invoked.
// The approved generator audits relocation coverage. Runtime compares resulting
// bytes/RVA pointers, never requires the loader's discardable .reloc pages.
// On Ready, pumpOriginal is the named IAT cell's current nonnull value; startup
// integration must ALSO compare it with the qualified loaded SDK's named export.
// No pointer to the temporary caller's context/profile is retained.
ProfileResult ValidateReportingProfile(std::uintptr_t hostBase,
    const StartupProfile& host, const ReportingProfile& profile,
    const MemoryOps& memory, std::uintptr_t* pumpOriginal, DWORD* error) noexcept;
} // namespace rs2fix::reporting
