#pragma once
#include "companion/steam_reporting_profile.h"

namespace rs2fix::reporting {
inline constexpr std::size_t kNativeProfileSpanLimit = 128;
inline constexpr std::size_t kNativeProfilePointerLimit = 32;
inline constexpr std::size_t kNativeProfileExceptionLimit = 64;
inline constexpr std::size_t kNativeProfileImportLimit = 16;
struct NativeLoggingProfile {
    // Reuse the immutable selector representation, not the legacy admission
    // policy. body.pump is the first named import (the CRT formatter here).
    ReportingProfile body;
    const PumpImportRecipe* imports;
    std::size_t importCount;
};
struct NativeImportOps {
    void* context;
    // Resolve an already loaded trusted runtime module. Never LoadLibrary,
    // invoke the import, or infer a target from a nonnull IAT cell alone.
    bool (*resolve)(void*, const char* module, const char* name,
        std::uintptr_t* address, DWORD* error) noexcept;
};
const NativeLoggingProfile& ProductionNativeLoggingProfile() noexcept;
const NativeImportOps& ProductionNativeImportOps() noexcept;
const char* NativeLoggingInventorySha256() noexcept;

// Cold, read-only supplementary qualification. Requires the existing verified
// host hash/lease. Does not relax the original ReportingProfile limits and never
// calls the logger or a native sink. All named IAT cells must match resolution
// from the already loaded, system-directory runtime modules.
ProfileResult ValidateNativeLoggingProfile(std::uintptr_t hostBase,
    const StartupProfile& host, const NativeLoggingProfile&, const MemoryOps&,
    const NativeImportOps&, DWORD* error) noexcept;
} // namespace rs2fix::reporting
