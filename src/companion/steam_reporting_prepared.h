#pragma once

#include "companion/steam_reporting_types.h"
#include "shared/startup_profile.h"

namespace rs2fix::reporting {
struct PreparedLayout {
    std::uint32_t service;
    std::uint32_t registration;
    std::uint32_t gameMode;
    std::uint32_t maximum;
    std::uint32_t members;
    std::uint32_t publicIp;
    std::uint32_t fullDirty;
};
const PreparedLayout& ProductionPreparedLayout() noexcept;
struct PreparedReadContext {
    MemoryOps memory;
    std::uintptr_t hostBase;
    std::uint32_t hostImageSize;
    const PreparedLayout* layout;
};
struct PreparedSnapshot {
    NativeCounts counts;
    std::uint32_t membersCount;
    std::uint32_t jsonBytes;
};
static_assert(std::is_trivial_v<PreparedSnapshot> && std::is_standard_layout_v<PreparedSnapshot>);

enum PreparedMismatchBits : std::uint32_t {
    PreparedMaximumDiffers = 1, PreparedMembersDiffer = 2, PreparedPiDiffers = 4,
    PreparedBotsDiffer = 8, PreparedJsonMaximumDiffers = 16
};
struct PreparedDiagnostic {
    NativeCounts json;
    std::uint32_t maximum, membersCount, jsonBytes, mismatchMask;
    bool valid;
};

// Read-only; requires qualified immutable profile, owner, source/binding epochs
// and expected source counts. Scratch must be owned, nonaliasing storage of
// exactly kJsonBytes, valid throughout the call. Its bounded supplied region is
// scrubbed on every normal exit, including rejected input. No endpoint,
// registration identity or Members element is copied; only GameMode is parsed.
// Success proves local tuple/header coherence, not publication or remote ACK.
Reason ReadPreparedState(const PreparedReadContext&, const NativeCounts& expected,
    char* scratch, std::size_t scratchCapacity, PreparedSnapshot* output,
    PreparedDiagnostic* diagnostic = nullptr) noexcept;
// Diagnostic is populated only for fully parsed JSON and stable validated
// headers, including a coherent mismatch. It never changes admission or makes
// the normal output usable on failure. No additional native reads are performed.
} // namespace rs2fix::reporting
