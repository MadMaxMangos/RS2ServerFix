#pragma once
#include "shared/native_log_framing.h"
#include "shared/startup_profile.h"
#include "shared/steam_reporting_status_v3.h"

namespace rs2fix::reporting {
inline constexpr std::size_t kNativeSinkLimit = 8;
struct NativeLogLayout {
    std::uint32_t logSlot, redirectorObject, redirectorVtable;
    std::uint32_t fileVtable, consoleVtable, inheritedVtable, debugVtable, eventVtable;
    std::uint32_t archiveVtable, managerSlot, managerVtable;
    std::uint32_t forceFlush, criticalError, requestingExit, logTimes;
    std::uint32_t suppressionInitialized, nameTable;
    std::uint32_t fileReentry, debugReentry, inheritedReentry, consoleReentry;
};
const NativeLogLayout& ProductionNativeLogLayout() noexcept;

struct NativeLogReadContext {
    MemoryOps memory;
    std::uintptr_t hostBase;
    std::uint32_t hostImageSize;
    std::uint32_t ownerThreadId;
    const NativeLogLayout* layout;
};
struct NativeLogSnapshot {
    // Owner-only comparison tokens. Never send these engine pointers to a worker
    // or treat a saved snapshot as a lifetime lease for a later native call.
    std::uintptr_t redirector;
    std::uintptr_t file;
    std::uintptr_t archive;
    std::uintptr_t archiveHandle;
    std::uintptr_t sinks[kNativeSinkLimit];
    std::uintptr_t sinkVtables[kNativeSinkLimit];
    std::uintptr_t inheritedFallbacks[kNativeSinkLimit];
    std::uint32_t sinkCount;
    std::uint32_t pathChars;
    std::uint64_t prefixMode;
    std::uint16_t path[1024];
};
static_assert(std::is_trivial_v<NativeLogSnapshot> && std::is_standard_layout_v<NativeLogSnapshot>);

// Read-only live-object gate, NOT cold-profile verification or call permission.
// Caller must first qualify the immutable host/code/import profile and normal
// owner ancestry/lifecycle. Takes two bounded observations, zeroes output on any
// refusal, never invokes engine code, allocates, locks, or opens the log file.
TransportReason ReadNativeLogSnapshot(const NativeLogReadContext&, NativeLogSnapshot*) noexcept;
} // namespace rs2fix::reporting
