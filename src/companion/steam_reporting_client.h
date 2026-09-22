#pragma once

#include "companion/steam_reporting_types.h"
#include "companion/host_hash.h"
#include "shared/startup_profile.h"

namespace rs2fix::reporting {
struct ClientQualification {
    Reason reason;
    DWORD error;
    std::uint64_t elapsedMs;
    Sha256Digest digest;
    std::uint64_t fileSize;
    // Comparison token only, not a retained module handle or permission to read
    // this address later. Never emit it to the reporting log/status payload.
    std::uint64_t moduleToken;
    std::uint32_t imageSize;
    std::uint32_t timestamp;
    std::uint32_t checksum;
    bool referenceAcquired;
    bool referenceReleased;
};
static_assert(std::is_trivial_v<ClientQualification> && std::is_standard_layout_v<ClientQualification>);

// Cold, once-only caller-owned policy: invoke only after the first true native
// Init while that caller owns the sole initial lifecycle reference. The caller
// must recheck lifecycle before/after and leave its own reference before Ready.
// No SDK/game call, load, permanent pin, or hot-path rehash occurs here. The
// separate C++ resource-owning frame must not be placed inside a SEH __try frame.
ClientQualification QualifyLoadedSteamClient() noexcept;

#if defined(RS2_REPORTING_TESTING)
// Inert adapters compile only in the local test target. Production callers
// cannot select a different filename, digest, memory reader or module provider.
struct ClientTestIdentity {
    const wchar_t* leaf;
    Sha256Digest digest;
    std::uint32_t imageSize;
    std::uint32_t timestamp;
    std::uint32_t checksum;
};
struct ClientModuleCandidate { std::uintptr_t base; std::uint32_t imageSize; };
struct ClientModuleTestOps {
    void* context;
    bool (*enumerate)(void*, const wchar_t*, ClientModuleCandidate*, std::uint32_t*, DWORD*) noexcept;
    bool (*retain)(void*, std::uintptr_t, HMODULE*, DWORD*) noexcept;
    bool (*release)(void*, HMODULE, DWORD*) noexcept;
    bool (*path)(void*, HMODULE, wchar_t*, std::size_t, DWORD*) noexcept;
};
ClientQualification QualifyLoadedSteamClientForTest(const ClientTestIdentity&,
    const ClientModuleTestOps&, const MemoryOps&, const HostHashOps&) noexcept;
#endif
} // namespace rs2fix::reporting
