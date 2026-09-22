#pragma once
#include "companion/host_hash.h"
#include "companion/steam_observer_dispatch.h"

namespace rs2fix::observer {
struct Profile {
    Sha256Digest hostDigest;
    Sha256Digest sdkDigest;
    std::uint32_t sdkImageSize;
    std::uint32_t sdkTimestamp;
    std::uint32_t sdkChecksum;
    std::uint32_t factoryIatRva;
    std::uint32_t shutdownIatRva;
    std::uint32_t initIatRva;
    std::uint32_t accessorRva;
    std::uint32_t factoryReturnRva;
    std::uint32_t literalRva;
    std::uint32_t contextRva;
    std::uint32_t privateRva;
    std::uint32_t publicationRva;
    std::uint32_t publisherReturnRva;
    std::uint32_t advertiseReturnRva;
    const char* importModule;
    const ByteSpan* spans;
    std::size_t spanCount;
};
inline constexpr char kInterfaceVersion[] = "SteamGameServer013";
static_assert(sizeof(kInterfaceVersion) == 19);
const Profile& ProductionObserverProfile() noexcept;

// No mutation or SDK call. Re-read the cold object caches after all fallible
// preparation and immediately before the atomic installation commit.
Reason CheckColdProfile(const BootstrapContextV3&, const StartupProfile&,
    const Profile&, const MemoryOps&, DWORD* error) noexcept;
Reason QualifySdk(const BootstrapContextV3&, const StartupProfile&, const Profile&,
    HostHashLease* sdkLease, DispatchConfig* config, DWORD* error) noexcept;
// Requires a DispatchConfig already qualified by QualifySdk and the same held
// startup leases. Reads the named server-pump binding; never invokes or loads SDK
// code and never changes the three-cell observer profile.
Reason QualifyServerPump(const BootstrapContextV3&, const StartupProfile&, const Profile&,
    const DispatchConfig&, std::uint32_t iatRva, ShutdownFn* original, DWORD* error) noexcept;
// Heap objects are permitted, but every table read is guarded. This only
// qualifies a returned interface; it never invokes a virtual method.
bool ValidateInterfaceObject(void* memoryOps, void* object) noexcept;
} // namespace rs2fix::observer
