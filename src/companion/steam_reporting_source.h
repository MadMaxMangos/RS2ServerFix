#pragma once

#include "companion/steam_reporting_types.h"
#include "shared/startup_profile.h"

namespace rs2fix::reporting {
// Conservative first-profile admission bounds, not claimed engine maxima.
inline constexpr std::uint32_t kSourceActorCapacity = 1048576;
inline constexpr std::uint32_t kSourceTravelCapacity = 65536;
inline constexpr std::size_t kSourceClassDepth = 64;
inline constexpr std::size_t kSourceRegionLimit = 32;

// Only global RVAs vary in the compiled inert host. Field offsets and admission
// rules remain the native profile's; fixture addresses are never production RVAs.
struct SourceLayout {
    std::uint32_t world;
    std::uint32_t worldInfoClass;
    std::uint32_t publicWrapper;
    std::uint32_t privateWrapper;
};
const SourceLayout& ProductionSourceLayout() noexcept;

struct SourceReadContext {
    MemoryOps memory;
    std::uintptr_t hostBase;
    std::uint32_t hostImageSize;
    std::uint64_t lifecycle;
    void* interfaceContext;
    // Try-only observer lookup of an accepted real/proxy interface in this
    // lifecycle. Must not invoke it, allocate, block or call into the game.
    bool (*acceptedInterface)(void*, std::uintptr_t, std::uint64_t) noexcept;
    const SourceLayout* layout;
};

// Owner-only comparison tokens, never log/queue data. Retained tokens must NEVER
// be dereferenced: every invocation obtains its pointers from current roots.
// Equality is a change detector, not lifetime proof or a pointer lease.
struct SourceIdentity {
    std::uintptr_t world;
    std::uintptr_t level;
    std::uintptr_t actors;
    std::uintptr_t worldInfo;
    std::uintptr_t game;
    std::uintptr_t expectedWorldInfoClass;
    std::uintptr_t wrapper;
    std::uintptr_t interfaceObject;
    std::uintptr_t vtables[4];
    std::uintptr_t classChain[kSourceClassDepth];
    std::uint32_t classCount;
    std::uint64_t lifecycle;
};
struct SourceSnapshot {
    SourceIdentity identity;
    std::uint32_t humans;
    std::uint32_t bots;
    std::uint32_t maximum;
    NativeCounts outer;
    float realTimeSeconds;
    float producerTimer;
    bool requested;
    bool dirty;
};
static_assert(std::is_trivial_v<SourceIdentity> && std::is_standard_layout_v<SourceIdentity>);
static_assert(std::is_trivial_v<SourceSnapshot> && std::is_standard_layout_v<SourceSnapshot>);

bool EqualSourceIdentity(const SourceIdentity&, const SourceIdentity&) noexcept;
// Requires a previously qualified immutable host profile and current owner /
// ancestry / lifecycle admission. Performs two bounded guarded observations;
// all relevant identity/readiness/count fields must agree. Never writes native
// memory, reads another actor, invokes native code or initializes class caches.
// Output is zeroed on failure and is NOT a valid zero-occupancy observation.
Reason ReadSourceSnapshot(const SourceReadContext&, SourceSnapshot*) noexcept;
} // namespace rs2fix::reporting
