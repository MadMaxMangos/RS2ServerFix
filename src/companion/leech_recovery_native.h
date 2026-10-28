#pragma once
#include "companion/steam_reporting_native_profile.h"
#include "companion/steam_reporting_types.h"
#include <array>

namespace rs2fix::reporting {
inline constexpr std::size_t kRecoveryGenericSlots = 128;
inline constexpr std::size_t kRecoveryTypedSlots = 16;
// A read-work budget, not an inferred engine maximum. This supports all sixteen
// retained HB payloads with 64 initialized player strings each, plus a 256-entry
// global kernel vector. No string contents are copied except bounded identities.
inline constexpr std::size_t kRecoveryVectorElements = 256;
inline constexpr std::size_t kRecoveryAllVectorElements = 1280;
inline constexpr std::size_t kRecoveryStringWitnesses = 1408;
inline constexpr std::size_t kRecoveryOwnedIntervals = 1536;
inline constexpr std::size_t kRecoveryStringCapacity = 1048576;
inline constexpr std::size_t kRecoveryVectorCapacity = 8192;
inline constexpr std::size_t kRecoverySessionBytes = 1024;
inline constexpr std::size_t kRecoveryCacheChars = 1024;
inline constexpr std::size_t kRecoveryGuidBytes = 37; // Native 36-byte UUID text plus NUL.

// Read-only BA9490 input ABI, NOT plugin std::string/std::vector objects. The
// qualified native routine copies the source strings and retains no pointer.
// These initialized owner-private views must never be passed to a native
// destructor. Keep their address stable from preparation until the call returns.
inline constexpr std::uint32_t kRecoveryMetadataMemberLimit = 256;
struct RecoveryBorrowedString {
    std::uintptr_t data;
    std::uint64_t unused;
    std::uint64_t size, capacity;
};
struct RecoveryBorrowedVector { std::uintptr_t begin, end, capacity; };
struct RecoveryMetadataMembers {
    RecoveryBorrowedVector vector;
    RecoveryBorrowedString strings[kRecoveryMetadataMemberLimit];
    char text[kRecoveryMetadataMemberLimit][kRecoveryGuidBytes];
    std::uint32_t count;
};
struct RecoveryRandomOps {
    void* context;
    bool (*fill)(void*, std::uint8_t*, std::size_t) noexcept;
};
static_assert(sizeof(RecoveryBorrowedString)==32 &&
    offsetof(RecoveryBorrowedString,size)==16 && offsetof(RecoveryBorrowedString,capacity)==24);
static_assert(sizeof(RecoveryBorrowedVector)==24 && sizeof(std::uintptr_t)==8);
static_assert(std::is_trivial_v<RecoveryMetadataMembers> &&
    std::is_standard_layout_v<RecoveryMetadataMembers>);
// Inert argument preparation only: no host/SDK call or admission is implied.
// Uses one RNG operation before any native mutation, refuses rather than clamps,
// and clears all output on failure. No callers may copy/move a prepared view.
bool PrepareRecoveryMetadataMembers(RecoveryMetadataMembers&, std::uint32_t count,
    const RecoveryRandomOps&) noexcept;
const RecoveryRandomOps& ProductionRecoveryRandomOps() noexcept;

// Reproduces the stock A53560 local object's ABI. A real native tree head must
// be stored at+A8 before this object may be filled or destroyed. Byte storage
// is deliberately not a plugin STL object; its address stays owner-resident.
struct alignas(16) RecoveryMetadataProperties { std::uint8_t bytes[0xC0]; };
struct RecoveryMetadataCache {
    NativeCounts counts;
    std::uint32_t countdownBits;
    std::uint8_t registrationChanged, fullDirty;
    std::uint16_t reserved;
};
static_assert(alignof(RecoveryMetadataProperties)==16 && sizeof(RecoveryMetadataProperties)>=0xB8);

enum class RecoveryNativeResult : std::uint32_t {
    Ready, InvalidContext, Unreadable, Changed, Budget, Shape, Alias,
    Descriptor, Pool, Readiness, Hook, Allocator, Import, Provenance
};
enum class RecoveryDescriptor : std::uint32_t { Finish, Create, Heartbeat };
struct RecoveryNativeLayout {
    std::uint32_t genericPool, issuedId, invalidId, heartbeatId, registry;
    std::uint32_t standalone, sdkSession, cacheSession, publicIp, authorizationToken, kernelVector;
    std::uint32_t core, httpManager, asyncManager, auth, role, componentTable;
    std::uint32_t previousReady, previousConnected, connected, statusHook;
    std::uint32_t gmalloc, gmallocVtable, jsonMalloc, jsonFree;
    std::uint32_t componentName, finishService, finishOperation;
    std::uint32_t createService, createOperation;
    std::uint32_t finishVtable, createVtable, heartbeatVtable, httpManagerVtable;
    std::uint32_t coreGuid;
};
const RecoveryNativeLayout& ProductionRecoveryNativeLayout() noexcept;
struct RecoveryNativeContext {
    std::uintptr_t hostBase;
    std::uint32_t hostImageSize;
    MemoryOps memory;
    const NativeImportOps* imports;
    const RecoveryNativeLayout* layout; // Only roots vary in inert fixtures.
};
struct RecoveryNativeString {
    std::uintptr_t object, data;
    std::uint64_t size, capacity;
    std::uint8_t header[32];
};
struct RecoveryNativeVector {
    std::uintptr_t object, begin, end, capacity;
    std::uint32_t firstString, stringCount;
};
struct RecoveryOwnedInterval { std::uintptr_t begin, end; };
struct RecoveryGenericTask {
    std::uint32_t state, id, holder;
    std::uintptr_t component, builder, success, error;
    std::uint64_t anchor, interval;
    std::int32_t errors, throttles;
    std::uint8_t expedite;
    std::uint8_t raw[0x78];
};
struct RecoveryTypedSlot {
    std::int32_t references;
    std::uint32_t firstString, stringCount;
    std::uintptr_t payload;
    RecoveryNativeVector vector;
};
struct RecoveryTypedPool {
    std::uintptr_t descriptor;
    std::uint16_t type, firstFree;
    RecoveryTypedSlot slots[kRecoveryTypedSlots];
};
struct RecoveryNativeSnapshot {
    std::uint32_t standalone, core, auth, issuedId, invalidId, heartbeatId;
    std::uint32_t genericFree, stringCount, intervalCount;
    std::uint8_t role, previousReady, previousConnected, connected;
    std::uintptr_t httpManager, asyncManager, gmalloc;
    std::uintptr_t componentName, finishService, finishOperation, createService, createOperation;
    // Both session IDs are native narrow std::strings. The rotating auth token
    // establishes current readiness; the separate core GUID identifies lifetime.
    RecoveryNativeString sdkSession, cacheSession, authorizationToken, coreGuid;
    // Standalone Members VALUE source at14AAD70. Stock BAB380 clears its
    // initialized elements/end; it is neither the auth token nor core GUID.
    RecoveryNativeVector kernelVector;
    // A53560's stock public-IP gate reads native FString at1798800, count+8.
    // Preserve complete bounded initialized UTF-16 contents plus the header;
    // these owner-private tokens never enter recovery wire/status records.
    std::uintptr_t publicIpData;
    std::int32_t publicIpCount, publicIpCapacity;
    std::uint8_t sdkBytes[kRecoverySessionBytes];
    std::uint8_t cacheBytes[kRecoverySessionBytes];
    std::uint8_t authorizationBytes[kRecoverySessionBytes];
    std::uint8_t coreGuidBytes[kRecoveryGuidBytes];
    std::uint16_t publicIpChars[kRecoveryCacheChars];
    RecoveryGenericTask generic[kRecoveryGenericSlots];
    RecoveryTypedPool finish, create, heartbeat;
    RecoveryNativeString strings[kRecoveryStringWitnesses];
    RecoveryOwnedInterval intervals[kRecoveryOwnedIntervals];
};
static_assert(std::is_trivial_v<RecoveryNativeSnapshot> && std::is_standard_layout_v<RecoveryNativeSnapshot>);

// Cold immutable selector/import qualification only; caller must already own the
// verified host hash and StartupProfile lease. The finite partitions retain all
// existing reporting/logging limits and never execute a native target.
ProfileResult ValidateNativeRecoveryProfile(std::uintptr_t hostBase,
    const StartupProfile&, const MemoryOps&, const NativeImportOps&, DWORD*) noexcept;
const char* NativeRecoveryInventorySha256() noexcept;
ProfileResult ValidateNativeRecoveryMetadataProfile(std::uintptr_t hostBase,
    const StartupProfile&, const MemoryOps&, const NativeImportOps&, DWORD*) noexcept;
const char* NativeRecoveryMetadataInventorySha256() noexcept;
// Two-pass read of the stock cached tuple, pending-update gates and dirty byte.
// Readiness/caller/session/source and profile leases remain separate authority.
RecoveryNativeResult ReadRecoveryMetadataCache(const RecoveryNativeContext&,
    RecoveryMetadataCache*, DWORD*) noexcept;
// Allocator-only inverse lease: no source/SDK continuation is inferred. The
// caller separately validates both immutable profiles and current owner.
RecoveryNativeResult RequireRecoveryMetadataAllocator(const RecoveryNativeContext&,
    std::uintptr_t expectedAllocator,DWORD*) noexcept;
// Fresh, two-observation read-only gate. Owner/source/SDK/lifetime, loaded profile
// and closed native-writer provenance are independently REQUIRED by the caller.
// Ready is a coherent shape/type/target observation, never a call permission or
// hostile-heap ownership attestation. Outputs are cleared on every refusal.
RecoveryNativeResult ReadNativeRecoverySnapshot(const RecoveryNativeContext&,
    RecoveryNativeSnapshot*, DWORD*) noexcept;
bool EqualNativeRecoverySnapshot(const RecoveryNativeSnapshot&, const RecoveryNativeSnapshot&) noexcept;
RecoveryNativeResult RequireNativeRecoveryReady(const RecoveryNativeSnapshot&) noexcept;
RecoveryNativeResult RequireFinishFirstFree(const RecoveryNativeSnapshot&) noexcept;
RecoveryNativeResult RequireCreateFirstFree(const RecoveryNativeSnapshot&) noexcept;
// Old HB provenance is an exact previously qualified native holder/slot plus
// all retained field/interval/header witnesses. The caller establishes completed
// native generic disposal and the same SDK/source/allocator lifetime. No slot is
// reserved, manually destroyed, reset, or skipped.
RecoveryNativeResult RequireHeartbeatFirstFree(const RecoveryNativeSnapshot& fresh,
    const RecoveryNativeSnapshot& preCancel, std::uint32_t oldHolder) noexcept;
RecoveryNativeResult ReadCreateResultString(const RecoveryNativeContext&,
    const void* borrowedObject, RecoveryNativeString*, DWORD*) noexcept;
// Known completed caller ownership only. This deliberately does not inspect the
// generic pool: a fallible enqueue may leave an UNKNOWN partial native task while
// our completed local holder still requires its one native inverse. Safe owner,
// idle same SDK/registry lifetime and unchanged inverse code profile are supplied
// by the caller; forward RuntimeCaptureAdmission is not inverse authority.
RecoveryNativeResult RequireRecoveryFinishInverse(const RecoveryNativeContext&,
    std::uintptr_t expectedDescriptor, std::uint16_t type, std::uint16_t slot,
    bool boundLocal, std::uint32_t ownedHolder, DWORD*) noexcept;

// Exact x64 native ABI declarations. Potentially throwing native recipes MUST
// remain outside guarded memory-probe catches. This module invokes none of them.
using RecoveryFinishSuccessFn = void (*)(const bool* borrowedResult, std::uint32_t id) noexcept;
using RecoveryFinishErrorFn = bool (*)(std::int32_t code, std::uint32_t id) noexcept;
using RecoveryAllocateFn = std::uint16_t (*)(void* descriptor);
using RecoveryTypeFn = std::uint16_t (*)(void* descriptor);
using RecoverySlotReleaseFn = void (*)(void* descriptor, std::uint16_t slot);
using RecoveryInitHolderFn = void* (*)(std::uint32_t* holder);
using RecoveryBindHolderFn = void (*)(std::uint32_t* holder, std::uint16_t type, std::uint16_t slot);
using RecoveryResolveHolderFn = void* (*)(const std::uint32_t* holder);
using RecoveryStringCopyFn = void* (*)(void* destination, const void* source, std::size_t offset, std::size_t count);
using RecoveryEnqueueFinishFn = std::uint32_t (*)(const char* component,
    const std::uint32_t* holder, RecoveryFinishSuccessFn, RecoveryFinishErrorFn);
using RecoveryReleaseHolderFn = void (*)(std::uint32_t* holder);
using RecoveryCancelFn = void (*)(std::uint32_t* id);
using RecoveryVoidFn = void (*)();
using RecoveryCreateSuccessFn = void (*)(const void* borrowedNativeString, std::uint32_t id);
struct RecoveryNativeCalls {
    RecoveryInitHolderFn initHolder;
    RecoveryBindHolderFn bindHolder;
    RecoveryResolveHolderFn resolveHolder;
    RecoveryStringCopyFn copyString;
    RecoveryEnqueueFinishFn enqueueFinish;
    RecoveryReleaseHolderFn releaseHolder;
    RecoveryCancelFn cancel;
    RecoveryVoidFn cleanup, start, create;
    RecoveryCreateSuccessFn createSuccess;
    RecoveryAllocateFn finishAllocate;
    RecoveryTypeFn finishType;
    RecoverySlotReleaseFn finishRelease;
};
RecoveryNativeCalls NativeRecoveryCallAddresses(std::uintptr_t qualifiedHostBase) noexcept;
using RecoveryMetadataHeadFn = void* (*)();
using RecoveryMetadataObjectFn = void (*)(void* nativeProperties);
using RecoveryMetadataUpdateFn = void (*)(const void* nativeProperties, const RecoveryBorrowedVector*);
struct RecoveryMetadataCalls {
    RecoveryMetadataHeadFn head;
    RecoveryMetadataObjectFn fill, destroy;
    RecoveryMetadataUpdateFn update;
};
// Potential native exceptions MUST propagate; these boundaries are not noexcept.
RecoveryMetadataCalls NativeRecoveryMetadataCallAddresses(std::uintptr_t qualifiedHostBase) noexcept;
} // namespace rs2fix::reporting
