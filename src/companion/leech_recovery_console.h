#pragma once
#include "companion/leech_recovery_native.h"
#include "companion/leech_recovery_control.h"

namespace rs2fix::reporting {
struct Runtime;
struct LeechRecovery;
inline constexpr std::size_t kLeechConsoleRegistryLimit=1024;
inline constexpr std::size_t kLeechConsoleReplyCharacters=256;
inline constexpr std::size_t kLeechConsoleOutputCapacity=4096;
inline constexpr std::uint32_t kLeechConsoleRegistryRva=0x14CC3B0;
inline constexpr std::uint32_t kLeechConsoleReturnRva=0xC92E6;
inline constexpr std::uint32_t kLeechConsoleReplyVtableRva=0xEAE5D8;
inline constexpr std::uint32_t kLeechConsoleReplyEntryRva=0x4B710;
enum class LeechConsoleReason : LONG {
    None, Profile, Allocator, Registry, ModulePin, Publication, Postcheck, NativeException
};
struct LeechConsoleObject { const std::uintptr_t* vtable; };
using LeechConsoleConstructFn=void* (*)(void*);
using LeechConsoleReplyFn=void (*)(void*,const wchar_t*,std::uint32_t);
struct LeechConsoleCalls {
    LeechConsoleConstructFn construct;
    LeechConsoleReplyFn reply;
    bool (*pin)(HMODULE) noexcept;
};
// Process-resident, never copied, freed, or unregistered after publication.
// Off-owner callers may touch ONLY the interlocked diagnostics and immutable
// identity. No borrowed command/output address survives an Exec invocation.
struct LeechConsoleAdapter {
    LeechConsoleObject object;
    LeechRecovery* recovery;
    HMODULE companion;
    LeechConsoleCalls calls;
    std::uintptr_t allocator;
    volatile LONG reason, execObserved, foreignObserved, unsupportedOutputObserved;
    bool attempted, constructing, replying;
};
struct LeechConsoleRegistry {
    std::uintptr_t data;
    std::int32_t count,capacity;
    std::uintptr_t entries[kLeechConsoleRegistryLimit];
};
static_assert(std::is_trivial_v<LeechConsoleAdapter> && std::is_standard_layout_v<LeechConsoleAdapter>);
static_assert(sizeof(LeechConsoleObject)==8 && offsetof(LeechConsoleRegistry,count)==8);

ProfileResult ValidateNativeLeechConsoleProfile(std::uintptr_t,const StartupProfile&,
    const MemoryOps&,const NativeImportOps&,DWORD*) noexcept;
const char* NativeLeechConsoleInventorySha256() noexcept;
// Bounded, read-only selectors. Ready is not native-call permission.
bool ReadLeechConsoleRegistry(const RecoveryNativeContext&,LeechConsoleRegistry*) noexcept;
bool ReadLeechConsoleOutput(const RecoveryNativeContext&,std::uintptr_t) noexcept;
void PrepareLeechConsole(LeechConsoleAdapter&,LeechRecovery&,HMODULE) noexcept;
bool LeechConsoleRegistrationDue(const Runtime&) noexcept;
// Called only at directly classified, top-level normal owner AfterPump. A native
// exception propagates after disabling this optional route; pipe is unchanged.
void RegisterLeechConsole(Runtime&,CallerClass,std::size_t,bool);
#if defined(RS2_REPORTING_TESTING)
std::int32_t ExecuteLeechConsoleForTest(LeechConsoleAdapter&,void*,std::uintptr_t,const wchar_t*,void*);
void ResetLeechConsoleForTest() noexcept;
#endif
} // namespace rs2fix::reporting
