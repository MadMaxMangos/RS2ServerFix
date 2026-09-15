#pragma once
#include "bootstrap/bootstrap_types.h"
#include "shared/path_identity.h"

namespace rs2fix {
struct GenuineResolverOps {
    void* context{};
    bool (*buildSystemPath)(void*, wchar_t*, std::size_t, DWORD*) noexcept{};
    HMODULE (*loadSystemLibrary)(void*, const wchar_t*, DWORD*) noexcept{};
    bool (*getModulePath)(void*, HMODULE, wchar_t*, std::size_t, DWORD*) noexcept{};
    bool (*queryFileIdentity)(void*, const wchar_t*, FileIdentity*, DWORD*) noexcept{};
    FARPROC (*getExport)(void*, HMODULE, const char*, DWORD*) noexcept{};
    bool (*queryAllocationBase)(void*, FARPROC, const void**, DWORD*) noexcept{};
    bool (*freeLibrary)(void*, HMODULE) noexcept{};
    void* (*allocateDispatch)(void*) noexcept{};
    bool (*freeDispatch)(void*, void*) noexcept{};
    bool (*beginOnce)(void*, INIT_ONCE*, DWORD, BOOL*, void**, DWORD*) noexcept{};
    bool (*completeOnce)(void*, INIT_ONCE*, DWORD, void*, DWORD*) noexcept{};
};
const GenuineResolverOps& ProductionGenuineResolverOps() noexcept;
GenuineFailureClass ClassifyGenuineFailure(GenuineResolverStatus) noexcept;
GenuineResolverStatus ValidateGenuineEvidence(HMODULE bootstrap, HMODULE candidate,
    const FileIdentity& expected, const FileIdentity& actual,
    FARPROC initialize, FARPROC calculate, bool initializeQueried, bool calculateQueried,
    const void* initializeBase, const void* calculateBase) noexcept;
GenuineResolverResult ResolveGenuineX3AudioPrivate(HMODULE,
    const GenuineResolverOps&) noexcept;

enum class AcquireMode : std::uint32_t { ExportRetryOnce };
enum class FallbackState : LONG { Empty = 0, Writing = 1, Ready = 2 };
struct GenuineResolverState {
    INIT_ONCE normalOnce{};
    alignas(8) X3AudioDispatch fallback{};
    LONG volatile fallbackState{};
};
inline constexpr std::uintptr_t kDispatchAlignment =
    std::uintptr_t{1} << INIT_ONCE_CTX_RESERVED_BITS;
static_assert(alignof(GenuineResolverState) >= kDispatchAlignment);
static_assert(offsetof(GenuineResolverState, fallback) % kDispatchAlignment == 0);
static_assert(std::is_trivially_copyable_v<GenuineResolverState>);
// Published dispatches retain their module for process lifetime. A private
// dispatch instead transfers one load reference to releaseModuleOnClose.
struct GenuineDispatchLease {
    X3AudioDispatch dispatch{};
    bool valid{};
    bool releaseModuleOnClose{};
};
bool TryGetNormal(GenuineResolverState*, const GenuineResolverOps&,
    X3AudioDispatch*, DWORD*) noexcept;
bool TryGetReadyFallback(GenuineResolverState*, X3AudioDispatch*) noexcept;
GenuineDispatchLease PublishPrivateSuccess(GenuineResolverState*,
    GenuineResolverResult&&, bool beginSucceeded, BOOL pending,
    const GenuineResolverOps&) noexcept;
GenuineDispatchLease AcquireGenuineX3Audio(GenuineResolverState*, HMODULE,
    const GenuineResolverOps&, AcquireMode mode = AcquireMode::ExportRetryOnce) noexcept;
void ReleaseGenuineX3AudioLease(GenuineDispatchLease*, const GenuineResolverOps&) noexcept;
} // namespace rs2fix
