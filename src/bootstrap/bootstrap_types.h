#pragma once
#include "shared/bootstrap_abi.h"
#include <cstdint>
#include <type_traits>

namespace rs2fix {
inline constexpr std::size_t kX3AudioHandleBytes = 20;
using X3DAudioInitializeFn = void(WINAPI*)(UINT32, FLOAT, BYTE*);
using X3DAudioCalculateFn = void(WINAPI*)(const BYTE*, const void*, const void*, UINT32, void*);
static_assert(std::is_same_v<X3DAudioInitializeFn, void(WINAPI*)(UINT32, FLOAT, BYTE*)>);
static_assert(std::is_same_v<X3DAudioCalculateFn,
    void(WINAPI*)(const BYTE*, const void*, const void*, UINT32, void*)>);

enum class GenuineResolverStatus : std::uint32_t {
    Ok = 0, SystemPathFailed, PathCapacityFailed, LoadFailed, SelfModule,
    CandidatePathFailed, FileIdentityFailed, WrongFile, InitializeExportMissing,
    CalculateExportMissing, InitializeAddressQueryFailed, CalculateAddressQueryFailed,
    InitializeWrongAllocationBase, CalculateWrongAllocationBase,
};
enum class GenuineFailureClass : std::uint32_t { None, ResourceApi, Validation };
struct X3AudioDispatch {
    HMODULE module{};
    X3DAudioInitializeFn initialize{};
    X3DAudioCalculateFn calculate{};
    GenuineResolverStatus status{GenuineResolverStatus::LoadFailed};
    DWORD win32Error{};
};
struct GenuineResolverResult {
    X3AudioDispatch dispatch{};
    GenuineFailureClass failureClass{GenuineFailureClass::ResourceApi};
    bool ownsModule{};
};
inline bool IsCompleteDispatch(const X3AudioDispatch& value) noexcept {
    return value.status == GenuineResolverStatus::Ok && value.module != nullptr &&
        value.initialize != nullptr && value.calculate != nullptr;
}
enum class CompanionLoadStatus : std::uint32_t {
    Ok, PathFailed, LoadFailed, SelfModule, GenuineModule, CandidatePathFailed,
    FileIdentityFailed, WrongFile, ExportMissing, QueryAddressFailed,
    WrongAddressBase, InitializeFailed,
};
struct CompanionLoadResult {
    HMODULE module{};
    CompanionLoadStatus status{CompanionLoadStatus::LoadFailed};
    DWORD win32Error{};
    DWORD initializeResult{kInitInvalidContext};
};
} // namespace rs2fix
