#pragma once
#include "bootstrap/bootstrap_types.h"
#include "shared/path_identity.h"

namespace rs2fix {
struct CompanionLoaderOps {
    void* context{};
    bool (*buildCompanionPath)(void*, HMODULE, wchar_t*, std::size_t, DWORD*) noexcept{};
    HMODULE (*loadLibrary)(void*, const wchar_t*, DWORD*) noexcept{};
    bool (*getModulePath)(void*, HMODULE, wchar_t*, std::size_t, DWORD*) noexcept{};
    bool (*queryFileIdentity)(void*, const wchar_t*, FileIdentity*, DWORD*) noexcept{};
    FARPROC (*getExport)(void*, HMODULE, const char*, DWORD*) noexcept{};
    bool (*queryAllocationBase)(void*, FARPROC, const void**, DWORD*) noexcept{};
    bool (*freeLibrary)(void*, HMODULE) noexcept{};
    DWORD (*invoke)(void*, InitializeV3Fn, const BootstrapContextV3*) noexcept{};
};
const CompanionLoaderOps& ProductionCompanionLoaderOps() noexcept;
CompanionLoadStatus ValidateCompanionEvidence(HMODULE bootstrap, HMODULE genuine,
    HMODULE candidate, FARPROC initializer, const FileIdentity& expected,
    const FileIdentity& actual, bool queried, const void* allocationBase) noexcept;
bool BuildCompanionPath(HMODULE bootstrap, wchar_t* output,
    std::size_t capacity, DWORD* error) noexcept;
CompanionLoadResult LoadAndInitializeCompanion(HMODULE,
    const BootstrapContextV3&, const CompanionLoaderOps&) noexcept;
CompanionLoadResult LoadAndInitializeCompanion(HMODULE, const BootstrapContextV3&) noexcept;
} // namespace rs2fix
