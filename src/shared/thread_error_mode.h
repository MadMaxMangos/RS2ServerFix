#pragma once
#include <Windows.h>

namespace rs2fix {
struct ThreadErrorModeOps {
    void* context{};
    DWORD (*getMode)(void*) noexcept{};
    bool (*setMode)(void*, DWORD, DWORD*) noexcept{};
    HMODULE (*loadLibrary)(void*, const wchar_t*, DWORD, DWORD*) noexcept{};
    // Production never returns. A fake may return to inspect the fatal outcome.
    void (*fatalRestoreFailure)(void*, DWORD) noexcept{};
};
const ThreadErrorModeOps& ProductionThreadErrorModeOps() noexcept;
HMODULE LoadLibraryWithThreadErrorMode(const wchar_t* absolutePath, DWORD flags,
    DWORD* error, const ThreadErrorModeOps& ops) noexcept;
} // namespace rs2fix
