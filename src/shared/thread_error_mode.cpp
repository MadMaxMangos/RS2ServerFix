#include "shared/thread_error_mode.h"

namespace rs2fix {
namespace {
DWORD GetMode(void*) noexcept { return GetThreadErrorMode(); }
bool SetMode(void*, DWORD mode, DWORD* error) noexcept {
    if (SetThreadErrorMode(mode, nullptr)) { *error = ERROR_SUCCESS; return true; }
    *error = GetLastError();
    return false;
}
HMODULE Load(void*, const wchar_t* path, DWORD flags, DWORD* error) noexcept {
    HMODULE module = LoadLibraryExW(path, nullptr, flags);
    *error = module != nullptr ? ERROR_SUCCESS : GetLastError();
    return module;
}
[[noreturn]] void Fatal(void*, DWORD) noexcept {
    RaiseFailFastException(nullptr, nullptr, FAIL_FAST_GENERATE_EXCEPTION_ADDRESS);
    TerminateProcess(GetCurrentProcess(), 0xC0000602UL);
    __assume(0);
}
constexpr ThreadErrorModeOps kProduction{nullptr, GetMode, SetMode, Load, Fatal};
} // namespace
const ThreadErrorModeOps& ProductionThreadErrorModeOps() noexcept { return kProduction; }

HMODULE LoadLibraryWithThreadErrorMode(const wchar_t* absolutePath, DWORD flags,
    DWORD* error, const ThreadErrorModeOps& ops) noexcept {
    DWORD failure = ERROR_INVALID_PARAMETER;
    if (error != nullptr) *error = failure;
    if (absolutePath == nullptr || ops.getMode == nullptr || ops.setMode == nullptr ||
        ops.loadLibrary == nullptr || ops.fatalRestoreFailure == nullptr) return nullptr;
    // Suppress loader dialogs on this thread without changing process-wide policy.
    const DWORD savedMode = ops.getMode(ops.context);
    if (!ops.setMode(ops.context, savedMode | SEM_FAILCRITICALERRORS, &failure)) {
        if (error != nullptr) *error = failure;
        return nullptr;
    }
    HMODULE module = ops.loadLibrary(ops.context, absolutePath, flags, &failure);
    DWORD restoreError = ERROR_SUCCESS;
    if (!ops.setMode(ops.context, savedMode, &restoreError)) {
        // Continuing would leak our temporary error mode into the host caller.
        if (error != nullptr) *error = restoreError;
        ops.fatalRestoreFailure(ops.context, restoreError);
        return nullptr;
    }
    if (error != nullptr) *error = failure;
    return module;
}
} // namespace rs2fix
