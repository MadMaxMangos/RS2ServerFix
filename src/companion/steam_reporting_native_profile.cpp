#include "companion/steam_reporting_native_profile.h"
#include <cstring>
#include <cwchar>
#include <iterator>

namespace rs2fix::reporting {
namespace {
#include "companion/steam_reporting_native_profile_data.inc"

bool ResolveSystemImport(void*, const char* moduleName, const char* name,
    std::uintptr_t* address, DWORD* error) noexcept {
    if (address) *address = 0;
    if (error) *error = ERROR_INVALID_PARAMETER;
    if (!address || !moduleName || !name ||
        (_stricmp(moduleName,"KERNEL32.dll") && _stricmp(moduleName,"ADVAPI32.dll") &&
         _stricmp(moduleName,"MSVCR110.dll"))) return false;
    HMODULE module = GetModuleHandleA(moduleName); // Existing static dependency only.
    if (!module) { if (error) *error = GetLastError(); return false; }
    wchar_t loaded[512]{}, expected[512]{};
    const DWORD length = GetModuleFileNameW(module, loaded, static_cast<DWORD>(std::size(loaded)));
    const UINT system = GetSystemDirectoryW(expected, static_cast<UINT>(std::size(expected)));
    const auto leaf = std::strlen(moduleName);
    if (!length || length >= std::size(loaded) || !system || system >= std::size(expected) ||
        leaf + 2 > std::size(expected) - system) {
        if (error) *error = ERROR_BAD_PATHNAME;
        return false;
    }
    expected[system] = L'\\';
    for (std::size_t i = 0; i < leaf; ++i) expected[system + 1 + i] = static_cast<unsigned char>(moduleName[i]);
    expected[system + 1 + leaf] = 0;
    if (_wcsicmp(loaded, expected)) { if (error) *error = ERROR_BAD_PATHNAME; return false; }
    const auto function = GetProcAddress(module, name);
    if (!function) { if (error) *error = GetLastError(); return false; }
    *address = reinterpret_cast<std::uintptr_t>(function);
    if (error) *error = ERROR_SUCCESS;
    return true;
}
constexpr NativeImportOps kImports{nullptr, ResolveSystemImport};
} // namespace

const NativeLoggingProfile& ProductionNativeLoggingProfile() noexcept { return kNativeProduction; }
const NativeImportOps& ProductionNativeImportOps() noexcept { return kImports; }
const char* NativeLoggingInventorySha256() noexcept { return kNativeInventorySha256; }
} // namespace rs2fix::reporting
