#pragma once
#include "companion/steam_reporting_types.h"
#include <Windows.h>

namespace rs2fix::reporting {
// Only a complete schema-2 document can authorize a mode. Error outputs never
// retain a partially parsed repair value from an earlier line.
Reason ParseConfig(const char* bytes, std::size_t size, Config* output) noexcept;
Reason ReadConfig(const wchar_t* companionDirectory, Config* output, DWORD* error) noexcept;
// V3 has exactly three required keys. No legacy quota/observer-config fallback,
// partial repair default or reload; legacy entry points above keep schema 2.
Reason ParseConfigV3(const char* bytes, std::size_t size, ConfigV3* output) noexcept;
Reason ReadConfigV3(const wchar_t* companionDirectory, ConfigV3* output, DWORD* error) noexcept;
} // namespace rs2fix::reporting
