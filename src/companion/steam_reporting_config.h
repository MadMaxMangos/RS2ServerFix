#pragma once
#include "companion/steam_reporting_types.h"
#include <Windows.h>

namespace rs2fix::reporting {
// Only a complete schema-2 document can authorize a mode. Error outputs never
// retain a partially parsed repair value from an earlier line.
Reason ParseConfig(const char* bytes, std::size_t size, Config* output) noexcept;
Reason ReadConfig(const wchar_t* companionDirectory, Config* output, DWORD* error) noexcept;
} // namespace rs2fix::reporting
