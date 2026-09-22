#pragma once

#include "companion/steam_reporting_types.h"

namespace rs2fix::reporting {
// Reads an already-owned bounded JSON copy; never probes native memory. The
// caller supplies independently qualified native counts and scrubs its copy.
// Limits count container openings, property names and scalar values as tokens;
// depth counts simultaneously open containers, including the root object.
// Returns None only after validating the whole document and its required tuple.
Reason ValidatePreparedJson(const char* bytes, std::size_t size,
    const NativeCounts& expected) noexcept;
} // namespace rs2fix::reporting
