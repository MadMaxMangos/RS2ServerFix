#pragma once

#include "shared/digest.h"
#include <cstdint>

namespace rs2fix {

enum class BuildIdentity : std::uint32_t {
    Pr1CrashFullDump,
    Pr1StockBaseline,
    CurrentStock,
    CurrentFullDump,
    Unknown,
    Indeterminate,
};

BuildIdentity ClassifyBuild(
    const Sha256Digest& digest,
    bool digestValid) noexcept;

const char* BuildIdentityName(BuildIdentity identity) noexcept;

} // namespace rs2fix
