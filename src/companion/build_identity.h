#pragma once

#include <array>
#include <cstdint>

namespace rs2fix {

using Sha256Digest = std::array<std::uint8_t, 32>;

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
