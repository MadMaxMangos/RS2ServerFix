#pragma once
#include <array>
#include <cstdint>
#include <string_view>
namespace rs2fix {
using Sha256Digest = std::array<std::uint8_t, 32>;
bool ParseSha256Upper(std::string_view text, Sha256Digest* digest) noexcept;
std::array<char, 65> FormatSha256Upper(const Sha256Digest& digest) noexcept;
}
