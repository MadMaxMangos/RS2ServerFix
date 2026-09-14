#include "shared/digest.h"
namespace rs2fix {
bool ParseSha256Upper(const std::string_view text, Sha256Digest* digest) noexcept {
    if (!digest) return false;
    *digest = {};
    if (text.size() != 64) return false;
    Sha256Digest parsed{};
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        const unsigned value = c >= '0' && c <= '9' ? static_cast<unsigned>(c - '0') :
            c >= 'A' && c <= 'F' ? static_cast<unsigned>(c - 'A' + 10) : 16;
        if (value == 16) return false;
        parsed[i / 2] = static_cast<std::uint8_t>((parsed[i / 2] << 4) | value);
    }
    *digest = parsed;
    return true;
}
std::array<char, 65> FormatSha256Upper(const Sha256Digest& digest) noexcept {
    constexpr char hex[] = "0123456789ABCDEF";
    std::array<char, 65> result{};
    for (std::size_t i = 0; i < digest.size(); ++i) {
        result[i * 2] = hex[digest[i] >> 4];
        result[i * 2 + 1] = hex[digest[i] & 15];
    }
    return result;
}
}
