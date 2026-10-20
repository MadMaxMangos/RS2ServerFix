#include "shared/native_log_framing.h"

namespace rs2fix::reporting::native_log {
namespace {
enum class Match { No, Partial, Yes };
Match Literal(const char* bytes, std::size_t size, std::size_t& at,
    const char* literal, std::size_t count) noexcept {
    for (std::size_t i = 0; i < count; ++i) {
        if (at == size) return Match::Partial;
        if (bytes[at++] != literal[i]) return Match::No;
    }
    return Match::Yes;
}
bool Digit(char c) noexcept { return c >= '0' && c <= '9'; }

// Current file prefix uses the pinned ASCII format "[%07.2f] ". Width is a
// minimum, not seven fixed characters. Accept its finite signed decimal shape
// (including negative zero), but not locale commas, exponents, NaN or infinity.
Match Prefix(const char* bytes, std::size_t size, std::size_t& at,
    PrefixMode mode) noexcept {
    if (mode == PrefixMode::LogOnly) return Literal(bytes, size, at, "Log: ", 5);
    if (mode != PrefixMode::ElapsedTime) return Match::No;
    auto match = Literal(bytes, size, at, "[", 1);
    if (match != Match::Yes) return match;
    if (at == size) return Match::Partial;
    const bool negative = bytes[at] == '-';
    if (negative) ++at;
    const auto first = at;
    while (at < size && Digit(bytes[at])) {
        if (at >= kPrefixLimit - 10) return Match::No;
        ++at;
    }
    if (at == size) return Match::Partial;
    const auto digits = at - first;
    const std::size_t minimum = negative ? 3 : 4;
    if (digits < minimum || (digits > minimum && bytes[first] == '0')) return Match::No;
    match = Literal(bytes, size, at, ".", 1);
    if (match != Match::Yes) return match;
    for (unsigned i = 0; i < 2; ++i) {
        if (at == size) return Match::Partial;
        if (!Digit(bytes[at++])) return Match::No;
    }
    return Literal(bytes, size, at, "] Log: ", 7);
}
} // namespace

LineView InspectLine(const char* bytes, std::size_t size, PrefixMode mode,
    bool complete) noexcept {
    const LineView unrelated{LineKind::Unrelated, 0, 0};
    const LineView incomplete{LineKind::Incomplete, 0, 0};
    const LineView malformed{LineKind::Malformed, 0, 0};
    if (!bytes) return size ? malformed : (complete ? unrelated : incomplete);
    std::size_t at{};
    const auto prefix = Prefix(bytes, size, at, mode);
    if (prefix == Match::No) return unrelated;
    if (prefix == Match::Partial) return complete ? unrelated : incomplete;
    if (at > kPrefixLimit) return unrelated;
    const auto offset = at;
    const auto marker = Literal(bytes, size, at, kMarker, sizeof(kMarker) - 1);
    if (marker == Match::No) return unrelated;
    if (marker == Match::Partial) return complete ? unrelated : incomplete;
    if (!complete) return {LineKind::Incomplete,offset,size-offset};
    // Only selected complete lines are subject to our frame/encoding bounds.
    // A partial tail, even an oversized one, is not yet a complete bad receipt.
    if (size < at + 2 || size - offset > kMessageLimit + 2 ||
        bytes[size - 2] != '\r' || bytes[size - 1] != '\n') return {LineKind::Malformed,offset,size-offset};
    const auto end = size - 2;
    for (auto i = offset; i < end; ++i)
        if (static_cast<unsigned char>(bytes[i]) < 0x20 ||
            static_cast<unsigned char>(bytes[i]) > 0x7e) return {LineKind::Malformed,offset,size-offset};
    return {LineKind::Frame, offset, end - offset};
}

bool BelongsToRun(const char* message,std::size_t bytes,const std::uint8_t (&runId)[16]) noexcept {
    if (!message) return false;
    std::size_t at{};
    constexpr char lead[]="{\"schema\":3,\"type\":\"";
    if (Literal(message,bytes,at,kMarker,sizeof(kMarker)-1)!=Match::Yes ||
        Literal(message,bytes,at,lead,sizeof(lead)-1)!=Match::Yes) return false;
    const auto typeBegin=at;
    while (at<bytes && at-typeBegin<32 &&
        ((message[at]>='a' && message[at]<='z') || message[at]=='-')) ++at;
    constexpr char run[]="\",\"run_id\":\"";
    if (at==typeBegin || Literal(message,bytes,at,run,sizeof(run)-1)!=Match::Yes) return false;
    constexpr char hex[]="0123456789abcdef";
    for (auto value:runId) {
        if (bytes-at<2 || message[at++]!=hex[value>>4] || message[at++]!=hex[value&15]) return false;
    }
    return at<bytes && message[at]=='"';
}

bool EscapeJsonUtf16(const std::uint16_t* text, std::size_t chars,
    char* output, std::size_t capacity, std::size_t* written) noexcept {
    if (written) *written = 0;
    if (output && capacity) output[0] = 0;
    if (!written || !output || !capacity || (!text && chars) || chars > 1023) return false;
    constexpr char hex[] = "0123456789abcdef";
    std::size_t at{};
    const auto put = [&](char c) noexcept {
        if (at >= capacity - 1) return false;
        output[at++] = c;
        return true;
    };
    bool ok = put('"');
    for (std::size_t i = 0; ok && i < chars; ++i) {
        const auto value = text[i];
        if (value == '"' || value == '\\') ok = put('\\') && put(static_cast<char>(value));
        else if (value >= 0x20 && value <= 0x7e) ok = put(static_cast<char>(value));
        else {
            // Escape UTF-16 code units, including both units of surrogate pairs.
            // No UTF-8/locale conversion can reintroduce raw low-byte delimiters.
            ok = put('\\') && put('u');
            for (int shift = 12; ok && shift >= 0; shift -= 4)
                ok = put(hex[(value >> shift) & 15]);
        }
    }
    ok = ok && put('"');
    if (!ok) { output[0] = 0; return false; }
    output[at] = 0;
    *written = at;
    return true;
}

bool PrepareMessage(const char* ascii, std::size_t bytes,
    wchar_t* output, std::size_t capacity) noexcept {
    if (output && capacity) output[0] = 0;
    if (!ascii || !output || bytes < sizeof(kMarker) - 1 ||
        bytes > kMessageLimit || capacity <= bytes) return false;
    // Validate before conversion, so a rejected slot contains no partial frame.
    for (std::size_t i = 0; i < bytes; ++i) {
        const auto c = static_cast<unsigned char>(ascii[i]);
        if (c < 0x20 || c > 0x7e || (i < sizeof(kMarker) - 1 && ascii[i] != kMarker[i])) return false;
    }
    for (std::size_t i = 0; i < bytes; ++i) output[i] = static_cast<unsigned char>(ascii[i]);
    output[bytes] = 0;
    return true;
}

bool ValidMessage(const wchar_t* message, std::size_t chars) noexcept {
    if (!message || chars < sizeof(kMarker) - 1 || chars > kMessageLimit || message[chars] != 0)
        return false;
    for (std::size_t i = 0; i < chars; ++i)
        if (message[i] < 0x20 || message[i] > 0x7e ||
            (i < sizeof(kMarker) - 1 && message[i] != static_cast<unsigned char>(kMarker[i]))) return false;
    return true;
}
} // namespace rs2fix::reporting::native_log
