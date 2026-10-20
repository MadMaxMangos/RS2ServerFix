#pragma once
#include <cstddef>
#include <cstdint>

namespace rs2fix::reporting::native_log {
inline constexpr std::size_t kMessageLimit = 8192;
inline constexpr std::size_t kPrefixLimit = 128;
inline constexpr std::size_t kLineLimit = kPrefixLimit + kMessageLimit + 2;
inline constexpr char kMarker[] = "[RS2ServerFix:event] ";

enum class PrefixMode : std::uint64_t { LogOnly = 0, ElapsedTime = 1 };
enum class LineKind { Unrelated, Incomplete, Frame, Malformed };
struct LineView {
    LineKind kind;
    // Includes the marker, excludes the engine prefix. A complete valid Frame
    // excludes CRLF; Incomplete/Malformed describes the available remainder,
    // potentially including partial or invalid delimiters. No receipt implied.
    std::size_t messageOffset;
    std::size_t messageBytes;
};

// Inspect an explicit byte count, not a C string. Only the exact native prefix
// immediately followed by our marker selects a frame; chat containing a marker
// later in a line cannot impersonate one. The caller streams unrelated long
// lines without retaining them. Incomplete selected lines never imply loss.
// Run/schema/sequence/JSON/digest validation belongs to the receipt consumer.
LineView InspectLine(const char* bytes, std::size_t size, PrefixMode,
    bool complete) noexcept;
// Scope before treating malformed/oversized selected lines as this run's loss.
// Matches only our canonical leading schema/type/run envelope, never a substring.
// The random run ID is correlation, not a secret or an authenticity guarantee.
bool BelongsToRun(const char* message, std::size_t bytes,
    const std::uint8_t (&runId)[16]) noexcept;

// Worker-only preparation. Never narrow arbitrary UTF-16 into the game's file
// sink: it writes low bytes verbatim. Metadata strings must first be JSON-escaped.
// Inputs and outputs must not overlap; ready storage has chars+1 elements so
// ValidMessage can inspect the required terminator at that explicit boundary.
bool EscapeJsonUtf16(const std::uint16_t* text, std::size_t chars,
    char* output, std::size_t capacity, std::size_t* written) noexcept;
bool PrepareMessage(const char* ascii, std::size_t bytes,
    wchar_t* output, std::size_t capacity) noexcept;
// A final bounded check at the native-call boundary also rejects a damaged or
// incorrectly prepared ready slot. Does not call native code or allocate.
bool ValidMessage(const wchar_t* message, std::size_t chars) noexcept;
} // namespace rs2fix::reporting::native_log
