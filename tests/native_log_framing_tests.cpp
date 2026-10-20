#include "shared/native_log_framing.h"
#include "test_framework.h"
#include <string>
#include <array>
#include <cstring>

namespace rs2fix::testcases {
void NativeLogFramingTests() {
    using namespace reporting::native_log;
    const std::string message = std::string(kMarker) + "{\"schema\":3,\"seq\":0}";
    for (const std::string prefix : {"Log: ", "[0000.00] Log: ",
            "[12345.67] Log: ", "[100000.00] Log: ", "[-000.00] Log: ", "[-1234.56] Log: "}) {
        const auto mode = prefix[0] == '[' ? PrefixMode::ElapsedTime : PrefixMode::LogOnly;
        const auto line = prefix + message + "\r\n";
        const auto view = InspectLine(line.data(), line.size(), mode, true);
        RS2_CHECK(view.kind == LineKind::Frame);
        RS2_CHECK(line.substr(view.messageOffset, view.messageBytes) == message);
        // Every possible read boundary leaves the exact selected line pending.
        for (std::size_t cut = 0; cut < line.size(); ++cut)
            RS2_CHECK(InspectLine(line.data(), cut, mode, false).kind == LineKind::Incomplete);
    }
    for (const std::string prefix : {"ScriptLog: ", "Log: player says ",
            "[1.00] Log: ", "[0000,00] Log: ", "[0000.000] Log: ",
            "[00001.00] Log: ", "[0000.00] Warning: ", "[+000.00] Log: ",
            "[0000.00] Log: other ", "[0000.00] Log: Log: "}) {
        const auto line = prefix + message + "\r\n";
        RS2_CHECK(InspectLine(line.data(), line.size(), PrefixMode::ElapsedTime, true).kind == LineKind::Unrelated);
        RS2_CHECK(InspectLine(line.data(), line.size(), PrefixMode::LogOnly, true).kind == LineKind::Unrelated);
    }
    std::string line = "Log: " + message;
    RS2_CHECK(InspectLine(line.data(), line.size(), PrefixMode::LogOnly, false).kind == LineKind::Incomplete);
    RS2_CHECK(InspectLine(line.data(), line.size(), PrefixMode::LogOnly, true).kind == LineKind::Malformed);
    line += '\n';
    RS2_CHECK(InspectLine(line.data(), line.size(), PrefixMode::LogOnly, true).kind == LineKind::Malformed);
    for (char invalid : {'\0', '\r', '\n', '\t', static_cast<char>(0x80)}) {
        line = "Log: " + message + invalid + "\r\n";
        RS2_CHECK(InspectLine(line.data(), line.size(), PrefixMode::LogOnly, true).kind == LineKind::Malformed);
    }
    line = "Log: " + std::string(kMarker) + std::string(kMessageLimit - sizeof(kMarker) + 1, 'x') + "\r\n";
    RS2_CHECK(InspectLine(line.data(), line.size(), PrefixMode::LogOnly, true).kind == LineKind::Frame);
    line.insert(line.size() - 2, 1, 'x');
    RS2_CHECK(InspectLine(line.data(), line.size(), PrefixMode::LogOnly, true).kind == LineKind::Malformed);
    RS2_CHECK(InspectLine(line.data(), line.size(), PrefixMode::LogOnly, false).kind == LineKind::Incomplete);
    line = "Log: unrelated " + std::string(kLineLimit * 2, 'x') + message + "\r\n";
    RS2_CHECK(InspectLine(line.data(), line.size(), PrefixMode::LogOnly, true).kind == LineKind::Unrelated);
    line = "Log: " + message + "\r\n";
    RS2_CHECK(InspectLine(line.data(), line.size(), static_cast<PrefixMode>(2), true).kind == LineKind::Unrelated);
    RS2_CHECK(InspectLine(nullptr, 0, PrefixMode::LogOnly, false).kind == LineKind::Incomplete);
    RS2_CHECK(InspectLine(nullptr, 1, PrefixMode::LogOnly, true).kind == LineKind::Malformed);

    // These code units would inject LF, CR, quote and NUL if narrowed by the
    // native file sink. Escape first, then validate the complete native message.
    const std::uint16_t unsafe[]{0x010a, 0x010d, 0x0122, 0x0100, 0xd83d, 0xde00, '"', '\\', '\n'};
    char escaped[128]{};
    std::size_t written{};
    RS2_CHECK(EscapeJsonUtf16(unsafe, std::size(unsafe), escaped, sizeof(escaped), &written));
    RS2_CHECK(std::strcmp(escaped, "\"\\u010a\\u010d\\u0122\\u0100\\ud83d\\ude00\\\"\\\\\\u000a\"") == 0);
    RS2_CHECK(written == std::strlen(escaped));
    const auto pathMessage = std::string(kMarker) + "{\"path\":" + escaped + "}";
    std::array<wchar_t, kMessageLimit + 1> ready{};
    RS2_CHECK(PrepareMessage(pathMessage.data(), pathMessage.size(), ready.data(), ready.size()));
    RS2_CHECK(ValidMessage(ready.data(), pathMessage.size()));
    ready[sizeof(kMarker)] = 0x010a;
    RS2_CHECK(!ValidMessage(ready.data(), pathMessage.size()));
    for (char invalid : {'\0', '\r', '\n', static_cast<char>(0x80)}) {
        const auto bad = std::string(kMarker) + invalid;
        RS2_CHECK(!PrepareMessage(bad.data(), bad.size(), ready.data(), ready.size()));
        RS2_CHECK(ready[0] == 0);
    }
    const auto maximum = std::string(kMarker) + std::string(kMessageLimit - sizeof(kMarker) + 1, 'x');
    RS2_CHECK(PrepareMessage(maximum.data(), maximum.size(), ready.data(), ready.size()));
    RS2_CHECK(ValidMessage(ready.data(), maximum.size()));
    RS2_CHECK(!PrepareMessage(maximum.data(), maximum.size(), ready.data(), maximum.size()));
    const auto excessive = maximum + "x";
    RS2_CHECK(!PrepareMessage(excessive.data(), excessive.size(), ready.data(), ready.size()));
    RS2_CHECK(!EscapeJsonUtf16(unsafe, std::size(unsafe), escaped, 8, &written));
    RS2_CHECK(escaped[0] == 0 && written == 0);
}
} // namespace rs2fix::testcases
