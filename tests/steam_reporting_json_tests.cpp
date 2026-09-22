#include "companion/steam_reporting_json.h"
#include "test_framework.h"

#include <cstring>
#include <string>

namespace {
using namespace rs2fix::reporting;
constexpr NativeCounts kCounts{65, 24, 64};
constexpr char kProperties[] =
    "\"op\":[{\"k\":\"PI_COUNT\",\"v\":\"65\"},"
    "{\"k\":\"BotPlayerCount\",\"v\":\"24\"},"
    "{\"k\":\"MaxPlayerCount\",\"v\":\"64\"}]";

Reason Check(const std::string& text, const NativeCounts& counts = kCounts) {
    return ValidatePreparedJson(text.data(), text.size(), counts);
}
std::string Document(const std::string& extra = {}) {
    return std::string("{") + kProperties + extra + "}";
}
std::string CountDocument(const std::string& value) {
    return std::string("{\"op\":[{\"k\":\"PI_COUNT\",\"v\":") + value +
        "},{\"k\":\"BotPlayerCount\",\"v\":\"24\"},"
        "{\"k\":\"MaxPlayerCount\",\"v\":\"64\"}]}";
}
void NativeShapeAndCoherence() {
    // Synthetic native GameMode shape: root op is an array of direct k/v
    // objects. No recorded player identity or real endpoint is in this fixture.
    const std::string native = std::string("{\"ip\":\"192.0.2.1\",\"pr\":7777,") +
        kProperties + ",\"map\":\"VNTE-Fixture\"}";
    RS2_CHECK(Check(native) == Reason::None); // Native PI 65 exceeds max 64.
    RS2_CHECK(Check(native, {64, 24, 64}) == Reason::PreparedMismatch);
    RS2_CHECK(Check(native, {65, 23, 64}) == Reason::PreparedMismatch);
    RS2_CHECK(Check(native, {65, 24, 63}) == Reason::PreparedMismatch);
    RS2_CHECK(Check(" \r\n\t" + native + "\n\t ") == Reason::None);
    RS2_CHECK(Check("{\"op\":[{\"v\":\"65\",\"k\":\"PI_COUNT\"},"
        "{\"v\":\"24\",\"k\":\"BotPlayerCount\"},"
        "{\"v\":\"64\",\"k\":\"MaxPlayerCount\"}]}") == Reason::None);
    RS2_CHECK(Check("{\"op\":[{\"k\":\"PI_COUNT\",\"v\":\"0\"},"
        "{\"k\":\"BotPlayerCount\",\"v\":\"0\"},"
        "{\"k\":\"MaxPlayerCount\",\"v\":\"0\"}]}", {0, 0, 0}) == Reason::None);
    RS2_CHECK(Check(CountDocument("\"4294967295\""), {UINT32_MAX, 24, 64}) == Reason::None);
    // The reader compares a tuple; separate source/vector guards impose native
    // field bounds. It must not introduce a human-only or PI<=maximum policy.
    RS2_CHECK(Check(Document(",\"extra\":{\"op\":[],\"k\":null,\"v\":[true,false,null,-0,0.1,1e999]}")) == Reason::None);
    RS2_CHECK(Check("{\"op\":[{\"k\":\"other\",\"v\":{\"nested\":[false,2.5]}},"
        "{\"k\":\"PI_COUNT\",\"v\":\"65\"},"
        "{\"k\":\"BotPlayerCount\",\"v\":\"24\"},"
        "{\"k\":\"MaxPlayerCount\",\"v\":\"64\"}]}") == Reason::None);
}
void EscapesAndAmbiguity() {
    RS2_CHECK(Check("{\"o\\u0070\":[{\"\\u006b\":\"PI_\\u0043OUNT\",\"v\":\"\\u0036\\u0035\"},"
        "{\"k\":\"BotPlayerCount\",\"\\u0076\":\"24\"},"
        "{\"k\":\"MaxPlayerCount\",\"v\":\"64\"}]}") == Reason::None);
    for (const auto* extra : {",\"op\":[]", ",\"o\\u0070\":[]"})
        RS2_CHECK(Check(Document(extra)) == Reason::PreparedMalformed);
    for (const auto* entry : {
        "{\"k\":\"PI_COUNT\",\"k\":\"other\",\"v\":\"65\"}",
        "{\"k\":\"other\",\"\\u006b\":\"PI_COUNT\",\"v\":\"65\"}",
        "{\"k\":\"PI_COUNT\",\"v\":\"65\",\"v\":\"65\"}",
        "{\"k\":\"PI_COUNT\",\"v\":\"65\",\"\\u0076\":null}",
        "{\"k\":\"other\",\"v\":null,\"v\":false}",
        "{\"v\":\"65\"}", "{\"k\":\"PI_COUNT\"}",
        "{\"k\":null,\"v\":\"65\"}", "[]", "null"}) {
        const auto text = std::string("{\"op\":[") + entry +
            ",{\"k\":\"BotPlayerCount\",\"v\":\"24\"},"
            "{\"k\":\"MaxPlayerCount\",\"v\":\"64\"}]}";
        RS2_CHECK(Check(text) == Reason::PreparedMalformed);
    }
    auto duplicate = Document();
    duplicate.insert(duplicate.size() - 2, ",{\"k\":\"PI_\\u0043OUNT\",\"v\":\"65\"}");
    RS2_CHECK(Check(duplicate) == Reason::PreparedMalformed);
    for (const auto* value : {"65", "null", "true", "{}", "[]", "\"\"", "\"065\"", "\"00\"",
        "\"+65\"", "\"-1\"", "\" 65\"", "\"65 \"", "\"65.0\"", "\"6.5e1\"",
        "\"4294967296\"", "\"999999999999999999999999999\"", "\"65\\u0000\"",
        "\"\\u0666\\u0665\""})
        RS2_CHECK(Check(CountDocument(value)) == Reason::PreparedMalformed);
    for (const auto* text : {"{}", "[]", "null", "{\"op\":{}}", "{\"op\":[]}",
        "{\"op\":[{\"k\":\"PI_COUNT\",\"v\":\"65\"}]}",
        "{\"nested\":{\"op\":[{\"k\":\"PI_COUNT\",\"v\":\"65\"}]}}"})
        RS2_CHECK(Check(text) == Reason::PreparedMalformed);
}
void FullSyntaxAndUnicode() {
    for (const auto* value : {"0", "-0", "123456", "-12.50", "0.0e+2", "1E-2", "1e999",
        "true", "false", "null", "[]", "{}", "[1,{},[null]]",
        "\"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0000\"", "\"\\uD83D\\uDE00\"",
        "\"\xC2\x80\xDF\xBF\xE0\xA0\x80\xEF\xBF\xBF\xF0\x90\x80\x80\xF4\x8F\xBF\xBF\""})
        RS2_CHECK(Check(Document(std::string(",\"x\":") + value)) == Reason::None);
    for (const auto* value : {"+1", "01", "-01", "-", ".5", "1.", "1e", "1e+", "1e-",
        "NaN", "Infinity", "True", "nul", "falsefalse", "[1,]", "[,1]", "{,}",
        "{\"a\":1,}", "{\"a\" 1}", "{a:1}", "[1 2]", "[}",
        "\"\\q\"", "\"\\u00GG\"", "\"\\u000\"", "\"\\uD800\"", "\"\\uDC00\"",
        "\"\\uD800\\u0041\"", "\"\\uD800x\"", "\"line\nfeed\"",
        "\"\x80\"", "\"\xC0\xAF\"", "\"\xC1\xBF\"", "\"\xC2\"",
        "\"\xE0\x80\x80\"", "\"\xED\xA0\x80\"", "\"\xE1\x80\"",
        "\"\xF0\x80\x80\x80\"", "\"\xF4\x90\x80\x80\"", "\"\xF5\x80\x80\x80\"",
        "\"\xF0\x90\x80\"", "\"\xE2\x28\xA1\""})
        RS2_CHECK(Check(Document(std::string(",\"x\":") + value)) == Reason::PreparedMalformed);
    for (const auto* tail : {"x", "{}", ",", "\xEF\xBB\xBF", "//comment", "/*comment*/"})
        RS2_CHECK(Check(Document() + tail) == Reason::PreparedMalformed);
    RS2_CHECK(Check(std::string("\xEF\xBB\xBF") + Document()) == Reason::PreparedMalformed);
    auto rawNull = Document(",\"x\":\"a");
    rawNull.pop_back();
    rawNull.push_back('\0');
    rawNull += "b\"}";
    RS2_CHECK(Check(rawNull) == Reason::PreparedMalformed);
    // The parser must not succeed early after finding the tuple or overread at
    // any truncation boundary, including inside escapes and multibyte strings.
    const auto complete = Document(",\"x\":\"\\uD83D\\uDE00\xE2\x82\xAC\"");
    for (std::size_t length = 1; length < complete.size(); ++length)
        RS2_CHECK(ValidatePreparedJson(complete.data(), length, kCounts) == Reason::PreparedMalformed);
}
void AdmissionLimits() {
    RS2_CHECK(ValidatePreparedJson(nullptr, 1, kCounts) == Reason::PreparedUnavailable);
    RS2_CHECK(ValidatePreparedJson("", 0, kCounts) == Reason::PreparedUnavailable);
    RS2_CHECK(Check(" \n\t ") == Reason::PreparedMalformed);
    auto padded = Document();
    padded.resize(kJsonBytes, ' ');
    RS2_CHECK(Check(padded) == Reason::None);
    padded += ' ';
    RS2_CHECK(Check(padded) == Reason::PreparedLimit);
    // Root is depth one. Fifteen simultaneous additional arrays reach 16.
    const auto atDepth = Document(",\"x\":" + std::string(kJsonDepth - 1, '[') + "0" +
        std::string(kJsonDepth - 1, ']'));
    RS2_CHECK(Check(atDepth) == Reason::None);
    const auto tooDeep = Document(",\"x\":" + std::string(kJsonDepth, '[') + "0" +
        std::string(kJsonDepth, ']'));
    RS2_CHECK(Check(tooDeep) == Reason::PreparedLimit);
    // The tuple is 18 tokens; extra property name + array adds two. Fill the
    // remaining budget with scalars, then exceed it by one valid scalar.
    std::string items;
    for (std::size_t i = 0; i < kJsonTokens - 20; ++i) {
        if (i) items += ',';
        items += '0';
    }
    RS2_CHECK(Check(Document(",\"x\":[" + items + "]")) == Reason::None);
    RS2_CHECK(Check(Document(",\"x\":[" + items + ",0]")) == Reason::PreparedLimit);
    auto longString = Document(",\"x\":\"" + std::string(32000, 'a') + "\"");
    RS2_CHECK(Check(longString) == Reason::None);
}
} // namespace

void ReportingJsonTests() {
    NativeShapeAndCoherence();
    EscapesAndAmbiguity();
    FullSyntaxAndUnicode();
    AdmissionLimits();
}
