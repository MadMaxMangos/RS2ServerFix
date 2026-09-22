#include "test_framework.h"
#include "companion/steam_reporting_config.h"
#include <cstring>
#include <string>

using namespace rs2fix::reporting;
void ReportingConfigTests() {
    Config config{Mode::Repair};
    const auto parse = [&config](const char* value) {
        return ParseConfig(value, std::strlen(value), &config);
    };
    RS2_CHECK(parse("schema=2\nmode=observe\n") == Reason::None && config.mode == Mode::Observe);
    RS2_CHECK(parse(" mode = repair \r\n schema = 2\r\n") == Reason::None && config.mode == Mode::Repair);
    RS2_CHECK(parse("schema=2\nmode=disabled") == Reason::ConfigDisabled && config.mode == Mode::Disabled);
    for (const char* value : {"", "mode=repair", "schema=1\nmode=repair", "schema=02\nmode=repair",
        "schema=2\nmode=correct", "schema=2\nmode=REPAIR", "schema=2\nmode=repair\nextra=1",
        "schema=2\nmode=repair\nmode=observe", "schema=2\nmode=repair\nschema=2",
        "schema=2\nmode=repair # enabled", "schema=2\nmode=rep\rair", "schema=2\nmode="}) {
        RS2_CHECK(parse(value) == Reason::ConfigInvalid && config.mode == Mode::Invalid);
    }
    const char nul[] = "schema=2\nmode=repair\0\n";
    RS2_CHECK(ParseConfig(nul, sizeof(nul) - 1, &config) == Reason::ConfigInvalid);
    const char bom[] = "\xEF\xBB\xBFschema=2\nmode=repair";
    RS2_CHECK(ParseConfig(bom, sizeof(bom) - 1, &config) == Reason::ConfigInvalid);
    const std::string oversized(kConfigBytes + 1, '\n');
    RS2_CHECK(ParseConfig(oversized.data(), oversized.size(), &config) == Reason::ConfigInvalid);
    RS2_CHECK(ParseConfig(nullptr, 1, &config) == Reason::ConfigInvalid && config.mode == Mode::Invalid);
    RS2_CHECK(ParseConfig("schema=2", 8, nullptr) == Reason::ConfigInvalid);
}
