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

    ConfigV3 native{Mode::Repair, Diagnostics::Detailed};
    const auto parseNative = [&native](const char* value) {
        return ParseConfigV3(value, std::strlen(value), &native);
    };
    RS2_CHECK(parseNative("schema=3\nmode=observe\ndiagnostics=normal\n") == Reason::None);
    RS2_CHECK(native.mode == Mode::Observe && native.diagnostics == Diagnostics::Normal);
    RS2_CHECK(parseNative(" diagnostics = detailed \r\nmode = repair\r\nschema = 3") == Reason::None);
    RS2_CHECK(native.mode == Mode::Repair && native.diagnostics == Diagnostics::Detailed);
    RS2_CHECK(parseNative("schema=3\nmode=disabled\ndiagnostics=normal") == Reason::ConfigDisabled);
    for (const auto* invalid : {"schema=3\nmode=repair", "schema=3\ndiagnostics=normal",
            "mode=repair\ndiagnostics=normal", "schema=2\nmode=repair\ndiagnostics=normal",
            "schema=3\nmode=repair\ndiagnostics=normal\ndiagnostics=detailed",
            "schema=3\nmode=repair\ndiagnostics=verbose", "schema=03\nmode=repair\ndiagnostics=normal",
            "schema=3\nmode=repair\ndiagnostics=normal\nmax_log_mib=512",
            "schema=3\nmode=repair\ndiagnostics=normal\nmode=observe",
            "schema=3\nmode=repair\ndiagnostics=normal\nschema=3",
            "schema=3\nmode=repair\ndiagnostics=normal # default", "schema=3\nmode=disabled"}) {
        RS2_CHECK(parseNative(invalid) == Reason::ConfigInvalid);
        RS2_CHECK(native.mode == Mode::Invalid && native.diagnostics == Diagnostics::Invalid);
    }
    const char nativeNul[] = "schema=3\nmode=repair\ndiagnostics=normal\0\n";
    RS2_CHECK(ParseConfigV3(nativeNul, sizeof(nativeNul) - 1, &native) == Reason::ConfigInvalid);
    RS2_CHECK(ParseConfigV3(nullptr, 1, &native) == Reason::ConfigInvalid);
    RS2_CHECK(ParseConfigV3("schema=3", 8, nullptr) == Reason::ConfigInvalid);
    RS2_CHECK(ParseConfigV3(oversized.data(), oversized.size(), &native) == Reason::ConfigInvalid);
    RS2_CHECK(parse("schema=3\nmode=repair\ndiagnostics=normal") == Reason::ConfigInvalid);
}
