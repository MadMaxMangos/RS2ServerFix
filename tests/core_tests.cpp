#include "bootstrap/bootstrap_types.h"
#include "companion/build_identity.h"
#include "shared/bootstrap_abi.h"

#include "test_framework.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string_view>

namespace {

std::uint8_t HexNibble(const char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
    }
    if (value >= 'A' && value <= 'F') {
        return static_cast<std::uint8_t>(value - 'A' + 10);
    }
    return 0xff;
}

rs2fix::Sha256Digest ParseDigest(const std::string_view text) {
    rs2fix::Sha256Digest digest{};
    RS2_CHECK(text.size() == digest.size() * 2);
    for (std::size_t index = 0; index < digest.size(); ++index) {
        const std::uint8_t high = HexNibble(text[index * 2]);
        const std::uint8_t low = HexNibble(text[index * 2 + 1]);
        RS2_CHECK(high != 0xff);
        RS2_CHECK(low != 0xff);
        digest[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return digest;
}

void TestBootstrapAbi() {
    RS2_CHECK(sizeof(rs2fix::BootstrapContextV1) == 48);
    RS2_CHECK(rs2fix::kBootstrapAbiVersion == 1);
    RS2_CHECK(rs2fix::kInitOk == 0);
    RS2_CHECK(rs2fix::kInitAlreadyInitialized == 1);
    RS2_CHECK(rs2fix::kInitInvalidContext == 2);
    RS2_CHECK(rs2fix::kInitHostIdentityFailed == 3);
    RS2_CHECK(rs2fix::kInitMarkerWriteFailed == 4);
    RS2_CHECK(
        static_cast<std::uint32_t>(
            rs2fix::GenuineResolverStatus::Ok) == 0);
}

void ExpectIdentity(
    const std::string_view digestText,
    const rs2fix::BuildIdentity expected,
    const char* expectedName) {
    const rs2fix::Sha256Digest digest = ParseDigest(digestText);
    const rs2fix::BuildIdentity actual =
        rs2fix::ClassifyBuild(digest, true);
    RS2_CHECK(actual == expected);
    RS2_CHECK(std::strcmp(
        rs2fix::BuildIdentityName(actual), expectedName) == 0);
}

void TestBuildIdentity() {
    ExpectIdentity(
        "155EBC77D2FA574F0A94709839EF1DF6A3DA82B278C846F14223967B058C4622",
        rs2fix::BuildIdentity::Pr1CrashFullDump,
        "pr1-crash-full-dump");
    ExpectIdentity(
        "5820F0DA82D7C2903DE31E0865320D9E70A0BF74F78F83C83DB4F9DEEAEB1DEF",
        rs2fix::BuildIdentity::Pr1StockBaseline,
        "pr1-stock-baseline");
    ExpectIdentity(
        "F4E38510832D1FAADA8AAD3B88CD2255B3EA49267EF0E874468E23BDE4EDFCC3",
        rs2fix::BuildIdentity::CurrentStock,
        "current-stock");
    ExpectIdentity(
        "0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393",
        rs2fix::BuildIdentity::CurrentFullDump,
        "current-full-dump");

    const rs2fix::Sha256Digest unknown{};
    RS2_CHECK(
        rs2fix::ClassifyBuild(unknown, true) ==
        rs2fix::BuildIdentity::Unknown);
    RS2_CHECK(std::strcmp(
        rs2fix::BuildIdentityName(rs2fix::BuildIdentity::Unknown),
        "unknown") == 0);
    RS2_CHECK(
        rs2fix::ClassifyBuild(unknown, false) ==
        rs2fix::BuildIdentity::Indeterminate);
    RS2_CHECK(std::strcmp(
        rs2fix::BuildIdentityName(rs2fix::BuildIdentity::Indeterminate),
        "indeterminate") == 0);
}

} // namespace

int main() {
    TestBootstrapAbi();
    TestBuildIdentity();
    std::cout << "checks=" << rs2fix::test::g_checks
              << " failures=" << rs2fix::test::g_failures << '\n';
    return rs2fix::test::g_failures == 0 ? 0 : 1;
}
