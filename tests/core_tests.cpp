#include "bootstrap/bootstrap_types.h"
#include "companion/build_identity.h"
#include "companion/marker.h"
#include "companion/sha256.h"
#include "shared/bootstrap_abi.h"

#include "test_framework.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
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

std::wstring GetTemporaryPath() {
    wchar_t buffer[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, buffer);
    RS2_CHECK(length != 0);
    RS2_CHECK(length < MAX_PATH);
    return std::wstring(buffer, length);
}

std::wstring MakeTemporaryFile(const wchar_t* prefix) {
    const std::wstring directory = GetTemporaryPath();
    wchar_t path[MAX_PATH]{};
    const UINT result = GetTempFileNameW(
        directory.c_str(), prefix, 0, path);
    RS2_CHECK(result != 0);
    return path;
}

bool WriteAll(HANDLE file, const void* data, const DWORD size) {
    const auto* cursor = static_cast<const std::uint8_t*>(data);
    DWORD remaining = size;
    while (remaining != 0) {
        DWORD written = 0;
        if (!WriteFile(file, cursor, remaining, &written, nullptr) ||
            written == 0) {
            return false;
        }
        cursor += written;
        remaining -= written;
    }
    return true;
}

void WriteBytesToFile(
    const std::wstring& path,
    const void* data,
    const DWORD size) {
    const HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    RS2_CHECK(file != INVALID_HANDLE_VALUE);
    if (file != INVALID_HANDLE_VALUE) {
        RS2_CHECK(WriteAll(file, data, size));
        RS2_CHECK(CloseHandle(file) != FALSE);
    }
}

void PatchByte(
    const std::wstring& path,
    const std::uint64_t offset,
    const std::uint8_t value) {
    const HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    RS2_CHECK(file != INVALID_HANDLE_VALUE);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    RS2_CHECK(SetFilePointerEx(file, position, nullptr, FILE_BEGIN) != FALSE);
    RS2_CHECK(WriteAll(file, &value, 1));
    RS2_CHECK(CloseHandle(file) != FALSE);
}

void ExpectFileDigest(
    const wchar_t* path,
    const std::string_view expectedText) {
    const rs2fix::FileHashResult result = rs2fix::HashFileSha256(
        path, GetTickCount64() + 60000);
    RS2_CHECK(result.digestValid);
    RS2_CHECK(!result.timedOut);
    RS2_CHECK(result.error == ERROR_SUCCESS);
    RS2_CHECK(result.digest == ParseDigest(expectedText));
}

void TestSha256() {
    const std::wstring smallFile = MakeTemporaryFile(L"R2H");
    const char bytes[] = {'a', 'b', 'c'};
    WriteBytesToFile(smallFile, bytes, sizeof(bytes));

    ExpectFileDigest(
        smallFile.c_str(),
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");

    const rs2fix::FileHashResult timeout =
        rs2fix::HashFileSha256(smallFile.c_str(), 0);
    RS2_CHECK(!timeout.digestValid);
    RS2_CHECK(timeout.timedOut);

    RS2_CHECK(DeleteFileW(smallFile.c_str()) != FALSE);

    ExpectFileDigest(
        RS2_PR1_BASELINE_PATH,
        "5820F0DA82D7C2903DE31E0865320D9E70A0BF74F78F83C83DB4F9DEEAEB1DEF");
    ExpectFileDigest(
        RS2_CURRENT_STOCK_PATH,
        "F4E38510832D1FAADA8AAD3B88CD2255B3EA49267EF0E874468E23BDE4EDFCC3");

    const std::wstring derivedPr1 = MakeTemporaryFile(L"R1D");
    RS2_CHECK(CopyFileW(
        RS2_PR1_BASELINE_PATH, derivedPr1.c_str(), FALSE) != FALSE);
    PatchByte(derivedPr1, 0x1e1, 0x3b);
    PatchByte(derivedPr1, 0xa6a313, 0x42);
    ExpectFileDigest(
        derivedPr1.c_str(),
        "155EBC77D2FA574F0A94709839EF1DF6A3DA82B278C846F14223967B058C4622");
    RS2_CHECK(DeleteFileW(derivedPr1.c_str()) != FALSE);

    const std::wstring derivedCurrent = MakeTemporaryFile(L"R3D");
    RS2_CHECK(CopyFileW(
        RS2_CURRENT_STOCK_PATH, derivedCurrent.c_str(), FALSE) != FALSE);
    PatchByte(derivedCurrent, 0x1e1, 0xf9);
    PatchByte(derivedCurrent, 0xa6bb43, 0x42);
    ExpectFileDigest(
        derivedCurrent.c_str(),
        "0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393");
    RS2_CHECK(DeleteFileW(derivedCurrent.c_str()) != FALSE);

    ExpectFileDigest(
        RS2_PR1_BASELINE_PATH,
        "5820F0DA82D7C2903DE31E0865320D9E70A0BF74F78F83C83DB4F9DEEAEB1DEF");
    ExpectFileDigest(
        RS2_CURRENT_STOCK_PATH,
        "F4E38510832D1FAADA8AAD3B88CD2255B3EA49267EF0E874468E23BDE4EDFCC3");
}

bool Contains(const char* text, const char* fragment) {
    return std::strstr(text, fragment) != nullptr;
}

void TestMarker() {
    rs2fix::MarkerData data{};
    data.processId = GetCurrentProcessId();
    data.executableSize = 23994880;
    data.digest = ParseDigest(
        "0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393");
    data.digestValid = true;
    data.buildIdentity = rs2fix::BuildIdentity::CurrentFullDump;
    data.resolverStatus = rs2fix::GenuineResolverStatus::Ok;
    data.initializeResult = rs2fix::kInitOk;
    data.bootstrapBesideExecutable = true;
    data.companionBesideExecutable = true;
    data.complete = true;
    const wchar_t leaf[] = L"VNGame_pr3.exe";
    std::memcpy(data.executableLeaf, leaf, sizeof(leaf));

    char marker[8192]{};
    std::size_t used = 0;
    RS2_CHECK(rs2fix::FormatMarkerUtf8(
        data, marker, sizeof(marker), &used));
    RS2_CHECK(used != 0);
    RS2_CHECK(Contains(marker, "schema=1\r\n"));
    RS2_CHECK(Contains(marker, "executable=VNGame_pr3.exe\r\n"));
    RS2_CHECK(Contains(marker, "build_identity=current-full-dump\r\n"));
    RS2_CHECK(Contains(marker, "resolver_status=ok\r\n"));
    RS2_CHECK(Contains(marker, "genuine_module=system32\r\n"));
    RS2_CHECK(Contains(marker, "bootstrap=faultrep.dll\r\n"));
    RS2_CHECK(Contains(marker, "companion=RS2ServerFix.dll\r\n"));
    RS2_CHECK(Contains(marker, "completion=complete\r\n"));
    RS2_CHECK(!Contains(marker, ":\\"));
    RS2_CHECK(!Contains(marker, "\\Users\\"));
    RS2_CHECK(!Contains(marker, "command_line"));
    RS2_CHECK(!Contains(marker, "environment"));
    RS2_CHECK(!Contains(marker, "network"));
    RS2_CHECK(!Contains(marker, "token"));
    RS2_CHECK(!Contains(marker, "exception"));
    RS2_CHECK(!Contains(marker, "memory"));

    char tooSmall[16]{};
    used = 99;
    RS2_CHECK(!rs2fix::FormatMarkerUtf8(
        data, tooSmall, sizeof(tooSmall), &used));
    RS2_CHECK(used == 0);

    const std::wstring temp = GetTemporaryPath();
    std::wstring missing = temp;
    missing += L"RS2ServerFix-missing-";
    missing += std::to_wstring(GetCurrentProcessId());

    const rs2fix::MarkerWriteResult writeResult =
        rs2fix::WriteMarkerWithFallback(
            missing.c_str(), temp.c_str(), data);
    RS2_CHECK(writeResult.written);
    RS2_CHECK(writeResult.usedFallback);
    RS2_CHECK(writeResult.primaryError != ERROR_SUCCESS);
    RS2_CHECK(GetFileAttributesW(writeResult.writtenPath) !=
              INVALID_FILE_ATTRIBUTES);
    RS2_CHECK(DeleteFileW(writeResult.writtenPath) != FALSE);
}

} // namespace

int main() {
    TestBootstrapAbi();
    TestBuildIdentity();
    TestSha256();
    TestMarker();
    std::cout << "checks=" << rs2fix::test::g_checks
              << " failures=" << rs2fix::test::g_failures << '\n';
    return rs2fix::test::g_failures == 0 ? 0 : 1;
}
