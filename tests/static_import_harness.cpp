#include "shared/path_identity.h"

#include <Windows.h>
#include <ErrorRep.h>

#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>

volatile auto g_reportFaultImportAnchor = &ReportFault;

namespace {

bool Fail(const char* message) {
    std::cerr << "FAIL\t" << message << '\n';
    return false;
}

bool OwnDirectory(wchar_t* directory) {
    wchar_t path[rs2fix::kPathCapacity]{};
    wchar_t leaf[260]{};
    DWORD error = ERROR_SUCCESS;
    return rs2fix::GetBoundedModulePath(
               nullptr,
               path,
               rs2fix::kPathCapacity,
               &error) &&
           rs2fix::ExtractDirectoryAndLeaf(
               path,
               directory,
               rs2fix::kPathCapacity,
               leaf,
               260,
               &error);
}

bool BuildMarkerPath(wchar_t* markerPath) {
    wchar_t directory[rs2fix::kPathCapacity]{};
    if (!OwnDirectory(directory)) {
        return false;
    }
    wchar_t leaf[64]{};
    if (swprintf_s(
            leaf,
            L"RS2ServerFix.loader.%lu.log",
            static_cast<unsigned long>(GetCurrentProcessId())) <= 0) {
        return false;
    }
    DWORD error = ERROR_SUCCESS;
    return rs2fix::AppendPathLeaf(
        directory,
        leaf,
        markerPath,
        rs2fix::kPathCapacity,
        &error);
}

bool ReadMarker(const wchar_t* path, std::string* text) {
    const HANDLE file = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) ||
        size.QuadPart <= 0 || size.QuadPart >= 8192) {
        CloseHandle(file);
        return false;
    }
    char buffer[8192]{};
    DWORD read = 0;
    const bool readSucceeded = ReadFile(
        file,
        buffer,
        static_cast<DWORD>(size.QuadPart),
        &read,
        nullptr) != FALSE &&
        read == static_cast<DWORD>(size.QuadPart);
    const bool closeSucceeded = CloseHandle(file) != FALSE;
    if (!readSucceeded || !closeSucceeded) {
        return false;
    }
    text->assign(buffer, read);
    return true;
}

bool ContainsLine(
    const std::string& text,
    const std::string_view line) {
    return text.find(line) != std::string::npos;
}

bool ValidateCompleteMarker(const wchar_t* markerPath) {
    const ULONGLONG deadline = GetTickCount64() + 15000;
    std::string marker;
    const std::string terminal = "completion=complete\r\n";
    while (GetTickCount64() < deadline) {
        marker.clear();
        if (ReadMarker(markerPath, &marker) &&
            marker.size() >= terminal.size() &&
            marker.compare(
                marker.size() - terminal.size(),
                terminal.size(),
                terminal) == 0) {
            break;
        }
        Sleep(10);
    }

    const std::string pid = "pid=" +
        std::to_string(GetCurrentProcessId()) + "\r\n";
    return (!marker.empty() || Fail("complete marker was not written")) &&
           (ContainsLine(marker, "schema=1\r\n") ||
            Fail("marker schema mismatch")) &&
           (ContainsLine(marker, pid) || Fail("marker PID mismatch")) &&
           (ContainsLine(
                marker,
                "bootstrap_beside_executable=true\r\n") ||
            Fail("bootstrap location evidence mismatch")) &&
           (ContainsLine(
                marker,
                "companion_beside_executable=true\r\n") ||
            Fail("companion location evidence mismatch")) &&
           (ContainsLine(marker, "resolver_status=ok\r\n") ||
            Fail("genuine resolver did not succeed")) &&
           (ContainsLine(marker, "genuine_module=system32\r\n") ||
            Fail("genuine module evidence mismatch")) &&
           (ContainsLine(marker, "initialize_result=0\r\n") ||
            Fail("companion initialization failed")) &&
           (marker.size() >= terminal.size() &&
            marker.compare(
                marker.size() - terminal.size(),
                terminal.size(),
                terminal) == 0 ||
            Fail("marker completion is not terminal"));
}

bool ValidateNoMarker(const wchar_t* markerPath) {
    const ULONGLONG deadline = GetTickCount64() + 2000;
    while (GetTickCount64() < deadline) {
        if (GetFileAttributesW(markerPath) != INVALID_FILE_ATTRIBUTES) {
            return Fail("marker unexpectedly exists");
        }
        Sleep(10);
    }
    return GetFileAttributesW(markerPath) == INVALID_FILE_ATTRIBUTES ||
           Fail("marker unexpectedly exists");
}

bool ValidateFaultrepIdentity(const bool expectSystem) {
    const HMODULE loaded = GetModuleHandleW(L"faultrep.dll");
    if (loaded == nullptr) {
        return Fail("faultrep.dll is not loaded");
    }

    wchar_t loadedPath[rs2fix::kPathCapacity]{};
    wchar_t expectedPath[rs2fix::kPathCapacity]{};
    DWORD error = ERROR_SUCCESS;
    if (!rs2fix::GetBoundedModulePath(
            loaded,
            loadedPath,
            rs2fix::kPathCapacity,
            &error)) {
        return Fail("loaded faultrep path is unavailable");
    }
    if (expectSystem) {
        if (!rs2fix::BuildSystemFaultrepPath(
                expectedPath,
                rs2fix::kPathCapacity,
                &error)) {
            return Fail("System32 faultrep path is unavailable");
        }
    } else {
        wchar_t directory[rs2fix::kPathCapacity]{};
        if (!OwnDirectory(directory) ||
            !rs2fix::AppendPathLeaf(
                directory,
                L"faultrep.dll",
                expectedPath,
                rs2fix::kPathCapacity,
                &error)) {
            return Fail("local faultrep path is unavailable");
        }
    }

    rs2fix::FileIdentity loadedIdentity{};
    rs2fix::FileIdentity expectedIdentity{};
    if (!rs2fix::QueryFileIdentity(
            loadedPath, &loadedIdentity, &error) ||
        !rs2fix::QueryFileIdentity(
            expectedPath, &expectedIdentity, &error)) {
        return Fail("faultrep file identity is unavailable");
    }
    return rs2fix::SameFileIdentity(
               loadedIdentity, expectedIdentity) ||
           Fail("wrong faultrep module was selected");
}

} // namespace

int wmain(const int argumentCount, wchar_t** arguments) {
    if (argumentCount != 3 || arguments == nullptr) {
        std::cerr << "usage: harness <--expect-system|--expect-bootstrap> "
                     "<--expect-marker|--forbid-marker>\n";
        return 2;
    }
    if (g_reportFaultImportAnchor == nullptr) {
        std::cerr << "FAIL\tReportFault import anchor is null\n";
        return 1;
    }

    const std::wstring_view moduleExpectation(arguments[1]);
    const std::wstring_view markerExpectation(arguments[2]);
    const bool expectSystem = moduleExpectation == L"--expect-system";
    const bool expectBootstrap =
        moduleExpectation == L"--expect-bootstrap";
    const bool expectMarker = markerExpectation == L"--expect-marker";
    const bool forbidMarker = markerExpectation == L"--forbid-marker";
    if ((!expectSystem && !expectBootstrap) ||
        (!expectMarker && !forbidMarker)) {
        std::cerr << "FAIL\tinvalid expectation\n";
        return 2;
    }

    wchar_t markerPath[rs2fix::kPathCapacity]{};
    if (!BuildMarkerPath(markerPath)) {
        std::cerr << "FAIL\tmarker path is unavailable\n";
        return 1;
    }

    const bool moduleValid = ValidateFaultrepIdentity(expectSystem);
    const bool markerValid = expectMarker
        ? ValidateCompleteMarker(markerPath)
        : ValidateNoMarker(markerPath);
    if (!moduleValid || !markerValid) {
        return 1;
    }
    std::cout << "harness=pass\n";
    return 0;
}
