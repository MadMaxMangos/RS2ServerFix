#include <Windows.h>

#include <cstdint>
#include <cwchar>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr DWORD kChildTimeoutMilliseconds = 20000;
constexpr DWORD kPathCapacity = 32768;

struct ProcessResult {
    bool created{};
    bool timedOut{};
    DWORD createError{};
    DWORD exitCode{STILL_ACTIVE};
    DWORD processId{};
};

bool FullPath(const std::wstring& input, std::wstring* output) {
    wchar_t buffer[kPathCapacity]{};
    const DWORD length = GetFullPathNameW(
        input.c_str(), kPathCapacity, buffer, nullptr);
    if (length == 0 || length >= kPathCapacity) {
        return false;
    }
    output->assign(buffer, length);
    while (output->size() > 3 &&
           (output->back() == L'\\' || output->back() == L'/')) {
        output->pop_back();
    }
    return true;
}

bool IsWithin(
    const std::wstring& root,
    const std::wstring& candidate,
    const bool allowRoot) noexcept {
    if (allowRoot && _wcsicmp(root.c_str(), candidate.c_str()) == 0) {
        return true;
    }
    return candidate.size() > root.size() &&
           _wcsnicmp(
               root.c_str(), candidate.c_str(), root.size()) == 0 &&
           (candidate[root.size()] == L'\\' ||
            candidate[root.size()] == L'/');
}

bool JoinPath(
    const std::wstring& directory,
    const std::wstring_view leaf,
    std::wstring* output) {
    if (directory.empty() || leaf.empty() ||
        leaf.find(L'\\') != std::wstring_view::npos ||
        leaf.find(L'/') != std::wstring_view::npos) {
        return false;
    }
    const bool needsSlash =
        directory.back() != L'\\' && directory.back() != L'/';
    if (directory.size() + (needsSlash ? 1U : 0U) + leaf.size() >=
        kPathCapacity) {
        return false;
    }
    *output = directory;
    if (needsSlash) {
        output->push_back(L'\\');
    }
    output->append(leaf);
    return true;
}

bool ExistingRegularFile(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}

bool CreateNewDirectory(const std::wstring& path) {
    return CreateDirectoryW(path.c_str(), nullptr) != FALSE;
}

bool CopyInto(
    const std::wstring& source,
    const std::wstring& directory,
    const std::wstring_view leaf) {
    std::wstring destination;
    return JoinPath(directory, leaf, &destination) &&
           CopyFileW(source.c_str(), destination.c_str(), TRUE) != FALSE;
}

bool WriteMalformedFile(const std::wstring& path) {
    constexpr char kMalformed[] = "not a portable executable";
    const HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD written = 0;
    const bool writeSucceeded = WriteFile(
        file,
        kMalformed,
        static_cast<DWORD>(sizeof(kMalformed) - 1),
        &written,
        nullptr) != FALSE &&
        written == sizeof(kMalformed) - 1;
    const bool flushSucceeded =
        writeSucceeded && FlushFileBuffers(file) != FALSE;
    const bool closeSucceeded = CloseHandle(file) != FALSE;
    return writeSucceeded && flushSucceeded && closeSucceeded;
}

ProcessResult RunChild(
    const std::wstring& executable,
    const std::wstring& directory,
    const wchar_t* moduleExpectation,
    const wchar_t* markerExpectation) {
    ProcessResult result{};
    if (executable.find(L'"') != std::wstring::npos) {
        result.createError = ERROR_INVALID_NAME;
        return result;
    }

    std::wstring command = L"\"" + executable + L"\" ";
    command += moduleExpectation;
    command.push_back(L' ');
    command += markerExpectation;
    std::vector<wchar_t> mutableCommand(
        command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(
            executable.c_str(),
            mutableCommand.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            directory.c_str(),
            &startup,
            &process)) {
        result.createError = GetLastError();
        return result;
    }

    result.created = true;
    result.processId = process.dwProcessId;
    CloseHandle(process.hThread);
    const DWORD wait = WaitForSingleObject(
        process.hProcess, kChildTimeoutMilliseconds);
    if (wait == WAIT_TIMEOUT) {
        result.timedOut = true;
        TerminateProcess(process.hProcess, ERROR_TIMEOUT);
        WaitForSingleObject(process.hProcess, 5000);
    } else if (wait == WAIT_OBJECT_0) {
        if (!GetExitCodeProcess(process.hProcess, &result.exitCode)) {
            result.exitCode = STILL_ACTIVE;
        }
    } else {
        result.createError = GetLastError();
    }
    CloseHandle(process.hProcess);
    return result;
}

bool ReportHealthyCase(
    const char* name,
    const ProcessResult& result) {
    const bool success = result.created &&
                         !result.timedOut &&
                         result.exitCode == ERROR_SUCCESS;
    std::cout << "case=" << name
              << " created=" << (result.created ? "true" : "false")
              << " timeout=" << (result.timedOut ? "true" : "false")
              << " exit=" << result.exitCode
              << " create_error=" << result.createError
              << " result=" << (success ? "pass" : "fail") << '\n';
    return success;
}

bool ExpectedLoaderCreateError(const DWORD error) noexcept {
    return error == ERROR_BAD_EXE_FORMAT ||
           error == ERROR_MOD_NOT_FOUND ||
           error == ERROR_PROC_NOT_FOUND ||
           error == ERROR_DLL_INIT_FAILED;
}

bool ReportInvalidBootstrapCase(const ProcessResult& result) {
    const bool creationRejected =
        !result.created && ExpectedLoaderCreateError(result.createError);
    const bool loaderExit = result.created &&
        !result.timedOut && result.exitCode >= 0x80000000UL;
    const bool success = creationRejected || loaderExit;
    std::cout << "case=invalid-bootstrap"
              << " created=" << (result.created ? "true" : "false")
              << " timeout=" << (result.timedOut ? "true" : "false")
              << " exit=" << result.exitCode
              << " create_error=" << result.createError
              << " result=" << (success ? "pass" : "fail") << '\n';
    return success;
}

bool SafePath(
    const std::wstring& root,
    const std::wstring& candidate,
    const bool allowRoot) {
    std::wstring absolute;
    return FullPath(candidate, &absolute) &&
           IsWithin(root, absolute, allowRoot);
}

bool RemoveTreeContents(
    const std::wstring& root,
    const std::wstring& directory) {
    if (!SafePath(root, directory, true)) {
        return false;
    }
    const DWORD rootAttributes = GetFileAttributesW(directory.c_str());
    if (rootAttributes == INVALID_FILE_ATTRIBUTES) {
        return GetLastError() == ERROR_FILE_NOT_FOUND ||
               GetLastError() == ERROR_PATH_NOT_FOUND;
    }
    if ((rootAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (rootAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return false;
    }

    std::wstring pattern = directory + L"\\*";
    WIN32_FIND_DATAW data{};
    const HANDLE find = FindFirstFileW(pattern.c_str(), &data);
    if (find != INVALID_HANDLE_VALUE) {
        bool success = true;
        do {
            if (std::wcscmp(data.cFileName, L".") == 0 ||
                std::wcscmp(data.cFileName, L"..") == 0) {
                continue;
            }
            std::wstring child;
            if (!JoinPath(directory, data.cFileName, &child) ||
                !SafePath(root, child, false)) {
                success = false;
                break;
            }
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                if ((data.dwFileAttributes &
                     FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                    if (!RemoveDirectoryW(child.c_str())) {
                        success = false;
                        break;
                    }
                } else if (!RemoveTreeContents(root, child)) {
                    success = false;
                    break;
                }
            } else {
                if ((data.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0) {
                    SetFileAttributesW(child.c_str(), FILE_ATTRIBUTE_NORMAL);
                }
                if (!DeleteFileW(child.c_str())) {
                    success = false;
                    break;
                }
            }
        } while (FindNextFileW(find, &data));
        const DWORD findError = GetLastError();
        FindClose(find);
        if (findError != ERROR_NO_MORE_FILES) {
            success = false;
        }
        if (!success) {
            return false;
        }
    } else {
        const DWORD findError = GetLastError();
        if (findError != ERROR_FILE_NOT_FOUND) {
            return false;
        }
    }

    SetFileAttributesW(directory.c_str(), FILE_ATTRIBUTE_NORMAL);
    return RemoveDirectoryW(directory.c_str()) != FALSE;
}

bool IsValidatedUniqueRoot(const std::wstring& root) {
    wchar_t temporary[kPathCapacity]{};
    const DWORD length = GetTempPathW(kPathCapacity, temporary);
    if (length == 0 || length >= kPathCapacity) {
        return false;
    }
    std::wstring absoluteTemporary;
    if (!FullPath(temporary, &absoluteTemporary) ||
        !IsWithin(absoluteTemporary, root, false)) {
        return false;
    }
    const std::size_t leafOffset = absoluteTemporary.size() + 1;
    const std::wstring_view leaf(root.c_str() + leafOffset);
    return leaf.find(L'\\') == std::wstring_view::npos &&
           leaf.find(L'/') == std::wstring_view::npos &&
           leaf.rfind(L"RS2ServerFix.static.", 0) == 0;
}

bool PrepareCase(
    const std::wstring& root,
    const wchar_t* leaf,
    const std::wstring& harness,
    std::wstring* directory,
    std::wstring* executable) {
    return JoinPath(root, leaf, directory) &&
           CreateNewDirectory(*directory) &&
           CopyInto(harness, *directory, L"rs2_static_import_harness.exe") &&
           JoinPath(
               *directory,
               L"rs2_static_import_harness.exe",
               executable);
}

bool RemoveCaseFile(
    const std::wstring& root,
    const std::wstring& directory,
    const std::wstring_view leaf) {
    std::wstring path;
    if (!JoinPath(directory, leaf, &path) ||
        !SafePath(root, path, false)) {
        return false;
    }
    if (DeleteFileW(path.c_str()) == FALSE) {
        return false;
    }
    return GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES;
}

void RemoveMarkerIfPresent(
    const std::wstring& root,
    const std::wstring& directory,
    const DWORD processId) {
    if (processId == 0) {
        return;
    }
    wchar_t leaf[64]{};
    if (swprintf_s(
            leaf,
            L"RS2ServerFix.loader.%lu.log",
            static_cast<unsigned long>(processId)) <= 0) {
        return;
    }
    std::wstring path;
    if (JoinPath(directory, leaf, &path) &&
        SafePath(root, path, false)) {
        DeleteFileW(path.c_str());
    }
}

} // namespace

int wmain(const int argumentCount, wchar_t** arguments) {
    if (argumentCount != 4 || arguments == nullptr) {
        std::cerr << "usage: runner <harness> <bootstrap> <companion>\n";
        return 2;
    }

    std::wstring harness;
    std::wstring bootstrap;
    std::wstring companion;
    if (!FullPath(arguments[1], &harness) ||
        !FullPath(arguments[2], &bootstrap) ||
        !FullPath(arguments[3], &companion) ||
        !ExistingRegularFile(harness) ||
        !ExistingRegularFile(bootstrap) ||
        !ExistingRegularFile(companion)) {
        std::cerr << "FAIL\tinput artifact validation failed\n";
        return 2;
    }

    wchar_t temporary[kPathCapacity]{};
    const DWORD temporaryLength = GetTempPathW(
        kPathCapacity, temporary);
    if (temporaryLength == 0 || temporaryLength >= kPathCapacity) {
        std::cerr << "FAIL\ttemporary path unavailable\n";
        return 1;
    }
    std::wstring temporaryRoot;
    if (!FullPath(temporary, &temporaryRoot)) {
        std::cerr << "FAIL\ttemporary path normalization failed\n";
        return 1;
    }
    const std::wstring uniqueLeaf =
        L"RS2ServerFix.static." +
        std::to_wstring(GetCurrentProcessId()) + L"." +
        std::to_wstring(GetTickCount64());
    std::wstring proposedRoot;
    std::wstring root;
    if (!JoinPath(temporaryRoot, uniqueLeaf, &proposedRoot) ||
        !FullPath(proposedRoot, &root) ||
        !IsValidatedUniqueRoot(root) ||
        !CreateNewDirectory(root)) {
        std::cerr << "FAIL\tunique temporary root creation failed\n";
        return 1;
    }

    const UINT previousErrorMode = SetErrorMode(
        SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    bool allPassed = true;

    std::wstring directory;
    std::wstring executable;
    bool prepared = PrepareCase(
        root, L"01-system-control", harness, &directory, &executable);
    ProcessResult result{};
    if (prepared) {
        result = RunChild(
            executable,
            directory,
            L"--expect-system",
            L"--forbid-marker");
    }
    allPassed = (prepared &&
        ReportHealthyCase("system-control", result)) && allPassed;

    prepared = PrepareCase(
        root, L"02-companion-only", harness, &directory, &executable) &&
        CopyInto(companion, directory, L"RS2ServerFix.dll");
    result = {};
    if (prepared) {
        result = RunChild(
            executable,
            directory,
            L"--expect-system",
            L"--forbid-marker");
    }
    allPassed = (prepared &&
        ReportHealthyCase("companion-only", result)) && allPassed;

    prepared = PrepareCase(
        root, L"03-bootstrap-only", harness, &directory, &executable) &&
        CopyInto(bootstrap, directory, L"faultrep.dll");
    result = {};
    if (prepared) {
        result = RunChild(
            executable,
            directory,
            L"--expect-bootstrap",
            L"--forbid-marker");
    }
    allPassed = (prepared &&
        ReportHealthyCase("bootstrap-only", result)) && allPassed;

    std::wstring bothDirectory;
    std::wstring bothExecutable;
    const bool bothPrepared = PrepareCase(
        root, L"04-both", harness, &bothDirectory, &bothExecutable) &&
        CopyInto(bootstrap, bothDirectory, L"faultrep.dll") &&
        CopyInto(companion, bothDirectory, L"RS2ServerFix.dll");
    ProcessResult bothResult{};
    if (bothPrepared) {
        bothResult = RunChild(
            bothExecutable,
            bothDirectory,
            L"--expect-bootstrap",
            L"--expect-marker");
    }
    allPassed = (bothPrepared &&
        ReportHealthyCase("both", bothResult)) && allPassed;

    prepared = PrepareCase(
        root, L"05-invalid-companion", harness, &directory, &executable) &&
        CopyInto(bootstrap, directory, L"faultrep.dll");
    std::wstring invalidCompanion;
    prepared = prepared &&
        JoinPath(directory, L"RS2ServerFix.dll", &invalidCompanion) &&
        WriteMalformedFile(invalidCompanion);
    result = {};
    if (prepared) {
        result = RunChild(
            executable,
            directory,
            L"--expect-bootstrap",
            L"--forbid-marker");
    }
    allPassed = (prepared &&
        ReportHealthyCase("invalid-companion", result)) && allPassed;

    prepared = PrepareCase(
        root, L"06-invalid-bootstrap", harness, &directory, &executable);
    std::wstring invalidBootstrap;
    prepared = prepared &&
        JoinPath(directory, L"faultrep.dll", &invalidBootstrap) &&
        WriteMalformedFile(invalidBootstrap);
    result = {};
    if (prepared) {
        result = RunChild(
            executable,
            directory,
            L"--expect-bootstrap",
            L"--forbid-marker");
    }
    allPassed = (prepared &&
        ReportInvalidBootstrapCase(result)) && allPassed;

    RemoveMarkerIfPresent(
        root, bothDirectory, bothResult.processId);
    const bool rollbackPrepared = bothPrepared &&
        RemoveCaseFile(root, bothDirectory, L"faultrep.dll") &&
        RemoveCaseFile(root, bothDirectory, L"RS2ServerFix.dll");
    result = {};
    if (rollbackPrepared) {
        result = RunChild(
            bothExecutable,
            bothDirectory,
            L"--expect-system",
            L"--forbid-marker");
    }
    allPassed = (rollbackPrepared &&
        ReportHealthyCase("rollback", result)) && allPassed;

    SetErrorMode(previousErrorMode);
    const bool cleaned =
        IsValidatedUniqueRoot(root) && RemoveTreeContents(root, root);
    if (!cleaned) {
        std::wcerr << L"FAIL\ttemporary cleanup failed: "
                   << root << L'\n';
        allPassed = false;
    }

    std::cout << "static_import_cases="
              << (allPassed ? "pass" : "fail") << '\n';
    return allPassed ? 0 : 1;
}
