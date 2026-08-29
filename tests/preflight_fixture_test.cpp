#include <Windows.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr DWORD kPathCapacity = 32768;
int g_checks = 0;
int g_failures = 0;

void Check(
    const bool condition,
    const char* expression,
    const int line) {
    ++g_checks;
    if (!condition) {
        ++g_failures;
        std::cerr << "line=" << line
                  << " CHECK failed: " << expression << '\n';
    }
}

#define PREFLIGHT_CHECK(expression) \
    Check(static_cast<bool>(expression), #expression, __LINE__)

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

bool BuildTemporaryRoot(std::wstring* root) {
    wchar_t temporary[kPathCapacity]{};
    const DWORD temporaryLength = GetTempPathW(
        kPathCapacity, temporary);
    if (temporaryLength == 0 || temporaryLength >= kPathCapacity) {
        return false;
    }
    wchar_t generated[kPathCapacity]{};
    if (GetTempFileNameW(temporary, L"R2P", 0, generated) == 0 ||
        !DeleteFileW(generated) ||
        !CreateDirectoryW(generated, nullptr)) {
        return false;
    }
    *root = generated;
    return true;
}

bool WriteTruncatedFile(const std::wstring& path) {
    constexpr char kBytes[] = "MZ truncated";
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
        kBytes,
        static_cast<DWORD>(sizeof(kBytes) - 1),
        &written,
        nullptr) != FALSE &&
        written == sizeof(kBytes) - 1;
    const bool closeSucceeded = CloseHandle(file) != FALSE;
    return writeSucceeded && closeSucceeded;
}

bool ReadAt(HANDLE file, const std::uint64_t offset, void* data, DWORD size) {
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    DWORD read = 0;
    return SetFilePointerEx(file, position, nullptr, FILE_BEGIN) != FALSE &&
           ReadFile(file, data, size, &read, nullptr) != FALSE &&
           read == size;
}

bool WriteAt(
    HANDLE file,
    const std::uint64_t offset,
    const void* data,
    DWORD size) {
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    DWORD written = 0;
    return SetFilePointerEx(file, position, nullptr, FILE_BEGIN) != FALSE &&
           WriteFile(file, data, size, &written, nullptr) != FALSE &&
           written == size;
}

bool ChangeMachineToI386(const std::wstring& path) {
    const HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    IMAGE_DOS_HEADER dos{};
    DWORD signature = 0;
    WORD originalMachine = 0;
    const std::uint64_t signatureOffset =
        static_cast<std::uint64_t>(dos.e_lfanew);
    bool success = ReadAt(file, 0, &dos, sizeof(dos)) &&
                   dos.e_magic == IMAGE_DOS_SIGNATURE;
    const std::uint64_t ntOffset = success
        ? static_cast<std::uint64_t>(dos.e_lfanew)
        : signatureOffset;
    success = success && ReadAt(
        file, ntOffset, &signature, sizeof(signature)) &&
        signature == IMAGE_NT_SIGNATURE &&
        ReadAt(
            file,
            ntOffset + sizeof(signature),
            &originalMachine,
            sizeof(originalMachine)) &&
        originalMachine == IMAGE_FILE_MACHINE_AMD64;
    const WORD replacement = IMAGE_FILE_MACHINE_I386;
    success = success && WriteAt(
        file,
        ntOffset + sizeof(signature),
        &replacement,
        sizeof(replacement)) &&
        FlushFileBuffers(file) != FALSE;
    const bool closeSucceeded = CloseHandle(file) != FALSE;
    return success && closeSucceeded;
}

bool ReadTextFile(const std::wstring& path, std::string* text) {
    const HANDLE file = CreateFileW(
        path.c_str(),
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
        size.QuadPart < 0 || size.QuadPart > 1024 * 1024) {
        CloseHandle(file);
        return false;
    }
    std::vector<char> bytes(
        static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    const bool readSucceeded = bytes.empty() ||
        (ReadFile(
             file,
             bytes.data(),
             static_cast<DWORD>(bytes.size()),
             &read,
             nullptr) != FALSE &&
         read == bytes.size());
    const bool closeSucceeded = CloseHandle(file) != FALSE;
    if (!readSucceeded || !closeSucceeded) {
        return false;
    }
    text->assign(bytes.begin(), bytes.end());
    return true;
}

bool RunScanner(
    const std::wstring& scanner,
    const std::wstring& root,
    const std::wstring& outputPath,
    DWORD* exitCode,
    std::string* output) {
    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    const HANDLE outputFile = CreateFileW(
        outputPath.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        &security,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    const HANDLE input = CreateFileW(
        L"NUL",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        &security,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (outputFile == INVALID_HANDLE_VALUE ||
        input == INVALID_HANDLE_VALUE) {
        if (outputFile != INVALID_HANDLE_VALUE) {
            CloseHandle(outputFile);
        }
        if (input != INVALID_HANDLE_VALUE) {
            CloseHandle(input);
        }
        return false;
    }

    std::wstring command = L"\"" + scanner + L"\" \"" + root + L"\"";
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input;
    startup.hStdOutput = outputFile;
    startup.hStdError = outputFile;
    PROCESS_INFORMATION process{};
    const bool created = CreateProcessW(
        scanner.c_str(),
        mutableCommand.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        root.c_str(),
        &startup,
        &process) != FALSE;
    CloseHandle(input);
    CloseHandle(outputFile);
    if (!created) {
        return false;
    }

    CloseHandle(process.hThread);
    const DWORD wait = WaitForSingleObject(process.hProcess, 20000);
    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(process.hProcess, ERROR_TIMEOUT);
        WaitForSingleObject(process.hProcess, 5000);
    }
    const bool exited = wait == WAIT_OBJECT_0 &&
        GetExitCodeProcess(process.hProcess, exitCode) != FALSE;
    CloseHandle(process.hProcess);
    return exited && ReadTextFile(outputPath, output);
}

bool Contains(
    const std::string& text,
    const std::string_view expected) {
    return text.find(expected) != std::string::npos;
}

void Cleanup(
    const std::wstring& root,
    const std::wstring& safe,
    const std::wstring& unsafe,
    const std::wstring& broken,
    const std::wstring& redirection,
    const std::wstring& output) {
    DeleteFileW(output.c_str());
    DeleteFileW(broken.c_str());
    DeleteFileW(unsafe.c_str());
    DeleteFileW(safe.c_str());
    RemoveDirectoryW(redirection.c_str());
    RemoveDirectoryW(root.c_str());
}

} // namespace

int wmain(const int argumentCount, wchar_t** arguments) {
    if (argumentCount != 3 || arguments == nullptr) {
        std::cerr << "usage: fixture-test <scanner> <named-import-harness>\n";
        return 2;
    }

    const std::wstring scanner(arguments[1]);
    const std::wstring harness(arguments[2]);
    std::wstring root;
    PREFLIGHT_CHECK(BuildTemporaryRoot(&root));
    if (root.empty()) {
        return 1;
    }

    std::wstring safe;
    std::wstring unsafe;
    std::wstring broken;
    std::wstring redirection;
    std::wstring outputPath;
    PREFLIGHT_CHECK(JoinPath(root, L"safe-importer.exe", &safe));
    PREFLIGHT_CHECK(JoinPath(root, L"non-amd64-importer.exe", &unsafe));
    PREFLIGHT_CHECK(JoinPath(root, L"broken.dll", &broken));
    PREFLIGHT_CHECK(JoinPath(root, L"redirect.exe.local", &redirection));
    PREFLIGHT_CHECK(JoinPath(root, L"scanner-output.txt", &outputPath));

    PREFLIGHT_CHECK(CopyFileW(harness.c_str(), safe.c_str(), TRUE) != FALSE);
    PREFLIGHT_CHECK(CopyFileW(harness.c_str(), unsafe.c_str(), TRUE) != FALSE);
    PREFLIGHT_CHECK(ChangeMachineToI386(unsafe));
    PREFLIGHT_CHECK(WriteTruncatedFile(broken));
    PREFLIGHT_CHECK(CreateDirectoryW(redirection.c_str(), nullptr) != FALSE);

    DWORD exitCode = 0;
    std::string output;
    PREFLIGHT_CHECK(RunScanner(
        scanner, root, outputPath, &exitCode, &output));
    PREFLIGHT_CHECK(exitCode != 0);
    PREFLIGHT_CHECK(Contains(
        output, "non-amd64-faultrep-importer"));
    PREFLIGHT_CHECK(Contains(
        output, "executable-local-redirection"));
    PREFLIGHT_CHECK(Contains(output, "malformed-pe"));

    PREFLIGHT_CHECK(DeleteFileW(unsafe.c_str()) != FALSE);
    PREFLIGHT_CHECK(DeleteFileW(broken.c_str()) != FALSE);
    PREFLIGHT_CHECK(RemoveDirectoryW(redirection.c_str()) != FALSE);

    exitCode = 1;
    output.clear();
    PREFLIGHT_CHECK(RunScanner(
        scanner, root, outputPath, &exitCode, &output));
    PREFLIGHT_CHECK(exitCode == 0);
    PREFLIGHT_CHECK(Contains(output, "safe-importer.exe"));
    PREFLIGHT_CHECK(Contains(output, "AMD64"));
    PREFLIGHT_CHECK(Contains(output, "faultrep.dll!ReportFault"));
    PREFLIGHT_CHECK(Contains(output, "result=pass"));

    Cleanup(
        root, safe, unsafe, broken, redirection, outputPath);
    PREFLIGHT_CHECK(
        GetFileAttributesW(root.c_str()) == INVALID_FILE_ATTRIBUTES);
    std::cout << "checks=" << g_checks
              << " failures=" << g_failures << '\n';
    return g_failures == 0 ? 0 : 1;
}
