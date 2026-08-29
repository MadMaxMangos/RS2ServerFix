#include "pe_reader.h"

#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace {

constexpr DWORD kPathCapacity = 32768;

struct ScanState {
    std::wstring root;
    std::size_t peFiles{};
    std::size_t faultrepImporters{};
    std::size_t unsafeFindings{};
};

std::string LowerAscii(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value;
}

std::string Sanitize(std::string value) {
    for (char& character : value) {
        if (character == '\t' || character == '\r' ||
            character == '\n') {
            character = '_';
        }
    }
    return value;
}

std::string Utf8(const std::wstring_view text) {
    if (text.empty()) {
        return {};
    }
    const int length = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        text.data(),
        static_cast<int>(text.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (length <= 0) {
        return "<invalid-unicode-path>";
    }
    std::string result(static_cast<std::size_t>(length), '\0');
    if (WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            result.data(),
            length,
            nullptr,
            nullptr) != length) {
        return "<invalid-unicode-path>";
    }
    return Sanitize(std::move(result));
}

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

bool IsWithinRoot(
    const std::wstring& root,
    const std::wstring& candidate) noexcept {
    return candidate.size() > root.size() &&
           _wcsnicmp(
               root.c_str(), candidate.c_str(), root.size()) == 0 &&
           (candidate[root.size()] == L'\\' ||
            candidate[root.size()] == L'/');
}

bool JoinPath(
    const std::wstring& directory,
    const wchar_t* leaf,
    std::wstring* output) {
    if (directory.empty() || leaf == nullptr || leaf[0] == L'\0' ||
        std::wcschr(leaf, L'\\') != nullptr ||
        std::wcschr(leaf, L'/') != nullptr) {
        return false;
    }
    const std::size_t leafLength = std::wcslen(leaf);
    const bool needsSlash =
        directory.back() != L'\\' && directory.back() != L'/';
    if (directory.size() + (needsSlash ? 1U : 0U) + leafLength >=
        kPathCapacity) {
        return false;
    }
    *output = directory;
    if (needsSlash) {
        output->push_back(L'\\');
    }
    output->append(leaf, leafLength);
    return true;
}

std::wstring RelativePath(
    const std::wstring& root,
    const std::wstring& path) {
    if (_wcsicmp(root.c_str(), path.c_str()) == 0) {
        return L".";
    }
    if (!IsWithinRoot(root, path)) {
        return L"<outside-root>";
    }
    return path.substr(root.size() + 1);
}

bool EndsWithInsensitive(
    const std::wstring_view value,
    const std::wstring_view suffix) noexcept {
    if (value.size() < suffix.size()) {
        return false;
    }
    const wchar_t* tail = value.data() + value.size() - suffix.size();
    return CompareStringOrdinal(
               tail,
               static_cast<int>(suffix.size()),
               suffix.data(),
               static_cast<int>(suffix.size()),
               TRUE) == CSTR_EQUAL;
}

bool IsPeExtension(const std::wstring_view name) noexcept {
    return EndsWithInsensitive(name, L".exe") ||
           EndsWithInsensitive(name, L".dll");
}

std::string MachineName(const std::uint16_t machine) {
    switch (machine) {
    case IMAGE_FILE_MACHINE_AMD64:
        return "AMD64";
    case IMAGE_FILE_MACHINE_I386:
        return "I386";
    case IMAGE_FILE_MACHINE_ARM64:
        return "ARM64";
    default:
        break;
    }
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase << machine;
    return stream.str();
}

void Emit(
    const char* kind,
    const std::wstring& relativePath,
    const std::string& machine,
    const std::string& detail) {
    std::cout << kind << '\t'
              << Utf8(relativePath) << '\t'
              << machine << '\t'
              << Sanitize(detail) << '\n';
}

void Unsafe(
    ScanState* state,
    const std::wstring& relativePath,
    const std::string& machine,
    const std::string& reason) {
    ++state->unsafeFindings;
    Emit("UNSAFE", relativePath, machine, reason);
}

bool ScanPeFile(
    const std::wstring& path,
    const std::wstring& relativePath,
    ScanState* state) {
    rs2fix::pe::Image image{};
    std::string error;
    if (!rs2fix::pe::ReadPeImage(path.c_str(), &image, &error)) {
        Unsafe(
            state,
            relativePath,
            "-",
            "malformed-pe:" + error);
        return true;
    }

    ++state->peFiles;
    const std::string machine = MachineName(image.machine);
    Emit("PE", relativePath, machine, "parsed");

    bool importsFaultrep = false;
    bool machineReported = false;
    for (const rs2fix::pe::ImportModule& module : image.imports) {
        if (LowerAscii(module.name) != "faultrep.dll") {
            continue;
        }
        importsFaultrep = true;
        if (!machineReported &&
            image.machine != IMAGE_FILE_MACHINE_AMD64) {
            Unsafe(
                state,
                relativePath,
                machine,
                "non-amd64-faultrep-importer");
            machineReported = true;
        }
        if (module.symbols.empty()) {
            Unsafe(
                state,
                relativePath,
                machine,
                "empty-faultrep-import-table");
        }
        for (const rs2fix::pe::ImportSymbol& symbol : module.symbols) {
            if (symbol.byOrdinal) {
                Emit(
                    "IMPORT",
                    relativePath,
                    machine,
                    "faultrep.dll!#" +
                        std::to_string(symbol.ordinal));
                Unsafe(
                    state,
                    relativePath,
                    machine,
                    "ordinal-faultrep-import");
            } else {
                Emit(
                    "IMPORT",
                    relativePath,
                    machine,
                    "faultrep.dll!" + symbol.name);
                if (symbol.name != "ReportFault") {
                    Unsafe(
                        state,
                        relativePath,
                        machine,
                        "unexpected-faultrep-import-name:" +
                            symbol.name);
                }
            }
        }
    }
    if (importsFaultrep) {
        ++state->faultrepImporters;
    }
    return true;
}

bool ScanDirectory(
    const std::wstring& directory,
    ScanState* state) {
    if (directory != state->root &&
        !IsWithinRoot(state->root, directory)) {
        Unsafe(state, L"<outside-root>", "-", "path-escaped-root");
        return false;
    }

    std::wstring pattern = directory + L"\\*";
    WIN32_FIND_DATAW data{};
    const HANDLE find = FindFirstFileW(pattern.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) {
            return true;
        }
        Unsafe(
            state,
            RelativePath(state->root, directory),
            "-",
            "enumeration-failed:" + std::to_string(error));
        return false;
    }

    bool completed = true;
    do {
        if (std::wcscmp(data.cFileName, L".") == 0 ||
            std::wcscmp(data.cFileName, L"..") == 0) {
            continue;
        }
        std::wstring path;
        if (!JoinPath(directory, data.cFileName, &path) ||
            !IsWithinRoot(state->root, path)) {
            Unsafe(state, L"<outside-root>", "-", "path-escaped-root");
            completed = false;
            continue;
        }
        const std::wstring relative = RelativePath(state->root, path);
        const std::wstring_view name(data.cFileName);

        if (EndsWithInsensitive(name, L".exe.local")) {
            Unsafe(
                state,
                relative,
                "-",
                "executable-local-redirection");
        }

        const bool directoryEntry =
            (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        const bool reparsePoint =
            (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        if (directoryEntry) {
            if (reparsePoint) {
                Emit("SKIP", relative, "-", "directory-reparse-point");
            } else if (!ScanDirectory(path, state)) {
                completed = false;
            }
            continue;
        }

        if (!IsPeExtension(name)) {
            continue;
        }
        if (reparsePoint) {
            Unsafe(
                state,
                relative,
                "-",
                "reparse-pe-not-scanned");
            continue;
        }
        if (!ScanPeFile(path, relative, state)) {
            completed = false;
        }
    } while (FindNextFileW(find, &data));

    const DWORD findError = GetLastError();
    FindClose(find);
    if (findError != ERROR_NO_MORE_FILES) {
        Unsafe(
            state,
            RelativePath(state->root, directory),
            "-",
            "enumeration-failed:" + std::to_string(findError));
        completed = false;
    }
    return completed;
}

} // namespace

int wmain(const int argumentCount, wchar_t** arguments) {
    if (argumentCount != 2 || arguments == nullptr) {
        std::cerr << "usage: rs2_deployment_preflight <selected-root>\n";
        return 2;
    }

    std::wstring root;
    if (!FullPath(arguments[1], &root)) {
        std::cerr << "UNSAFE\t.\t-\troot-normalization-failed\n";
        return 2;
    }
    const DWORD attributes = GetFileAttributesW(root.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        std::cerr << "UNSAFE\t.\t-\troot-is-not-a-plain-directory\n";
        return 2;
    }

    std::cout << "kind\tpath\tmachine\tdetail\n";
    ScanState state{};
    state.root = root;
    const bool complete = ScanDirectory(root, &state);
    if (!complete && state.unsafeFindings == 0) {
        Unsafe(&state, L".", "-", "scan-incomplete");
    }
    const bool passed = complete && state.unsafeFindings == 0;
    std::cout << "SUMMARY\t.\t-\tpe_files=" << state.peFiles
              << ";faultrep_importers=" << state.faultrepImporters
              << ";unsafe=" << state.unsafeFindings
              << ";result=" << (passed ? "pass" : "unsafe")
              << '\n';
    return passed ? 0 : 1;
}
