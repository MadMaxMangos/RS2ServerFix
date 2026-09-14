#include "tool_paths.h"
#include <Windows.h>
#include <algorithm>
#include <cwchar>
#include <vector>
namespace rs2fix::tooling {
namespace {
bool Fail(std::string* error, const char* token) {
    if (error) *error = token;
    return false;
}
std::size_t RootLength(const std::wstring& path) {
    if (path.size() >= 3 && path[1] == L':') return 3;
    const auto server = path.find(L'\\', 2);
    if (server == std::wstring::npos) return 0;
    const auto share = path.find(L'\\', server + 1);
    return share == std::wstring::npos ? path.size() : share;
}
bool Normalize(const wchar_t* input, std::wstring* normalized, std::string* error) {
    if (!normalized || !IsAbsoluteToolPath(input)) return Fail(error, "path_not_absolute_plain");
    std::wstring source(input);
    std::replace(source.begin(), source.end(), L'/', L'\\');
    // Do not normalize away a reparse-point component followed by '..'.
    for (std::size_t begin = 0; begin < source.size();) {
        const auto end = source.find(L'\\', begin);
        const auto component = source.substr(begin, end == std::wstring::npos ? end : end - begin);
        if (component == L"." || component == L"..") return Fail(error, "path_dot_component");
        if (!component.empty() && (component.back() == L'.' || component.back() == L' '))
            return Fail(error, "path_ambiguous_component");
        auto device = component.substr(0, component.find(L'.'));
        while (!device.empty() && device.back() == L' ') device.pop_back();
        for (wchar_t& ch : device) if (ch >= L'a' && ch <= L'z') ch = static_cast<wchar_t>(ch - (L'a' - L'A'));
        if (device == L"CON" || device == L"PRN" || device == L"AUX" || device == L"NUL" ||
            device == L"CONIN$" || device == L"CONOUT$" ||
            (device.size() == 4 && (device.substr(0, 3) == L"COM" || device.substr(0, 3) == L"LPT") &&
                ((device[3] >= L'1' && device[3] <= L'9') || device[3] == L'\u00B9' || device[3] == L'\u00B2' || device[3] == L'\u00B3')))
            return Fail(error, "path_reserved_device");
        if (end == std::wstring::npos) break;
        begin = end + 1;
    }
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetFullPathNameW(source.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
    if (length == 0 || length >= buffer.size()) return Fail(error, "path_normalize_failed");
    normalized->assign(buffer.data(), length);
    const auto root = RootLength(*normalized);
    while (normalized->size() > root && normalized->back() == L'\\') normalized->pop_back();
    return true;
}
bool PlainAncestors(std::wstring path, std::string* error) {
    const auto root = RootLength(path);
    if (root == 0) return Fail(error, "path_root_invalid");
    for (;;) {
        const DWORD attrs = GetFileAttributesW(path.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) return Fail(error, "path_missing_or_inaccessible");
        if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) return Fail(error, "path_reparse_point");
        if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) return Fail(error, "path_parent_not_directory");
        if (path.size() <= root) return true;
        const auto slash = path.find_last_of(L'\\');
        path.resize(std::max(root, slash));
    }
}
bool RequireExisting(const wchar_t* input, bool directory, std::wstring* output, std::string* error) {
    if (error) error->clear();
    std::wstring path;
    if (!Normalize(input, &path, error)) return false;
    const DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return Fail(error, "path_missing_or_inaccessible");
    if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) return Fail(error, "path_reparse_point");
    if (((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory) return Fail(error, "path_wrong_type");
    const auto root = RootLength(path);
    const std::wstring parent = directory ? path : path.substr(0, std::max(root, path.find_last_of(L'\\')));
    if (!PlainAncestors(parent, error)) return false;
    if (!output) return Fail(error, "path_null_output");
    *output = std::move(path);
    return true;
}
}
bool IsAbsoluteToolPath(const wchar_t* input) noexcept {
    if (!input) return false;
    const auto size = wcsnlen_s(input, 32768);
    if (size < 3 || size >= 32768) return false;
    for (std::size_t i = 0; i < size; ++i) {
        if (input[i] < L' ' || input[i] == L'"' || input[i] == L'\'' ||
            input[i] == L'*' || input[i] == L'?' || input[i] == L'|' ||
            input[i] == L'<' || input[i] == L'>' || (input[i] == L':' && i != 1)) return false;
    }
    const bool drive = ((input[0] >= L'A' && input[0] <= L'Z') ||
                        (input[0] >= L'a' && input[0] <= L'z')) &&
        input[1] == L':' && (input[2] == L'\\' || input[2] == L'/');
    if (drive) return true;
    if (input[0] != L'\\' || input[1] != L'\\' || input[2] == L'.' || input[2] == L'\\') return false;
    const wchar_t* share = std::wcschr(input + 2, L'\\');
    return share && share[1] != L'\0' && share[1] != L'\\';
}
bool RequireAbsolutePlainFile(const wchar_t* input, std::wstring* normalized, std::string* error) {
    return RequireExisting(input, false, normalized, error);
}
bool RequireAbsolutePlainDirectory(const wchar_t* input, std::wstring* normalized, std::string* error) {
    return RequireExisting(input, true, normalized, error);
}
bool IsPathWithin(const std::wstring& root, const std::wstring& candidate, bool allowRoot) noexcept {
    std::size_t length = root.size();
    while (length > 0 && (root[length - 1] == L'\\' || root[length - 1] == L'/')) --length;
    if (!length || candidate.size() < length ||
        CompareStringOrdinal(root.data(), static_cast<int>(length), candidate.data(), static_cast<int>(length), TRUE) != CSTR_EQUAL) return false;
    if (candidate.size() == length) return allowRoot;
    return candidate[length] == L'\\' || candidate[length] == L'/';
}
bool RequireAbsoluteNewFileOutsideRoot(const wchar_t* input, const std::wstring& forbiddenRoot,
    std::wstring* normalized, std::string* error) {
    if (error) error->clear();
    std::wstring path;
    if (!Normalize(input, &path, error)) return false;
    std::wstring forbidden;
    if (!forbiddenRoot.empty() && !RequireAbsolutePlainDirectory(forbiddenRoot.c_str(), &forbidden, error)) return false;
    if (!forbidden.empty() && IsPathWithin(forbidden, path, true)) return Fail(error, "path_inside_forbidden_root");
    const DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) return Fail(error, "path_output_exists");
    if (GetLastError() != ERROR_FILE_NOT_FOUND) return Fail(error, "path_output_inaccessible");
    const auto root = RootLength(path);
    const auto slash = path.find_last_of(L'\\');
    if (slash == std::wstring::npos || slash + 1 == path.size() ||
        !PlainAncestors(path.substr(0, std::max(root, slash)), error)) return false;
    if (!normalized) return Fail(error, "path_null_output");
    *normalized = std::move(path);
    return true;
}
}
