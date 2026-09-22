#include "companion/steam_reporting_config.h"
#include "shared/path_identity.h"
#include <cstring>

namespace rs2fix::reporting {
namespace {
bool Equal(const char* data, std::size_t count, const char* word) noexcept {
    const auto size = std::strlen(word);
    return count == size && std::memcmp(data, word, size) == 0;
}
bool Space(char c) noexcept { return c == ' ' || c == '\t'; }
} // namespace

Reason ParseConfig(const char* bytes, std::size_t size, Config* output) noexcept {
    if (output) *output = {Mode::Invalid};
    if (!output || !bytes || !size || size > kConfigBytes) return Reason::ConfigInvalid;
    bool schema = false, mode = false;
    Mode selected = Mode::Invalid;
    std::size_t cursor = 0;
    while (cursor < size) {
        const auto start = cursor;
        while (cursor < size && bytes[cursor] != '\n') {
            const auto c = static_cast<unsigned char>(bytes[cursor]);
            if (c > 127 || c == 0 || (c < 32 && c != '\t' && c != '\r'))
                return Reason::ConfigInvalid;
            ++cursor;
        }
        auto first = start, last = cursor;
        if (cursor < size) ++cursor;
        if (last > first && bytes[last - 1] == '\r') --last;
        while (first < last && Space(bytes[first])) ++first;
        while (first < last && Space(bytes[last - 1])) --last;
        if (first == last) continue;
        auto equal = first;
        while (equal < last && bytes[equal] != '=') ++equal;
        if (equal == last) return Reason::ConfigInvalid;
        auto keyEnd = equal, value = equal + 1;
        while (keyEnd > first && Space(bytes[keyEnd - 1])) --keyEnd;
        while (value < last && Space(bytes[value])) ++value;
        if (Equal(bytes + first, keyEnd - first, "schema")) {
            if (schema || !Equal(bytes + value, last - value, "2"))
                return Reason::ConfigInvalid;
            schema = true;
        } else if (Equal(bytes + first, keyEnd - first, "mode")) {
            if (mode) return Reason::ConfigInvalid;
            if (Equal(bytes + value, last - value, "disabled")) selected = Mode::Disabled;
            else if (Equal(bytes + value, last - value, "observe")) selected = Mode::Observe;
            else if (Equal(bytes + value, last - value, "repair")) selected = Mode::Repair;
            else return Reason::ConfigInvalid;
            mode = true;
        } else return Reason::ConfigInvalid;
    }
    if (!schema || !mode) return Reason::ConfigInvalid;
    output->mode = selected;
    return selected == Mode::Disabled ? Reason::ConfigDisabled : Reason::None;
}

Reason ReadConfig(const wchar_t* directory, Config* output, DWORD* error) noexcept {
    if (error) *error = ERROR_INVALID_PARAMETER;
    if (output) *output = {Mode::Invalid};
    if (!directory || !output) return Reason::ConfigInvalid;
    auto* path = static_cast<wchar_t*>(VirtualAlloc(nullptr, kPathCapacity * sizeof(wchar_t),
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!path) { if (error) *error = GetLastError(); return Reason::PreparationFailed; }
    constexpr wchar_t leaf[] = L"RS2SteamReport.ini";
    DWORD localError{};
    if (!AppendPathLeaf(directory, kPathCapacity, leaf, sizeof(leaf) / sizeof(leaf[0]),
        path, kPathCapacity, &localError)) {
        VirtualFree(path, 0, MEM_RELEASE);
        if (error) *error = localError;
        return Reason::ConfigInvalid;
    }
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    localError = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    VirtualFree(path, 0, MEM_RELEASE);
    if (file == INVALID_HANDLE_VALUE) {
        if (error) *error = localError;
        return localError == ERROR_FILE_NOT_FOUND || localError == ERROR_PATH_NOT_FOUND ?
            Reason::ConfigMissing : Reason::ConfigInvalid;
    }
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    char bytes[kConfigBytes]{};
    DWORD read{};
    Reason result = Reason::ConfigInvalid;
    if (GetFileInformationByHandle(file, &info) &&
        !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
        GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= sizeof(bytes) &&
        ReadFile(file, bytes, static_cast<DWORD>(size.QuadPart), &read, nullptr) &&
        read == static_cast<DWORD>(size.QuadPart)) result = ParseConfig(bytes, read, output);
    // The held read-only handle disallows concurrent writes/deletion while parsing.
    // Malformed content and all I/O failures revoke any partially parsed mode.
    if (!CloseHandle(file)) { result = Reason::ConfigInvalid; localError = GetLastError(); }
    if (result != Reason::None && result != Reason::ConfigDisabled) {
        output->mode = Mode::Invalid;
        if (!localError) localError = ERROR_INVALID_DATA;
    }
    if (error) *error = localError;
    return result;
}
} // namespace rs2fix::reporting
