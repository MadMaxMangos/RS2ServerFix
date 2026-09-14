#include "shared/path_identity.h"
#include <cwchar>
#include <iterator>
#include <limits>

namespace rs2fix {
namespace {
void StoreError(DWORD* error, DWORD value) noexcept {
    if (error != nullptr) *error = value;
}
void Empty(wchar_t* output, std::size_t capacity) noexcept {
    if (output != nullptr && capacity != 0) output[0] = L'\0';
}
bool Length(const wchar_t* input, std::size_t capacity, std::size_t* length) noexcept {
    if (input == nullptr || capacity == 0) return false;
    for (std::size_t i = 0; i < capacity; ++i) {
        if (input[i] == L'\0') { *length = i; return i != 0; }
    }
    return false;
}
bool ValidateOutput(wchar_t* output, std::size_t capacity, DWORD* error) noexcept {
    Empty(output, capacity);
    if (output == nullptr || capacity == 0 ||
        capacity > std::numeric_limits<DWORD>::max()) {
        StoreError(error, ERROR_INVALID_PARAMETER);
        return false;
    }
    return true;
}
} // namespace

bool AppendPathLeaf(const wchar_t* directory, std::size_t directoryCapacity,
    const wchar_t* leaf, std::size_t leafCapacity, wchar_t* output,
    std::size_t outputCapacity, DWORD* error) noexcept {
    if (directory == nullptr || leaf == nullptr || output == nullptr ||
        directoryCapacity == 0 || leafCapacity == 0 || outputCapacity == 0) {
        Empty(output, outputCapacity);
        StoreError(error, ERROR_INVALID_PARAMETER);
        return false;
    }
    std::size_t directoryLength = 0, leafLength = 0;
    if (!Length(directory, directoryCapacity, &directoryLength) ||
        !Length(leaf, leafCapacity, &leafLength)) {
        Empty(output, outputCapacity);
        StoreError(error, ERROR_INVALID_NAME);
        return false;
    }
    const bool separator = directory[directoryLength - 1] != L'\\' &&
        directory[directoryLength - 1] != L'/';
    const std::size_t extra = separator ? 1u : 0u;
    if (directoryLength >= outputCapacity ||
        extra >= outputCapacity - directoryLength ||
        leafLength >= outputCapacity - directoryLength - extra) {
        Empty(output, outputCapacity);
        StoreError(error, ERROR_INSUFFICIENT_BUFFER);
        return false;
    }
    std::wmemmove(output, directory, directoryLength);
    std::size_t cursor = directoryLength;
    if (separator) output[cursor++] = L'\\';
    std::wmemmove(output + cursor, leaf, leafLength);
    output[cursor + leafLength] = L'\0';
    StoreError(error, ERROR_SUCCESS);
    return true;
}

bool BuildSystemX3AudioPath(wchar_t* output, std::size_t capacity, DWORD* error) noexcept {
    if (!ValidateOutput(output, capacity, error)) return false;
    const UINT length = GetSystemDirectoryW(output, static_cast<UINT>(capacity));
    if (length == 0) {
        const DWORD failure = GetLastError();
        Empty(output, capacity);
        StoreError(error, failure);
        return false;
    }
    if (length >= capacity) {
        Empty(output, capacity);
        StoreError(error, ERROR_INSUFFICIENT_BUFFER);
        return false;
    }
    constexpr wchar_t leaf[] = L"X3DAudio1_7.dll";
    return AppendPathLeaf(output, capacity, leaf, std::size(leaf), output, capacity, error);
}

bool GetBoundedModulePath(HMODULE module, wchar_t* output,
    std::size_t capacity, DWORD* error) noexcept {
    if (!ValidateOutput(output, capacity, error)) return false;
    SetLastError(ERROR_SUCCESS);
    const DWORD length = GetModuleFileNameW(module, output, static_cast<DWORD>(capacity));
    if (length == 0) {
        const DWORD failure = GetLastError();
        Empty(output, capacity);
        StoreError(error, failure);
        return false;
    }
    if (length >= capacity) {
        Empty(output, capacity);
        StoreError(error, ERROR_INSUFFICIENT_BUFFER);
        return false;
    }
    StoreError(error, ERROR_SUCCESS);
    return true;
}

bool ExtractDirectoryAndLeaf(const wchar_t* path, std::size_t pathCapacity,
    wchar_t* directory, std::size_t directoryCapacity,
    wchar_t* leaf, std::size_t leafCapacity, DWORD* error) noexcept {
    Empty(directory, directoryCapacity);
    Empty(leaf, leafCapacity);
    if (path == nullptr || directory == nullptr || leaf == nullptr ||
        pathCapacity == 0 || directoryCapacity == 0 || leafCapacity == 0) {
        StoreError(error, ERROR_INVALID_PARAMETER);
        return false;
    }
    std::size_t length = 0;
    if (!Length(path, pathCapacity, &length)) {
        StoreError(error, ERROR_INVALID_NAME);
        return false;
    }
    std::size_t separator = length;
    while (separator != 0 && path[separator - 1] != L'\\' &&
        path[separator - 1] != L'/') --separator;
    if (separator == 0 || separator == length) {
        StoreError(error, ERROR_INVALID_NAME);
        return false;
    }
    // Preserve C:\ when splitting a file at the drive root.
    const std::size_t directoryLength = separator == 3 && path[1] == L':'
        ? separator : separator - 1;
    const std::size_t leafLength = length - separator;
    if (directoryLength == 0) {
        StoreError(error, ERROR_INVALID_NAME);
        return false;
    }
    if (directoryLength >= directoryCapacity || leafLength >= leafCapacity) {
        StoreError(error, ERROR_INSUFFICIENT_BUFFER);
        return false;
    }
    std::wmemcpy(directory, path, directoryLength);
    directory[directoryLength] = L'\0';
    std::wmemcpy(leaf, path + separator, leafLength);
    leaf[leafLength] = L'\0';
    StoreError(error, ERROR_SUCCESS);
    return true;
}

bool QueryFileIdentity(const wchar_t* path, FileIdentity* identity, DWORD* error) noexcept {
    if (identity != nullptr) *identity = {};
    if (path == nullptr || path[0] == L'\0' || identity == nullptr) {
        StoreError(error, ERROR_INVALID_PARAMETER);
        return false;
    }
    const HANDLE file = CreateFileW(path, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        StoreError(error, GetLastError());
        return false;
    }
    BY_HANDLE_FILE_INFORMATION information{};
    if (!GetFileInformationByHandle(file, &information)) {
        const DWORD failure = GetLastError();
        CloseHandle(file);
        StoreError(error, failure);
        return false;
    }
    if (!CloseHandle(file)) {
        StoreError(error, GetLastError());
        return false;
    }
    identity->volumeSerial = information.dwVolumeSerialNumber;
    identity->fileIndexHigh = information.nFileIndexHigh;
    identity->fileIndexLow = information.nFileIndexLow;
    identity->valid = true;
    StoreError(error, ERROR_SUCCESS);
    return true;
}

bool SameFileIdentity(const FileIdentity& left, const FileIdentity& right) noexcept {
    return left.valid && right.valid && left.volumeSerial == right.volumeSerial &&
        left.fileIndexHigh == right.fileIndexHigh && left.fileIndexLow == right.fileIndexLow;
}
} // namespace rs2fix
