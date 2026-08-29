#include "shared/path_identity.h"

#include <algorithm>
#include <cwchar>
#include <limits>

namespace rs2fix {
namespace {

void StoreError(DWORD* error, const DWORD value) noexcept {
    if (error != nullptr) {
        *error = value;
    }
}

bool ValidateOutput(
    wchar_t* output,
    const std::size_t capacity,
    DWORD* error) noexcept {
    if (output == nullptr || capacity == 0 ||
        capacity > std::numeric_limits<DWORD>::max()) {
        StoreError(error, ERROR_INVALID_PARAMETER);
        return false;
    }
    output[0] = L'\0';
    return true;
}

} // namespace

bool AppendPathLeaf(
    const wchar_t* directory,
    const wchar_t* leaf,
    wchar_t* output,
    const std::size_t capacity,
    DWORD* error) noexcept {
    if (directory == nullptr || leaf == nullptr || output == nullptr ||
        capacity == 0) {
        StoreError(error, ERROR_INVALID_PARAMETER);
        return false;
    }

    const std::size_t directoryLength =
        wcsnlen_s(directory, kPathCapacity);
    const std::size_t leafLength = wcsnlen_s(leaf, kPathCapacity);
    if (directoryLength == 0 || directoryLength >= kPathCapacity ||
        leafLength == 0 || leafLength >= kPathCapacity) {
        output[0] = L'\0';
        StoreError(error, ERROR_INVALID_NAME);
        return false;
    }

    const bool needsSeparator =
        directory[directoryLength - 1] != L'\\' &&
        directory[directoryLength - 1] != L'/';
    const std::size_t required = directoryLength +
        (needsSeparator ? 1u : 0u) + leafLength + 1;
    if (required > capacity) {
        output[0] = L'\0';
        StoreError(error, ERROR_INSUFFICIENT_BUFFER);
        return false;
    }

    std::wmemmove(output, directory, directoryLength);
    std::size_t cursor = directoryLength;
    if (needsSeparator) {
        output[cursor++] = L'\\';
    }
    std::wmemmove(output + cursor, leaf, leafLength);
    output[cursor + leafLength] = L'\0';
    StoreError(error, ERROR_SUCCESS);
    return true;
}

bool BuildSystemFaultrepPath(
    wchar_t* output,
    const std::size_t capacity,
    DWORD* error) noexcept {
    if (!ValidateOutput(output, capacity, error)) {
        return false;
    }

    const UINT outputCapacity = static_cast<UINT>(capacity);
    const UINT length = GetSystemDirectoryW(output, outputCapacity);
    if (length == 0) {
        StoreError(error, GetLastError());
        return false;
    }
    if (length >= capacity) {
        output[0] = L'\0';
        StoreError(error, ERROR_INSUFFICIENT_BUFFER);
        return false;
    }

    return AppendPathLeaf(
        output, L"faultrep.dll", output, capacity, error);
}

bool GetBoundedModulePath(
    HMODULE module,
    wchar_t* output,
    const std::size_t capacity,
    DWORD* error) noexcept {
    if (!ValidateOutput(output, capacity, error)) {
        return false;
    }

    SetLastError(ERROR_SUCCESS);
    const DWORD length = GetModuleFileNameW(
        module, output, static_cast<DWORD>(capacity));
    if (length == 0) {
        StoreError(error, GetLastError());
        return false;
    }
    if (length >= capacity - 1) {
        output[0] = L'\0';
        StoreError(error, ERROR_INSUFFICIENT_BUFFER);
        return false;
    }

    StoreError(error, ERROR_SUCCESS);
    return true;
}

bool ExtractDirectoryAndLeaf(
    const wchar_t* path,
    wchar_t* directory,
    const std::size_t directoryCapacity,
    wchar_t* leaf,
    const std::size_t leafCapacity,
    DWORD* error) noexcept {
    if (path == nullptr || directory == nullptr || leaf == nullptr ||
        directoryCapacity == 0 || leafCapacity == 0) {
        StoreError(error, ERROR_INVALID_PARAMETER);
        return false;
    }
    directory[0] = L'\0';
    leaf[0] = L'\0';

    const std::size_t length = wcsnlen_s(path, kPathCapacity);
    if (length == 0 || length >= kPathCapacity) {
        StoreError(error, ERROR_INVALID_NAME);
        return false;
    }

    std::size_t separator = length;
    while (separator != 0) {
        --separator;
        if (path[separator] == L'\\' || path[separator] == L'/') {
            break;
        }
    }
    if ((path[separator] != L'\\' && path[separator] != L'/') ||
        separator + 1 >= length) {
        StoreError(error, ERROR_INVALID_NAME);
        return false;
    }

    const std::size_t directoryLength = separator;
    const std::size_t leafLength = length - separator - 1;
    if (directoryLength + 1 > directoryCapacity ||
        leafLength + 1 > leafCapacity) {
        StoreError(error, ERROR_INSUFFICIENT_BUFFER);
        return false;
    }

    std::wmemcpy(directory, path, directoryLength);
    directory[directoryLength] = L'\0';
    std::wmemcpy(leaf, path + separator + 1, leafLength);
    leaf[leafLength] = L'\0';
    StoreError(error, ERROR_SUCCESS);
    return true;
}

bool QueryFileIdentity(
    const wchar_t* path,
    FileIdentity* identity,
    DWORD* error) noexcept {
    if (identity != nullptr) {
        *identity = {};
    }
    if (path == nullptr || path[0] == L'\0' || identity == nullptr) {
        StoreError(error, ERROR_INVALID_PARAMETER);
        return false;
    }

    const HANDLE file = CreateFileW(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        StoreError(error, GetLastError());
        return false;
    }

    BY_HANDLE_FILE_INFORMATION information{};
    if (!GetFileInformationByHandle(file, &information)) {
        const DWORD localError = GetLastError();
        CloseHandle(file);
        StoreError(error, localError);
        return false;
    }
    CloseHandle(file);

    identity->volumeSerial = information.dwVolumeSerialNumber;
    identity->fileIndexHigh = information.nFileIndexHigh;
    identity->fileIndexLow = information.nFileIndexLow;
    identity->valid = true;
    StoreError(error, ERROR_SUCCESS);
    return true;
}

bool SameFileIdentity(
    const FileIdentity& left,
    const FileIdentity& right) noexcept {
    return left.valid && right.valid &&
           left.volumeSerial == right.volumeSerial &&
           left.fileIndexHigh == right.fileIndexHigh &&
           left.fileIndexLow == right.fileIndexLow;
}

} // namespace rs2fix
