#include "companion/sha256.h"

#include <bcrypt.h>

#include <cstddef>
#include <cstdint>

namespace rs2fix {
namespace {

constexpr DWORD kReadBufferSize = 64 * 1024;

bool NtSucceeded(const NTSTATUS status) noexcept {
    return status >= 0;
}

DWORD StatusAsError(const NTSTATUS status) noexcept {
    const DWORD value = static_cast<DWORD>(status);
    return value == ERROR_SUCCESS ? ERROR_GEN_FAILURE : value;
}

} // namespace

FileHashResult HashFileSha256(
    const wchar_t* path,
    const ULONGLONG softDeadlineTick) noexcept {
    FileHashResult result{};
    result.error = ERROR_GEN_FAILURE;

    if (path == nullptr || path[0] == L'\0') {
        result.error = ERROR_INVALID_PARAMETER;
        return result;
    }
    if (GetTickCount64() > softDeadlineTick) {
        result.error = ERROR_TIMEOUT;
        result.timedOut = true;
        return result;
    }

    HANDLE file = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        result.error = GetLastError();
        return result;
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    void* hashObject = nullptr;
    void* readBuffer = nullptr;
    NTSTATUS status = 0;
    DWORD objectLength = 0;
    DWORD propertyBytes = 0;
    DWORD digestLength = 0;

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart < 0) {
        result.error = GetLastError();
        goto cleanup;
    }
    result.fileSize = static_cast<std::uint64_t>(fileSize.QuadPart);

    status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!NtSucceeded(status)) {
        result.error = StatusAsError(status);
        goto cleanup;
    }

    status = BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectLength),
        sizeof(objectLength),
        &propertyBytes,
        0);
    if (!NtSucceeded(status) || propertyBytes != sizeof(objectLength) ||
        objectLength == 0) {
        result.error = NtSucceeded(status)
            ? ERROR_INVALID_DATA
            : StatusAsError(status);
        goto cleanup;
    }

    propertyBytes = 0;
    status = BCryptGetProperty(
        algorithm,
        BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&digestLength),
        sizeof(digestLength),
        &propertyBytes,
        0);
    if (!NtSucceeded(status) || propertyBytes != sizeof(digestLength) ||
        digestLength != result.digest.size()) {
        result.error = NtSucceeded(status)
            ? ERROR_INVALID_DATA
            : StatusAsError(status);
        goto cleanup;
    }

    hashObject = VirtualAlloc(
        nullptr, objectLength, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    readBuffer = VirtualAlloc(
        nullptr, kReadBufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (hashObject == nullptr || readBuffer == nullptr) {
        result.error = ERROR_NOT_ENOUGH_MEMORY;
        goto cleanup;
    }

    status = BCryptCreateHash(
        algorithm,
        &hash,
        static_cast<PUCHAR>(hashObject),
        objectLength,
        nullptr,
        0,
        0);
    if (!NtSucceeded(status)) {
        result.error = StatusAsError(status);
        goto cleanup;
    }

    while (true) {
        if (GetTickCount64() > softDeadlineTick) {
            result.error = ERROR_TIMEOUT;
            result.timedOut = true;
            goto cleanup;
        }

        DWORD bytesRead = 0;
        if (!ReadFile(
                file,
                readBuffer,
                kReadBufferSize,
                &bytesRead,
                nullptr)) {
            result.error = GetLastError();
            goto cleanup;
        }
        if (bytesRead == 0) {
            break;
        }

        status = BCryptHashData(
            hash,
            static_cast<PUCHAR>(readBuffer),
            bytesRead,
            0);
        if (!NtSucceeded(status)) {
            result.error = StatusAsError(status);
            goto cleanup;
        }
    }

    status = BCryptFinishHash(
        hash,
        result.digest.data(),
        static_cast<ULONG>(result.digest.size()),
        0);
    if (!NtSucceeded(status)) {
        result.error = StatusAsError(status);
        goto cleanup;
    }

    result.error = ERROR_SUCCESS;
    result.digestValid = true;

cleanup:
    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    if (readBuffer != nullptr) {
        VirtualFree(readBuffer, 0, MEM_RELEASE);
    }
    if (hashObject != nullptr) {
        VirtualFree(hashObject, 0, MEM_RELEASE);
    }
    if (algorithm != nullptr) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    CloseHandle(file);
    return result;
}

} // namespace rs2fix
