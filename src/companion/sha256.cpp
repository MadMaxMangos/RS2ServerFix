#include "companion/sha256.h"

#include <bcrypt.h>
#include <limits>

namespace rs2fix {
namespace {
constexpr DWORD kReadBufferSize = 64 * 1024;
DWORD StatusError(const NTSTATUS status) noexcept {
    return status == 0 ? ERROR_GEN_FAILURE : static_cast<DWORD>(status);
}
class CngHash {
public:
    CngHash() noexcept = default;
    CngHash(const CngHash&) = delete;
    CngHash& operator=(const CngHash&) = delete;
    ~CngHash() noexcept {
        if (hash_) BCryptDestroyHash(hash_);
        if (object_) VirtualFree(object_, 0, MEM_RELEASE);
        if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0);
    }
    DWORD Begin() noexcept {
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &algorithm_, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (status < 0) return StatusError(status);
        DWORD objectLength = 0, received = 0, hashLength = 0;
        status = BCryptGetProperty(algorithm_, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &received, 0);
        if (status < 0) return StatusError(status);
        if (received != sizeof(objectLength) || objectLength == 0)
            return ERROR_INVALID_DATA;
        status = BCryptGetProperty(algorithm_, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &received, 0);
        if (status < 0) return StatusError(status);
        if (received != sizeof(hashLength) || hashLength != Sha256Digest{}.size())
            return ERROR_INVALID_DATA;
        object_ = VirtualAlloc(nullptr, objectLength, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!object_) return ERROR_NOT_ENOUGH_MEMORY;
        status = BCryptCreateHash(algorithm_, &hash_, static_cast<PUCHAR>(object_),
            objectLength, nullptr, 0, 0);
        return status < 0 ? StatusError(status) : ERROR_SUCCESS;
    }
    DWORD Update(const void* bytes, const DWORD size) noexcept {
        const NTSTATUS status = BCryptHashData(hash_,
            const_cast<PUCHAR>(static_cast<const UCHAR*>(bytes)), size, 0);
        return status < 0 ? StatusError(status) : ERROR_SUCCESS;
    }
    DWORD Finish(Sha256Digest* digest) noexcept {
        const NTSTATUS status = BCryptFinishHash(hash_, digest->data(),
            static_cast<ULONG>(digest->size()), 0);
        return status < 0 ? StatusError(status) : ERROR_SUCCESS;
    }
private:
    BCRYPT_ALG_HANDLE algorithm_{};
    BCRYPT_HASH_HANDLE hash_{};
    void* object_{};
};
ULONGLONG Ticks(void*) noexcept { return GetTickCount64(); }
bool Read(void*, HANDLE file, void* buffer, DWORD size,
          DWORD* count, DWORD* error) noexcept {
    const bool ok = ReadFile(file, buffer, size, count, nullptr) != FALSE;
    *error = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}
constexpr HashReadOps kReadOps{nullptr, Ticks, Read};
}
const HashReadOps& ProductionHashReadOps() noexcept { return kReadOps; }
bool HashBytesSha256(const void* bytes, const std::size_t size,
                     Sha256Digest* digest, DWORD* error) noexcept {
    if (error) *error = ERROR_INVALID_PARAMETER;
    if (digest) *digest = {};
    if (!digest || (!bytes && size != 0) || size > std::numeric_limits<DWORD>::max())
        return false;
    CngHash hash;
    DWORD result = hash.Begin();
    if (result == ERROR_SUCCESS && size != 0)
        result = hash.Update(bytes, static_cast<DWORD>(size));
    Sha256Digest completed{};
    if (result == ERROR_SUCCESS) result = hash.Finish(&completed);
    if (error) *error = result;
    if (result != ERROR_SUCCESS) return false;
    *digest = completed;
    return true;
}
FileHashResult HashHandleSha256(HANDLE file, const ULONGLONG softDeadlineTick,
                               const HashReadOps& ops) noexcept {
    FileHashResult result{};
    result.error = ERROR_INVALID_PARAMETER;
    if (!file || file == INVALID_HANDLE_VALUE || !ops.ticks || !ops.read) return result;
    const auto expired = [&]() noexcept {
        if (ops.ticks(ops.context) < softDeadlineTick) return false;
        result.error = ERROR_TIMEOUT;
        result.timedOut = true;
        return true;
    };
    if (expired()) return result;
    CngHash hash;
    result.error = hash.Begin();
    if (result.error != ERROR_SUCCESS) return result;
    auto* buffer = static_cast<UCHAR*>(VirtualAlloc(
        nullptr, kReadBufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!buffer) { result.error = ERROR_NOT_ENOUGH_MEMORY; return result; }
    while (!expired()) {
        DWORD read = 0, error = ERROR_SUCCESS;
        const bool ok = ops.read(ops.context, file, buffer, kReadBufferSize, &read, &error);
        // A soft budget cannot interrupt a blocking read. Reject its result if late.
        if (expired()) break;
        if (!ok || read > kReadBufferSize) {
            result.error = error == ERROR_SUCCESS ? ERROR_READ_FAULT : error;
            break;
        }
        if (read == 0) {
            Sha256Digest completed{};
            result.error = hash.Finish(&completed);
            if (!expired() && result.error == ERROR_SUCCESS) {
                result.digest = completed;
                result.digestValid = true;
            }
            break;
        }
        if (result.fileSize > std::numeric_limits<std::uint64_t>::max() - read) {
            result.error = ERROR_ARITHMETIC_OVERFLOW;
            break;
        }
        result.fileSize += read;
        result.error = hash.Update(buffer, read);
        if (result.error != ERROR_SUCCESS) break;
    }
    VirtualFree(buffer, 0, MEM_RELEASE);
    return result;
}
FileHashResult HashFileSha256(const wchar_t* path, const ULONGLONG deadline) noexcept {
    FileHashResult result{};
    result.error = ERROR_INVALID_PARAMETER;
    if (!path || !path[0]) return result;
    if (GetTickCount64() >= deadline) {
        result.error = ERROR_TIMEOUT;
        result.timedOut = true;
        return result;
    }
    const HANDLE file = CreateFileW(path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) { result.error = GetLastError(); return result; }
    result = HashHandleSha256(file, deadline);
    if (!CloseHandle(file) && result.digestValid) {
        result.error = GetLastError();
        result.digestValid = false;
        result.digest = {};
    }
    return result;
}
}
