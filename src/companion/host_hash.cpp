#include "companion/host_hash.h"
#include <limits>
#include <utility>

namespace rs2fix {
namespace {
ULONGLONG Ticks(void*) noexcept { return GetTickCount64(); }
HANDLE Open(void*, const wchar_t* path, DWORD* error) noexcept {
    const HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    *error = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    return file;
}
bool Metadata(void*, HANDLE file, BY_HANDLE_FILE_INFORMATION* info, DWORD* error) noexcept {
    if (GetFileType(file) != FILE_TYPE_DISK) { *error = ERROR_INVALID_HANDLE; return false; }
    if (!GetFileInformationByHandle(file, info)) { *error = GetLastError(); return false; }
    if ((info->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 || info->nNumberOfLinks == 0) {
        *error = ERROR_INVALID_DATA;
        return false;
    }
    *error = ERROR_SUCCESS;
    return true;
}
bool Read(void*, HANDLE file, void* buffer, DWORD size, DWORD* count, DWORD* error) noexcept {
    const bool ok = ReadFile(file, buffer, size, count, nullptr) != FALSE;
    *error = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}
void Close(void*, HANDLE file) noexcept { CloseHandle(file); }
constexpr HostHashOps kOps{nullptr, Ticks, Open, Metadata, Read, Close};
bool SameTime(const FILETIME& a, const FILETIME& b) noexcept {
    return a.dwLowDateTime == b.dwLowDateTime && a.dwHighDateTime == b.dwHighDateTime;
}
bool SameIdentity(const BY_HANDLE_FILE_INFORMATION& a,
                  const BY_HANDLE_FILE_INFORMATION& b) noexcept {
    return a.dwVolumeSerialNumber == b.dwVolumeSerialNumber &&
        a.nFileIndexHigh == b.nFileIndexHigh && a.nFileIndexLow == b.nFileIndexLow &&
        a.nFileSizeHigh == b.nFileSizeHigh && a.nFileSizeLow == b.nFileSizeLow &&
        a.dwFileAttributes == b.dwFileAttributes && a.nNumberOfLinks == b.nNumberOfLinks &&
        SameTime(a.ftCreationTime, b.ftCreationTime) && SameTime(a.ftLastWriteTime, b.ftLastWriteTime);
}
}
const HostHashOps& ProductionHostHashOps() noexcept { return kOps; }
HostHashLease::~HostHashLease() noexcept { Close(); }
void HostHashLease::Close() noexcept {
    if (valid()) ops_.close(ops_.context, file_);
    file_ = INVALID_HANDLE_VALUE;
}
HostHashLease::HostHashLease(HostHashLease&& other) noexcept { *this = std::move(other); }
HostHashLease& HostHashLease::operator=(HostHashLease&& other) noexcept {
    if (this != &other) {
        Close();
        file_ = other.file_;
        initial_ = other.initial_;
        ops_ = other.ops_;
        other.file_ = INVALID_HANDLE_VALUE;
    }
    return *this;
}
std::uint64_t HostHashLease::fileSize() const noexcept {
    return (static_cast<std::uint64_t>(initial_.nFileSizeHigh) << 32) | initial_.nFileSizeLow;
}
FixReason HostHashLease::ValidateStable(DWORD* error) const noexcept {
    if (error) *error = ERROR_INVALID_HANDLE;
    if (!valid()) return FixReason::HostIdentityChanged;
    BY_HANDLE_FILE_INFORMATION current{};
    DWORD localError = ERROR_SUCCESS;
    if (!ops_.metadata(ops_.context, file_, &current, &localError)) {
        if (error) *error = localError == ERROR_SUCCESS ? ERROR_INVALID_DATA : localError;
        return FixReason::HostIdentityChanged;
    }
    if (!SameIdentity(initial_, current)) {
        if (error) *error = ERROR_FILE_INVALID;
        return FixReason::HostIdentityChanged;
    }
    if (error) *error = ERROR_SUCCESS;
    return FixReason::None;
}
HostHashResult AcquireHostHash(const wchar_t* path, HostHashLease* lease,
                              const HostHashOps& ops) noexcept {
    HostHashResult result{};
    result.hash.error = ERROR_INVALID_PARAMETER;
    if (!path || !path[0] || !lease || lease->valid() || !ops.ticks || !ops.open ||
        !ops.metadata || !ops.read || !ops.close) return result;
    const ULONGLONG started = ops.ticks(ops.context);
    const ULONGLONG deadline = started > std::numeric_limits<ULONGLONG>::max() - kHostHashSoftBudgetMs
        ? std::numeric_limits<ULONGLONG>::max() : started + kHostHashSoftBudgetMs;
    DWORD error = ERROR_SUCCESS;
    lease->file_ = ops.open(ops.context, path, &error);
    lease->ops_ = ops;
    if (!lease->file_ || lease->file_ == INVALID_HANDLE_VALUE) {
        lease->file_ = INVALID_HANDLE_VALUE;
        result.hash.error = error == ERROR_SUCCESS ? ERROR_OPEN_FAILED : error;
        result.reason = error == ERROR_SHARING_VIOLATION
            ? FixReason::HostOpenSharingViolation : FixReason::HostOpenFailed;
        return result;
    }
    if (!ops.metadata(ops.context, lease->file_, &lease->initial_, &error)) {
        result.reason = FixReason::HostIdentityChanged;
        result.hash.error = error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error;
        return result;
    }
    const HashReadOps reads{ops.context, ops.ticks, ops.read};
    result.hash = HashHandleSha256(lease->file_, deadline, reads);
    const std::uint64_t hashedBytes = result.hash.fileSize;
    result.hash.fileSize = lease->fileSize();
    if (!result.hash.digestValid) {
        result.reason = result.hash.timedOut
            ? FixReason::HostHashBudgetExceeded : FixReason::HostHashFailed;
        return result;
    }
    result.reason = lease->ValidateStable(&error);
    if (result.reason == FixReason::None && hashedBytes != lease->fileSize()) {
        result.reason = FixReason::HostIdentityChanged;
        error = ERROR_FILE_INVALID;
    }
    if (result.reason == FixReason::None && ops.ticks(ops.context) >= deadline) {
        result.reason = FixReason::HostHashBudgetExceeded;
        result.hash.timedOut = true;
        error = ERROR_TIMEOUT;
    }
    if (result.reason != FixReason::None) {
        result.hash.error = error;
        result.hash.digestValid = false;
        result.hash.digest = {};
    }
    // Retain the handle even on failure; the owner decides the terminal state.
    result.hash.fileSize = lease->fileSize();
    return result;
}
}
