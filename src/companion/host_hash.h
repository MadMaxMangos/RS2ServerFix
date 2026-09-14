#pragma once
#include "companion/recon_types.h"
#include "companion/sha256.h"

namespace rs2fix {
inline constexpr ULONGLONG kHostHashSoftBudgetMs = 10000;
struct HostHashOps {
    void* context{};
    ULONGLONG (*ticks)(void*) noexcept{};
    HANDLE (*open)(void*, const wchar_t*, DWORD*) noexcept{};
    bool (*metadata)(void*, HANDLE, BY_HANDLE_FILE_INFORMATION*, DWORD*) noexcept{};
    bool (*read)(void*, HANDLE, void*, DWORD, DWORD*, DWORD*) noexcept{};
    void (*close)(void*, HANDLE) noexcept{};
};
const HostHashOps& ProductionHostHashOps() noexcept;
struct HostHashResult {
    FileHashResult hash{};
    FixReason reason{FixReason::HostHashFailed};
};
class HostHashLease {
public:
    HostHashLease() noexcept = default;
    ~HostHashLease() noexcept;
    HostHashLease(const HostHashLease&) = delete;
    HostHashLease& operator=(const HostHashLease&) = delete;
    HostHashLease(HostHashLease&& other) noexcept;
    HostHashLease& operator=(HostHashLease&& other) noexcept;
    bool valid() const noexcept { return file_ != INVALID_HANDLE_VALUE; }
    std::uint64_t fileSize() const noexcept;
    // All validation reads this same retained handle, including after rollback.
    FixReason ValidateStable(DWORD* error = nullptr) const noexcept;
private:
    friend HostHashResult AcquireHostHash(const wchar_t*, HostHashLease*, const HostHashOps&) noexcept;
    void Close() noexcept;
    HANDLE file_{INVALID_HANDLE_VALUE};
    BY_HANDLE_FILE_INFORMATION initial_{};
    HostHashOps ops_{};
};
HostHashResult AcquireHostHash(const wchar_t* path, HostHashLease* lease,
    const HostHashOps& ops = ProductionHostHashOps()) noexcept;
}
