#pragma once
#include "companion/steam_observer_profile.h"

namespace rs2fix::observer {
struct Config { bool enabled; std::uint32_t maxLogMiB; };
Reason ParseConfig(const char* bytes, std::size_t size, Config* output) noexcept;
// Reuse the observer prerequisite's existing bounded parser without activating
// an observer or retaining startup-local path storage.
Reason ReadObserverConfig(const wchar_t* directory, Config* output) noexcept;
struct TransactionOps {
    MemoryOps memory;
    void* context;
    std::size_t pageSize;
    bool (*protect)(void*, std::uintptr_t, std::size_t, DWORD, DWORD*, DWORD*) noexcept;
    bool (*compareExchange)(void*, std::uintptr_t, void*, void*, void**, DWORD*) noexcept;
    bool (*stableIdentity)(void*, DWORD*) noexcept;
};
struct InstallResult { bool armed; bool fatal; Reason reason; DWORD error; };
// Optional reporting-only fourth cell, committed in the SAME transaction as
// the three observer cells. The caller publishes immutable forwarding state
// before installation. The validator checks immutable native evidence only:
// IAT ownership changes are verified separately before and after the swap.
struct ServerPumpCell {
    std::uint32_t iatRva;
    ShutdownFn original;
    ShutdownFn wrapper;
    void* profileContext;
    bool (*validateNativeProfile)(void*, DWORD*) noexcept;
};
InstallResult InstallObserver(const BootstrapContextV3&, const StartupProfile&,
    const Profile&, DispatchState&, const TransactionOps&,
    const ServerPumpCell* serverPump=nullptr) noexcept;
// Narrow production facade shared with reporting: keep the same guarded
// protection/CAS/lease-stability adapters and unsafe-rollback policy.
InstallResult InstallObserverWithLeases(const BootstrapContextV3&, const StartupProfile&,
    const Profile&, DispatchState&, HostHashLease& host, HostHashLease& sdk,
    const ServerPumpCell* serverPump=nullptr) noexcept;
[[noreturn]] void FailFastObserverInstallation(const InstallResult&) noexcept;

// Called only inside the existing pre-service initialization opportunity, AFTER
// the core recon marker/reporter attempt. Neither result nor marker is changed.
void StartObserver(const BootstrapContextV3&, const StartupProfile&, const Profile&,
    const Sha256Digest& hostDigest, HostHashLease&, const wchar_t* executableDirectory) noexcept;
void ObserverUnavailable(Reason) noexcept;
} // namespace rs2fix::observer
