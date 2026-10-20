#pragma once
#include <Windows.h>
#include <cstddef>
#include <cstdint>

namespace rs2fix::recovery {
inline constexpr wchar_t kTrainingRoot[] = L"E:\\rs2v_trainingsrv";
inline constexpr wchar_t kTrainingExecutableDirectory[] = L"E:\\rs2v_trainingsrv\\Binaries\\Win64";
inline constexpr std::size_t kControlPathBytes = 512;
inline constexpr std::size_t kControlFileBytes = 512;
inline constexpr std::size_t kControlAclCharacters = 8192;
enum class ControlResult : LONG {
    Uninitialized, Disabled, Ready, Missing, InvalidConfig, InvalidIdentity,
    InvalidPath, SecurityRejected, ReadFailure, InvalidRequest, Latched,
    Stopped, WorkerFailure, PendingWrite, EndpointUnavailable
};
struct ControlConfig {
    bool enabled;
    BYTE operatorSid[SECURITY_MAX_SID_SIZE];
    DWORD operatorSidBytes;
};
// Scalars only. The qualified owner separately binds this request to its current
// source/world epoch; the control worker has no source or native object access.
struct ControlRequest { DWORD pid; BYTE runId[16]; };
struct ControlSecurity {
    BYTE operatorSid[SECURITY_MAX_SID_SIZE];
    DWORD operatorSidBytes;
    BYTE administratorSid[SECURITY_MAX_SID_SIZE];
    DWORD administratorSidBytes;
};
// Zero-initializable, process-resident POD. Do not copy or free it after Start.
// request and requestAcl become immutable before the release latch. No worker
// writes an exported recovery publication. Root owns startup/shutdown ordering.
struct ControlState {
    volatile LONG stop;
    volatile LONG started;
    volatile LONG latched;
    volatile LONG result;
    bool enabled;
    ControlRequest identity;
    ControlRequest request;
    ControlSecurity security;
    HANDLE directories[4];
    HANDLE thread;
    HANDLE pipe;
    HANDLE ioEvent;
    HANDLE stopEvent;
    wchar_t requestPath[kControlPathBytes];
    wchar_t directoryAcl[3][kControlAclCharacters];
    wchar_t configAcl[kControlAclCharacters];
    wchar_t requestAcl[kControlAclCharacters];
    DWORD error;
};
ControlResult ParseControlConfig(const char*, std::size_t, ControlConfig*) noexcept;
ControlResult ParseControlRequest(const char*, std::size_t,
    const ControlRequest& identity, ControlRequest*) noexcept;
ControlResult InitializeControl(ControlState&, const wchar_t* executableDirectory,
    DWORD pid, const BYTE (&runId)[16], DWORD* error) noexcept;
bool StartControl(ControlState&, DWORD* error) noexcept;
void StopControl(ControlState&) noexcept;
bool ReadLatchedControl(const ControlState&, ControlRequest*) noexcept;
#ifdef RS2_REPORTING_TESTING
ControlResult PrepareControlPipeForTesting(ControlState&, DWORD*) noexcept;
bool ControlPeerMatchesForTesting(const ControlSecurity&, PSID) noexcept;
ControlResult ReadControlConfigForTesting(const wchar_t*, const ControlSecurity&,
    ControlConfig*, DWORD*) noexcept;
bool ValidateControlSecurityForTesting(PSECURITY_DESCRIPTOR,
    const ControlSecurity&, bool permissionFile) noexcept;
ControlResult ReadControlRequestForTesting(const wchar_t* exactPath,
    const ControlSecurity&, const ControlRequest&, ControlRequest*,
    wchar_t* observedAcl, std::size_t aclCapacity, DWORD*) noexcept;
#endif
} // namespace rs2fix::recovery
