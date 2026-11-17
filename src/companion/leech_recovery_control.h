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
// Keep legacy pilot syntax independent of the portable, EXE-derived root.
inline constexpr std::size_t kLegacyControlRootCharacters = 36;
inline constexpr std::size_t kControlRootCharacters = kControlPathBytes;
inline constexpr std::size_t kControlDirectoryPins = kControlPathBytes / 2;
struct ControlScope { DWORD schema; wchar_t serverRoot[kControlRootCharacters]; };
inline constexpr ControlScope kTrainingControlScope{1,L"E:\\rs2v_trainingsrv"};
enum class ControlResult : LONG {
    Uninitialized, Disabled, Ready, Missing, InvalidConfig, InvalidIdentity,
    InvalidPath, SecurityRejected, ReadFailure, InvalidRequest, Latched,
    Stopped, WorkerFailure, PendingWrite, EndpointUnavailable, AlreadyClaimed
};
enum class RequestOrigin : LONG { None, Pipe, ServerAdminConsole };
enum class ControlTransport : unsigned { None, AuthenticatedPipe, WebAdminOnly };
enum class ConsoleRegistration : LONG { NotRegistered, Available, Unavailable };
enum class ConsoleCommand : unsigned { Unrelated, Invalid, Status, Recover };
inline constexpr std::size_t kConsoleCommandCharacters = 96;
inline constexpr std::size_t kConsoleConfirmationCharacters = 16;
struct ControlConfig {
    bool enabled;
    bool consoleRequested;
    bool autoRoot;
    ControlTransport transport;
    ControlScope scope;
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
// Identity is immutable before Start. The latch itself records the winning
// origin: no competing writer can overwrite another request's payload. No
// worker writes an exported recovery publication. Root owns shutdown ordering.
struct ControlState {
    volatile LONG stop;
    volatile LONG started;
    volatile LONG latched;
    volatile LONG result;
    bool enabled;
    // Requested opt-in is not authority: the native adapter must qualify first.
    bool consoleRequested;
    ControlTransport transport;
    // One-way owner publication AFTER native registration, read interlocked.
    // Requested intent above is startup-immutable and is never call authority.
    volatile LONG consoleRegistration;
    // Configuration scope joins the immutable PID/run identity before Start.
    ControlScope scope;
    ControlRequest identity;
    ControlSecurity security;
    HANDLE directories[kControlDirectoryPins];
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
    const ControlRequest& identity, ControlRequest*, const ControlScope* = nullptr) noexcept;
ControlResult InitializeControl(ControlState&, const wchar_t* executableDirectory,
    DWORD pid, const BYTE (&runId)[16], DWORD* error, bool allowManualPilot = false,
    bool allowWebAdminOnly = false) noexcept;
bool ManualPilotScope(const ControlScope&) noexcept;
bool LegacyPipeScope(const ControlScope&, ControlTransport) noexcept;
bool WebAdminOnlyScope(const ControlScope&, ControlTransport) noexcept;
bool ConsoleControlScope(const ControlState&) noexcept;
// Activated does not imply a worker exists: WebAdmin-only is owner-serviced.
bool StartControl(ControlState&, DWORD* error) noexcept;
void StopControl(ControlState&) noexcept;
// Call only from the qualified owner WebAdmin route after intent-token checks.
// Trusted local opt-in delegates to existing game-admin privileges; this route
// does NOT authenticate the Windows operator. It cannot select the pipe origin.
bool ClaimConsoleControlRequest(ControlState&) noexcept;
// Qualified owner only, after completing a rejection with NO native recipe
// entry. Does not restart a failed worker, change identity, or bypass a stop.
bool ReleasePreflightClaim(ControlState&) noexcept;
ConsoleRegistration ReadConsoleRegistration(const ControlState&) noexcept;
bool ReadLatchedControl(const ControlState&, ControlRequest*, RequestOrigin* = nullptr) noexcept;
void ConsoleConfirmation(const BYTE (&runId)[16],
    char (&output)[kConsoleConfirmationCharacters + 1]) noexcept;
// Pure bounded parsing; does not read beyond the supplied span or claim a
// request. The native adapter must first copy a bounded, readable UTF-16 span.
ConsoleCommand ParseConsoleCommand(const wchar_t*, std::size_t characters,
    const char (&confirmation)[kConsoleConfirmationCharacters + 1]) noexcept;
#ifdef RS2_REPORTING_TESTING
// Private startup dispatch seam; production never accepts caller-supplied calls.
struct ControlPlatformCalls {
    bool (*administratorIdentity)(ControlSecurity*, DWORD*) noexcept;
    ControlResult (*preparePipe)(ControlState&, DWORD*) noexcept;
    HANDLE (*startWorker)(ControlState&, DWORD*) noexcept;
};
ControlResult PrepareControlTransportForTesting(ControlState&, const ControlConfig&,
    bool allowWebAdminOnly, const ControlPlatformCalls&, DWORD*) noexcept;
bool StartControlForTesting(ControlState&, const ControlPlatformCalls&, DWORD*) noexcept;
bool StartupThreadUnimpersonatedForTesting(DWORD (*presence)() noexcept, DWORD*) noexcept;
bool ClaimControlForTesting(ControlState&, RequestOrigin) noexcept;
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
