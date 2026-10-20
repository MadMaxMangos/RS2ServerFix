#pragma once
#include "companion/console_status.h"
#include "companion/steam_reporting_status_v3.h"
#include "shared/steam_reporting_snapshot_v3.h"
#include "companion/leech_recovery_wire.h"

namespace rs2fix::reporting {
enum class ConsoleStateV3 { WaitingLogger, Paused, Ready, Disabled };
struct ConsoleNoticeV3 {
    ConsoleStateV3 state;
    bool transportReason;
    std::uint64_t reason, epoch, ownerTransition, workerCondition, sourceQpc;
};
// Selection/formatting are worker-only. These are value copies, not a second
// owner/receipt-worker mailbox. The sequenced DATA remains authoritative.
bool SelectReportingConsoleNotice(const StatusSnapshotV3&,std::uint64_t now,
    ConsoleNoticeV3*) noexcept;
bool FormatReportingConsoleNotice(const StatusHeader&,const ConsoleNoticeV3&,
    const char* event,ConsoleReportContext*) noexcept;
bool FormatRecoveryConsoleNotice(const RecoveryStatusWireV1&,ConsoleReportContext*) noexcept;

struct ReportingConsole {
    volatile LONG claimed;
    StatusWireV3* status;
    RecoveryStatusWireV1* recovery; // Cold attachment, immutable after armed.
    ConsoleStatusOps ops;
    bool (*qpc)(void*,std::uint64_t*) noexcept;
    HANDLE thread;
    std::uint64_t armed,stop;
    // Only the console worker writes the fields below after preparation.
    ConsoleDiagnostics diagnostics;
    ConsoleNoticeV3 latest;
    RecoveryStatusWireV1 latestRecovery;
    std::uint64_t lastAttemptMs,lastClockMs,lastClockQpc;
    bool haveSelection,pending,pendingAttempted,haveAttempt,haveClock,everReady;
    bool haveRecoverySelection,recoveryPending,recoveryPendingAttempted,haveNormalAttempt;
};
static_assert(std::is_trivial_v<ReportingConsole> && sizeof(ReportingConsole)<4096);

// Cold preparation, once per process-lifetime storage, before hook admission.
// Caller pins the containing module and retains storage even if stdout blocks.
ReporterStartResult StartReportingConsole(ReportingConsole&,StatusWireV3&,
    const ConsoleStatusOps&,bool (*qpc)(void*,std::uint64_t*) noexcept) noexcept;
ReporterStartResult StartReportingConsole(ReportingConsole&,StatusWireV3&) noexcept;
bool AttachReportingConsoleRecovery(ReportingConsole&,RecoveryStatusWireV1*) noexcept;
void ArmReportingConsole(ReportingConsole&) noexcept;
void StopReportingConsole(ReportingConsole&) noexcept;
// Pre-arm rejection only. Preserve the separate one-shot bounded startup notice
// when the persistent channel has not been armed or could not be prepared.
void ScheduleReportingDisabledNotice(const StatusWireV3&,Reason) noexcept;
// One iteration on the sole worker; test seam uses the same ConsoleStatusOps.
// false means terminal. No native logger, repair, allocation or thread creation.
bool CycleReportingConsole(ReportingConsole&) noexcept;
}
