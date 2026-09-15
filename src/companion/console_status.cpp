#include "companion/console_status.h"
#include "shared/version.h"
#include <cstdio>
#include <cstring>
#include <initializer_list>

namespace rs2fix {
namespace {
// Bound every enum fragment and the fixed text, including failure reporting.
constexpr std::size_t kMaxEnumFragment = 32;
constexpr std::size_t kFixedLineBound = sizeof(
    "[RS2ServerFix] v" RS2FIX_VERSION_ASCII
    " loaded; host=; mode=; qualification=; recon=; fix="
    "recon-exclusive-scale-v1; reason=; marker=; acceptance=\r\n");
static_assert(kFixedLineBound + 4 * kMaxEnumFragment + 3 * 8 <= kConsoleLineCapacity);
static_assert(sizeof("host_open_sharing_violation") - 1 <= kMaxEnumFragment);
static_assert(sizeof("pr1-crash-full-dump") - 1 <= kMaxEnumFragment);
ReporterStorage g_reporter{};

bool ValidReport(const ConsoleReportContext& report) noexcept {
    if (report.bytes < 2 || report.bytes >= kConsoleLineCapacity ||
        report.line[report.bytes] != '\0' || report.line[report.bytes - 2] != '\r' ||
        report.line[report.bytes - 1] != '\n') return false;
    for (DWORD i = 0; i < report.bytes - 2; ++i)
        if (report.line[i] < 32 || report.line[i] > 126) return false;
    return true;
}
ULONGLONG Ticks(void*) noexcept { return GetTickCount64(); }
void SleepFor(void*, DWORD delay) noexcept { Sleep(delay); }
HANDLE StdOutput(void*, DWORD* error) noexcept {
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    *error = output == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    return output;
}
bool Write(void*, HANDLE output, const void* bytes, DWORD size,
           DWORD* written, DWORD* error) noexcept {
    const bool ok = WriteFile(output, bytes, size, written, nullptr) != FALSE;
    *error = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}
HANDLE Start(void*, LPTHREAD_START_ROUTINE function, void* context, DWORD* error) noexcept {
    const HANDLE thread = CreateThread(nullptr, 0, function, context, 0, nullptr);
    *error = thread ? ERROR_SUCCESS : GetLastError();
    return thread;
}
bool Close(void*, HANDLE thread, DWORD* error) noexcept {
    const bool ok = CloseHandle(thread) != FALSE;
    *error = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}
constexpr ConsoleStatusOps kOps{nullptr, Ticks, SleepFor, StdOutput, Write, Start, Close};
DWORD WINAPI ReportThread(void* context) noexcept {
    const auto& state = *static_cast<const ReporterStorage*>(context);
    const ConsoleReportResult result = RunConsoleReporter(state.report, state.ops);
    return result.written ? ERROR_SUCCESS : result.error;
}
}
const ConsoleStatusOps& ProductionConsoleStatusOps() noexcept { return kOps; }

bool FormatConsoleStatus(const MarkerData& data, const MarkerWriteResult& marker,
                         ConsoleReportContext* output) noexcept {
    if (!output) return false;
    *output = {};
    if (static_cast<unsigned>(data.buildIdentity) > static_cast<unsigned>(BuildIdentity::Indeterminate) ||
        static_cast<unsigned>(data.mode) > static_cast<unsigned>(ReconMode::Active) ||
        static_cast<unsigned>(data.recon.outcome) > static_cast<unsigned>(ReconOutcome::Fatal) ||
        static_cast<unsigned>(data.recon.reason) > static_cast<unsigned>(FixReason::RollbackFailed)) return false;
    const char* host = BuildIdentityName(data.buildIdentity);
    const char* mode = ReconModeName(data.mode);
    const char* recon = ReconOutcomeName(data.recon.outcome);
    const char* reason = FixReasonName(data.recon.reason);
    for (const char* fragment : {host, mode, recon, reason})
        if (!fragment || strnlen_s(fragment, kMaxEnumFragment + 1) > kMaxEnumFragment) return false;
    const bool markerOk = marker.written && marker.finalError == ERROR_SUCCESS &&
        marker.cleanupError == ERROR_SUCCESS && data.complete;
    const bool accepted = markerOk && MarkerStateAccepted(data);
    const int size = std::snprintf(output->line, sizeof(output->line),
        "[RS2ServerFix] v%s loaded; host=%s; mode=%s; qualification=%s; recon=%s; "
        "fix=%s; reason=%s; marker=%s; acceptance=%s\r\n",
        RS2FIX_VERSION_ASCII, host, mode, data.recon.qualified ? "ready" : "rejected",
        recon, kReconFixId, reason, markerOk ? "complete" : "failed",
        accepted ? "passed" : "failed");
    if (size <= 0 || static_cast<std::size_t>(size) >= sizeof(output->line)) {
        *output = {};
        return false;
    }
    output->bytes = static_cast<DWORD>(size);
    return true;
}

ConsoleReportResult RunConsoleReporter(const ConsoleReportContext& report,
                                      const ConsoleStatusOps& ops) noexcept {
    ConsoleReportResult result{};
    result.error = ERROR_INVALID_PARAMETER;
    if (!ValidReport(report) || !ops.ticks || !ops.sleep || !ops.getStdOutput || !ops.write)
        return result;
    const ULONGLONG started = ops.ticks(ops.context);
    // The iteration bound also prevents a broken test clock from creating a wait.
    for (DWORD observation = 0; observation <= kConsoleOpportunityMs / kConsolePollMs; ++observation) {
        const ULONGLONG now = ops.ticks(ops.context);
        if (now < started) { result.error = ERROR_INVALID_DATA; return result; }
        const ULONGLONG elapsed = now - started;
        result.delayMs = elapsed > kConsoleOpportunityMs
            ? kConsoleOpportunityMs : static_cast<DWORD>(elapsed);
        if (elapsed >= kConsoleOpportunityMs || observation == kConsoleOpportunityMs / kConsolePollMs) {
            result.timedOut = true;
            result.error = ERROR_TIMEOUT;
            return result;
        }
        DWORD error = ERROR_SUCCESS;
        const HANDLE output = ops.getStdOutput(ops.context, &error);
        if (output && output != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            result.attempted = true;
            result.written = ops.write(ops.context, output, report.line, report.bytes, &written, &error);
            result.written = result.written && written == report.bytes;
            result.error = result.written ? ERROR_SUCCESS
                : (error == ERROR_SUCCESS ? ERROR_WRITE_FAULT : error);
            return result;
        }
        ops.sleep(ops.context, kConsolePollMs);
    }
    return result;
}

ReporterStartResult TryStartReporter(ReporterStorage* storage,
    const ConsoleReportContext& report, const ConsoleStatusOps& ops) noexcept {
    ReporterStartResult result{};
    result.error = ERROR_INVALID_PARAMETER;
    if (!storage || !ValidReport(report) || !ops.startThread || !ops.closeThread ||
        !ops.ticks || !ops.sleep || !ops.getStdOutput || !ops.write) return result;
    if (InterlockedCompareExchange(&storage->claimed, 1, 0) != 0) {
        result.error = ERROR_ALREADY_EXISTS;
        return result;
    }
    // The worker receives an owned value copy. Keep this storage claimed for
    // its lifetime; startup returns without joining the report-only thread.
    storage->report = report;
    storage->ops = ops;
    MemoryBarrier();
    const HANDLE thread = ops.startThread(ops.context, ReportThread, storage, &result.error);
    if (!thread || thread == INVALID_HANDLE_VALUE) {
        if (result.error == ERROR_SUCCESS) result.error = ERROR_NOT_ENOUGH_MEMORY;
        return result;
    }
    result.started = true;
    DWORD closeError = ERROR_SUCCESS;
    if (!ops.closeThread(ops.context, thread, &closeError))
        result.error = closeError == ERROR_SUCCESS ? ERROR_INVALID_HANDLE : closeError;
    else result.error = ERROR_SUCCESS;
    return result;
}
ReporterStartResult StartReporter(const ConsoleReportContext& report) noexcept {
    return TryStartReporter(&g_reporter, report, kOps);
}
}
