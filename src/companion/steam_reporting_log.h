#pragma once

#if defined(RS2_STEAM_REPORTING)
#include "companion/steam_observer_log.h"
#include "companion/steam_reporting_records.h"

namespace rs2fix::reporting {
// Startup-only. Header/ring are already initialized and remain resident. The
// writer copies the immutable identity; it never generates another run ID/key.
// Dispatch storage may still be preparing; its optional EventSink stays unset.
observer::Writer* PrepareReportingWriter(const wchar_t* directory, std::uint32_t quotaMiB,
    StatusWire&, ReportRing&, observer::DispatchState&, Reason*, DWORD*) noexcept;
ReportSink GetReportingWriterSink(observer::Writer*) noexcept;
void ArmReportingWriter(observer::Writer*) noexcept;
// Startup/shutdown scheduling API, not a hook API. Hooks publish StopStatus;
// the existing worker observes it without any per-hook event/thread operation.
void StopReportingWriter(observer::Writer*) noexcept;
// Hook-safe: requests only, with no formatting, I/O, thread start or wake-up.
void RequestReportingNotice(observer::Writer*, bool ready, Reason) noexcept;
// No-writer startup rejection/fault-completion path only. Immutable header may
// have incomplete identity; the notice explicitly labels that unavailable.
void ScheduleReportingDisabledNotice(const StatusWire&, Reason) noexcept;

#if defined(RS2_OBSERVER_TESTING)
observer::Writer* PrepareReportingWriterForTest(const wchar_t*, StatusWire&, ReportRing&,
    observer::DispatchState&, const observer::WriterTestOptions&, Reason*, DWORD*) noexcept;
#endif
} // namespace rs2fix::reporting
#endif
