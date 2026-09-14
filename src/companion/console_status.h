#pragma once
#include "companion/marker.h"
#include <type_traits>

namespace rs2fix {
inline constexpr std::size_t kConsoleLineCapacity = 384;
inline constexpr DWORD kConsolePollMs = 100;
inline constexpr DWORD kConsoleOpportunityMs = 30000;

struct ConsoleReportContext {
    char line[kConsoleLineCapacity];
    DWORD bytes;
};
static_assert(std::is_trivial_v<ConsoleReportContext> &&
    std::is_standard_layout_v<ConsoleReportContext>);

struct ConsoleStatusOps {
    void* context;
    ULONGLONG (*ticks)(void*) noexcept;
    void (*sleep)(void*, DWORD) noexcept;
    HANDLE (*getStdOutput)(void*, DWORD*) noexcept;
    bool (*write)(void*, HANDLE, const void*, DWORD, DWORD*, DWORD*) noexcept;
    HANDLE (*startThread)(void*, LPTHREAD_START_ROUTINE, void*, DWORD*) noexcept;
    bool (*closeThread)(void*, HANDLE, DWORD*) noexcept;
};
const ConsoleStatusOps& ProductionConsoleStatusOps() noexcept;

struct ConsoleReportResult {
    bool attempted{};
    bool written{};
    bool timedOut{};
    DWORD delayMs{};
    DWORD error{};
};
struct ReporterStartResult {
    bool started{};
    DWORD error{};
};

bool FormatConsoleStatus(const MarkerData& data, const MarkerWriteResult& marker,
    ConsoleReportContext* output) noexcept;
ConsoleReportResult RunConsoleReporter(const ConsoleReportContext& report,
    const ConsoleStatusOps& ops) noexcept;

// Production copies into static POD storage. The companion loader retains the
// module until process exit, and this is invoked only after the terminal marker.
ReporterStartResult StartReporter(const ConsoleReportContext& report) noexcept;

// Narrow scheduling seam: tests own this storage for the entire callback lifetime.
// Production supplies only the static storage and the constexpr Win32 adapter.
struct ReporterStorage {
    volatile LONG claimed;
    ConsoleReportContext report;
    ConsoleStatusOps ops;
};
static_assert(std::is_trivial_v<ReporterStorage> && std::is_standard_layout_v<ReporterStorage>);
ReporterStartResult TryStartReporter(ReporterStorage* storage,
    const ConsoleReportContext& report, const ConsoleStatusOps& ops) noexcept;
}
