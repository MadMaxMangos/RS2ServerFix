#pragma once
#include "shared/bootstrap_abi.h"

namespace rs2fix {
enum class InitializationClaim : std::uint32_t { Claimed, Running, Finished };
DWORD ValidateBootstrapContextV3(const BootstrapContextV3* context) noexcept;
InitializationClaim ClaimInitialization(LONG volatile* state) noexcept;
struct MarkerData;
struct MarkerWriteResult;
struct MarkerFileOps;
struct ConsoleStatusOps;
// Best effort only. The caller MUST fail fast after this returns. The console
// adapter supplies an already-ready console; no polling or thread is permitted.
bool TryReportFatalInitialization(const wchar_t* primaryDirectory,
    const wchar_t* fallbackDirectory, const MarkerData& data,
    MarkerWriteResult* writeResult, const MarkerFileOps& markerOps,
    const ConsoleStatusOps& readyConsoleOps) noexcept;
DWORD RunCompanionInitialization(const BootstrapContextV3& context,
    LONG volatile* state) noexcept;
} // namespace rs2fix
