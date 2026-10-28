#pragma once
#include "companion/steam_reporting_records_v3.h"
#include "companion/steam_reporting_profile.h"

namespace rs2fix::reporting {
struct NativeStartupSummary {
    std::uint32_t buildIdentity;
    std::uint32_t reconMode;
    std::uint32_t reconOutcome;
    std::uint32_t reconReason;
    std::uint32_t reconQualified;
    std::uint32_t initializeResult;
    std::uint32_t markerComplete;
    std::uint32_t markerError;
    std::uint32_t startupAccepted;
};
struct NativeFormatContext {
    StatusHeader header;
    LogIdentity log;
    ConfigV3 config;
    ReportingIdentities identities;
    NativeStartupSummary startup;
};
// Bracket-midpoint estimate, with the original calibration retained in the
// bootstrap. Integer arithmetic is checked; QPC remains authoritative.
bool DeriveUtcFiletime(const LogIdentity&, std::uint64_t frequency,
    std::uint64_t sourceQpc, std::uint64_t* utc) noexcept;
// Worker-only formatting into caller-owned fixed storage. Frames include the
// marker but no native prefix or CRLF. Failure clears output and byte count.
bool FormatNativeBootstrap(const NativeFormatContext&, char*, std::size_t capacity,
    std::size_t* bytes) noexcept;
// Pre-admission gate: called before publishing identity/ready/bootstrap. A path
// whose escaped metadata does not fit is unsupported, not an admitted-record
// loss. Outputs can be retained as the exact bootstrap receipt and ready frame.
TransportReason PrepareNativeBootstrap(const NativeFormatContext&,char*,std::size_t,
    wchar_t*,std::size_t,std::size_t* bytes) noexcept;
bool FormatNativeRecord(const NativeFormatContext&, const ReportRecordV3&,
    char*, std::size_t capacity, std::size_t* bytes, bool recoveryDetail = false) noexcept;
} // namespace rs2fix::reporting
