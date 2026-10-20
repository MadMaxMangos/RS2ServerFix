#pragma once
#include "companion/steam_reporting_records.h"
#include "shared/steam_reporting_status_v3.h"
#include "shared/leech_recovery_status.h"

// Staged V3 contract. Do not enqueue these through the legacy V2 ring: its
// canonicalizer and consumers intentionally know only their original kinds.
namespace rs2fix::reporting {
inline constexpr std::uint32_t kReportRecordSchemaV3 = 3;
enum class RecordKindV3 : std::uint32_t {
    State = 1, Request, Witness, BuilderEnter, BuilderReturn, BuilderUnwind,
    Anchor, TransportSummary, Control, Recovery = 10, Count = 11
};
struct ReportTransportSummaryPayload {
    std::uint64_t anchorSequence;
    std::uint64_t nativeSubmitCalls;
    std::uint64_t nativeSubmitElapsedTicks;
    std::uint64_t nativeSubmitMaximumTicks;
    std::uint64_t nativeSubmitOverFiveMilliseconds;
    std::uint64_t forwardedPumpWithoutCapture;
    std::uint64_t forwardedBuilderWithoutCapture;
    std::uint64_t transportState;
    std::uint64_t transportReason;
    std::uint64_t pauseEpoch;
    std::uint64_t pauseBoundarySequence;
    // These are the paired anchor's pre-submission snapshot, not receipts for
    // the anchor/summary itself or a claim to cover the current in-flight call.
    std::uint64_t submittedSequence;
    std::uint64_t observedSequence;
    std::uint64_t timingAccountedThroughQpc;
    std::uint64_t generatedSequence;
    std::uint64_t reserved[11];
};
struct ReportControlPayload {
    std::uint64_t event;
    std::uint64_t transportState;
    std::uint64_t transportReason;
    std::uint64_t pauseEpoch;
    std::uint64_t pauseBoundarySequence;
    std::uint64_t abandonedPendingRequest;
    std::uint64_t abandonedWitness;
    std::uint64_t lastRequestQpc;
    std::uint64_t generatedBefore;
    std::uint64_t submittedBefore;
    std::uint64_t observedBefore;
    std::uint64_t forwardedPumpWithoutCapture;
    std::uint64_t forwardedBuilderWithoutCapture;
    std::uint64_t timingAccountedThroughQpc;
    std::uint64_t reserved[12];
};
union ReportPayloadV3 {
    ReportStatePayload state;
    ReportRequestPayload request;
    ReportBuilderPayload builder;
    ReportAnchorPayload anchor;
    ReportTransportSummaryPayload transport;
    ReportControlPayload control;
    ReportRecoveryPayload recovery;
};
struct alignas(8) ReportRecordV3 { ReportHeader header; ReportPayloadV3 payload; };
struct alignas(8) ReportRingV3 {
    StatusWireV3* status;
    std::uint32_t ownerThreadId;
    std::uint32_t reserved;
    std::uint64_t ready;
    std::uint64_t reportWriteSequence;
    std::uint64_t reportReadSequence;
    ReportRecordV3 slots[kReportRecordCapacity];
};
struct ReportSinkV3 {
    void* context;
    bool (*publish)(void*, const ReportRecordV3&, std::uint64_t* acceptedSequence) noexcept;
};
bool InitializeReportRing(ReportRingV3&, StatusWireV3&, std::uint32_t ownerThreadId) noexcept;
ReportWriteResult EnqueueReport(ReportRingV3&, const ReportRecordV3&, std::uint64_t*) noexcept;
ReportReadResult DequeueReport(ReportRingV3&, ReportRecordV3*) noexcept;
ReportSinkV3 ReportRingSink(ReportRingV3&) noexcept;
static_assert(static_cast<std::uint32_t>(RecordKindV3::Anchor) ==
    static_cast<std::uint32_t>(RecordKind::Anchor));
static_assert(static_cast<std::uint32_t>(RecordKindV3::TransportSummary) == 8);
static_assert(static_cast<std::uint32_t>(RecordKindV3::Control) == 9);
static_assert(static_cast<std::uint32_t>(RecordKindV3::Recovery) == 10);
static_assert(static_cast<std::uint32_t>(RecordKindV3::Count) == 11);
static_assert(sizeof(ReportTransportSummaryPayload) == 208 && sizeof(ReportControlPayload) == 208);
static_assert(offsetof(ReportTransportSummaryPayload, transportReason) == 64);
static_assert(offsetof(ReportTransportSummaryPayload, reserved) == 120);
static_assert(offsetof(ReportControlPayload, timingAccountedThroughQpc) == 104);
static_assert(offsetof(ReportControlPayload, reserved) == 112);
static_assert(sizeof(ReportPayloadV3) == 208 && offsetof(ReportRecordV3, payload) == 48);
static_assert(sizeof(ReportRecordV3) == 256 && alignof(ReportRecordV3) == 8);
static_assert(kReportBatchLimit * sizeof(ReportRecordV3) == 8192);
static_assert(kReportRecordCapacity * sizeof(ReportRecordV3) == 65536);
static_assert(sizeof(ReportRingV3::slots) == 65536 && offsetof(ReportRingV3, slots) % 8 == 0);
static_assert(std::is_trivial_v<ReportRecordV3> && std::is_standard_layout_v<ReportRecordV3> &&
    std::is_trivially_copyable_v<ReportRecordV3>);
} // namespace rs2fix::reporting
