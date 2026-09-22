#pragma once

#include "companion/steam_reporting_status.h"
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace rs2fix::reporting {
inline constexpr std::uint32_t kReportRecordSchema=2;
inline constexpr std::size_t kReportRecordCapacity=256;
inline constexpr std::size_t kReportBatchLimit=32;

enum class RecordKind : std::uint32_t {
    State=1, Request, Witness, BuilderEnter, BuilderReturn, BuilderUnwind, Anchor, Count
};
struct ReportHeader {
    std::uint64_t sequence;
    std::uint64_t qpc;
    std::uint64_t sourceEpoch;
    std::uint64_t bindingEpoch;
    std::uint32_t kind;
    std::uint32_t reason;
    std::uint32_t flags;
    std::uint32_t threadId;
};
struct ReportStatePayload {
    std::uint64_t phase;
    std::uint64_t requestSequence;
    std::uint64_t witnessSequence;
    std::uint64_t buildSequence;
    std::uint64_t pendingSinceQpc;
    std::uint64_t freshSinceQpc;
    std::uint64_t qualificationFlags;
    std::uint64_t nativeTaskState;
    std::uint32_t mode;
    std::uint32_t classification;
    std::uint32_t pi;
    std::uint32_t bots;
    std::uint32_t maximum;
    std::uint32_t pending;
    std::uint32_t fresh;
    std::uint32_t bound;
    // One-time cold qualification duration, separate from hot-path QPC costs.
    std::uint64_t clientQualificationMs;
    // Rechecked task/metadata scalars, not a current-due or wall-clock claim.
    // Signed native values are carried as raw bits; no addresses are recorded.
    // All added fields are zero when no stable schedule observation is present.
    std::uint64_t nativeScheduleValid;
    std::uint64_t nativeScheduleAnchorBits;
    std::uint64_t nativeErrorsBits;
    std::uint64_t nativeThrottlesBits;
    std::uint64_t nativeExpedite;
    std::uint64_t nativeRetryLimit;
    std::uint64_t nativeIntervalUnits;
    std::uint64_t nativeIntervalOverrideBits;
    std::uint64_t nativeRetryOverrideBits;
    std::uint64_t nativeDelayUnits;
    // 0 unknown; 1 poll; 2 retry base; 3/4/5/6 retry 30s/60s/5m/30m.
    std::uint64_t nativeTier;
    std::uint64_t reserved[2];
};
struct ReportRequestPayload {
    std::uint64_t requestSequence;
    std::uint64_t witnessSequence;
    std::uint64_t stagedQpc;
    std::uint64_t previousSampleQpc;
    std::uint64_t observedQpc;
    std::uint64_t freshSinceQpc;
    std::uint64_t sourceAgeTicks;
    std::uint32_t pi;
    std::uint32_t bots;
    std::uint32_t maximum;
    std::uint32_t stagedBots;
    std::uint32_t humanPlayers;
    std::uint32_t worldBots;
    std::uint32_t classification;
    std::uint32_t pending;
    std::uint64_t reserved[15];
};
struct ReportBuilderPayload {
    std::uint64_t buildSequence;
    std::uint64_t requestSequence;
    std::uint64_t witnessSequence;
    std::uint64_t sourceAgeTicks;
    // Probe cost excludes later record publication/status accounting. The
    // classification value is a non-additive subset of probe cost; completed
    // total wrapper-own durations belong in Status/Anchor metrics.
    std::uint64_t probeElapsedTicks;
    std::uint64_t classificationElapsedTicks;
    std::uint64_t originalElapsedTicks;
    std::uint64_t entryQpc;
    std::uint64_t returnQpc;
    std::uint32_t pi;
    std::uint32_t bots;
    std::uint32_t maximum;
    std::uint32_t classification;
    std::uint32_t selected;
    std::uint32_t result;
    std::uint32_t pending;
    std::uint32_t fresh;
    std::uint64_t reserved[13];
};
struct ReportDurationSummary {
    std::uint64_t calls;
    std::uint64_t elapsedTicks;
    std::uint64_t maximumTicks;
    std::uint64_t overFiveMilliseconds;
};
struct ReportAnchorPayload {
    std::uint64_t normalAttempts;
    std::uint64_t fullSelected;
    std::uint64_t selectedTrue;
    std::uint64_t normalReturns;
    std::uint64_t falseReturns;
    std::uint64_t nativeUnwinds;
    std::uint64_t requestSequence;
    std::uint64_t witnessSequence;
    std::uint64_t buildSequence;
    std::uint64_t distinctSelectedWitnesses;
    ReportDurationSummary durations[kStatusDurationClasses];
};
union ReportPayload {
    ReportStatePayload state;
    ReportRequestPayload request;
    ReportBuilderPayload builder;
    ReportAnchorPayload anchor;
};
struct alignas(8) ReportRecord { ReportHeader header; ReportPayload payload; };
static_assert(sizeof(ReportHeader)==48 && offsetof(ReportHeader,kind)==32);
static_assert(offsetof(ReportHeader,threadId)==44 && offsetof(ReportRecord,payload)==48);
static_assert(sizeof(ReportStatePayload)==208 && sizeof(ReportRequestPayload)==208);
static_assert(offsetof(ReportStatePayload,nativeScheduleValid)==104 &&
    offsetof(ReportStatePayload,nativeTier)==184 && offsetof(ReportStatePayload,reserved)==192);
static_assert(sizeof(ReportBuilderPayload)==208 && sizeof(ReportAnchorPayload)==208);
static_assert(sizeof(ReportPayload)==208 && sizeof(ReportRecord)==256 && alignof(ReportRecord)==8);
static_assert(kReportBatchLimit*sizeof(ReportRecord)==8192);
static_assert(std::is_trivial_v<ReportRecord> && std::is_standard_layout_v<ReportRecord> &&
    std::is_trivially_copyable_v<ReportRecord>);

// These pointers are private process-resident context, NEVER record fields or
// exported status. Context is immutable after ready release-publication. One
// qualified startup/owner produces; exactly one existing writer consumes.
struct alignas(8) ReportRing {
    StatusWire* status;
    std::uint32_t ownerThreadId;
    std::uint32_t reserved;
    std::uint64_t ready;
    std::uint64_t reportWriteSequence;
    std::uint64_t reportReadSequence;
    ReportRecord slots[kReportRecordCapacity];
};
static_assert(offsetof(ReportRing,ready)%8==0 && offsetof(ReportRing,reportWriteSequence)%8==0 &&
    offsetof(ReportRing,reportReadSequence)%8==0 && offsetof(ReportRing,slots)%8==0);
static_assert(sizeof(ReportRing::slots)==65536 && std::is_trivial_v<ReportRing>);
enum class ReportWriteResult : std::uint32_t { Accepted, Stopping, Revoked, Unavailable, Lost };
enum class ReportReadResult : std::uint32_t { Record, Empty, Unavailable, Lost };
struct ReportSink {
    void* context;
    bool (*publish)(void*, const ReportRecord&, std::uint64_t* acceptedSequence) noexcept;
};

// Initialize exclusively owned, zeroed, unpublished storage once. Never resets
// an active ring or clears any status fault. The ring/status outlive all users.
bool InitializeReportRing(ReportRing&, StatusWire&, std::uint32_t ownerThreadId) noexcept;
// Input sequence MUST be zero (unassigned). Ring assigns sequence/threadId and
// canonicalizes declared fields only; reserved bytes cannot enter evidence.
// acceptedSequence is required caller-owned storage; zero on every rejection.
ReportWriteResult EnqueueReport(ReportRing&, const ReportRecord&,
    std::uint64_t* acceptedSequence) noexcept;
// Output is caller-owned, not a ring slot. Prior records remain drainable after
// stopping/fault. Worker copies and scrubs a slot before release-publishing reuse.
ReportReadResult DequeueReport(ReportRing&, ReportRecord*) noexcept;
ReportSink ReportRingSink(ReportRing&) noexcept;
} // namespace rs2fix::reporting
