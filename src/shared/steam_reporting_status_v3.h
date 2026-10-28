#pragma once
#include "shared/steam_reporting_status.h"

// Native-log reporting has a separate wire, never a larger object exported as
// RS2SteamReport_StatusV2. During migration the unchanged V2 definitions above
// remain in use by the legacy runtime/tools. Only the header and owner payload
// shapes are shared; offsets, publication protocol and artifact identity differ.
namespace rs2fix::reporting {
inline constexpr std::uint32_t kStatusSchemaV3 = 3;
inline constexpr std::uint32_t kReportingArtifactVersionV3 = 0x00070100U;
inline constexpr std::uint64_t kRuntimeReasonCountV3 = 59;

// A separate domain: temporary transport refusals must never become bits in
// the existing runtime Reason mask or consume entries in its reasons[64].
enum class TransportReason : std::uint64_t {
    None = 0, AwaitingLogger, CategorySuppressed, ForceFlushMissing,
    FramingUnsupported, SinkUnsupported, FileManagerUnsupported,
    ReceiptUnavailable, ReaderBehind, ReceiptOverdue, CreditPressure,
    SameFileRequalification, ReceiptGap, ReceiptCorrupt, FileIdentityChanged,
    FileTruncated, ProfileUnsafe, NativeLogException, Count
};
enum class TransportState : std::uint64_t {
    WaitingLogger = 0, Running, Paused, Faulted, Stopping
};
enum class ReportPhaseV3 : std::uint64_t {
    Uninitialized = 0, Initializing, Rejected, Prepared, AwaitingInit,
    Observing, Repairing, Stopping, Faulted, WaitingLogger, Paused
};

struct OwnerTransport {
    std::uint64_t state;
    std::uint64_t reason;
    std::uint64_t startupSubmitted;
    // Diagnostic permission, not a replacement for the request/witness gates.
    std::uint64_t actualRepairAdmitted;
    std::uint64_t generatedSequence;
    std::uint64_t submittedSequence;
    std::uint64_t pauseEpoch;
    std::uint64_t pauseBoundarySequence;
    std::uint64_t transitionSequence;
    std::uint64_t transitionQpc;
    std::uint64_t forwardedPumpWithoutCapture;
    std::uint64_t forwardedBuilderWithoutCapture;
    std::uint64_t reservedCredits;
    std::uint64_t submitWindowStartQpc;
    std::uint64_t submitWindowCount;
    // A non-additive subset of the existing inclusive own-time duration classes.
    std::uint64_t nativeSubmitCalls;
    std::uint64_t nativeSubmitElapsedTicks;
    std::uint64_t nativeSubmitMaximumTicks;
    std::uint64_t nativeSubmitOverFiveMilliseconds;
    std::uint64_t lastNativeSubmitQpc;
    std::uint64_t qualifiedSinkEpoch;
    std::uint64_t reserved;
};
struct WorkerTransport {
    std::uint64_t startupObserved;
    std::uint64_t preparedSequence;
    std::uint64_t observedSequence;
    std::uint64_t lastReceiptQpc;
    std::uint64_t readerOffset;
    std::uint64_t partialBytes;
    std::uint64_t ledgerDepth;
    std::uint64_t readyDepth;
    std::uint64_t ringReadSequence;
    std::uint64_t readCycles;
    std::uint64_t readBytes;
    std::uint64_t formatCalls;
    std::uint64_t formatTicks;
    std::uint64_t receiptTicks;
    std::uint64_t pauseReason;
    std::uint64_t pauseConditionSequence;
    std::uint64_t pauseConditionQpc;
    std::uint64_t lastReadError;
    std::uint64_t matchedAwaitingSubmitSequence;
    std::uint64_t reserved;
};
struct ConsoleDiagnostics {
    std::uint64_t attempts;
    std::uint64_t written;
    std::uint64_t failures;
    std::uint64_t lastError;
    std::uint64_t lastAttemptQpc;
    std::uint64_t lastNoticeEpoch;
    std::uint64_t skippedTransitions;
    std::uint64_t workerState;
};
struct LogIdentity {
    std::uint64_t volumeSerial;
    std::uint8_t fileId[16];
    std::uint64_t initialEOF;
    std::uint64_t pathChars;
    std::uint64_t prefixMode;
    std::uint64_t transportKind;
    std::uint64_t durability;
    std::uint64_t utcFiletime;
    std::uint64_t calibrationQpcBefore;
    std::uint64_t calibrationQpcAfter;
    std::uint64_t initialAtLineBoundary;
    std::uint16_t path[1024];
};
struct alignas(8) StatusWireV3 {
    StatusHeader header;
    std::uint64_t headerReady;
    std::uint64_t ownerSequence;
    std::uint64_t workerSequence;
    std::uint64_t consoleSequence;
    std::uint64_t logIdentityReady;
    std::uint64_t revokeReasons;
    std::uint64_t lossReasons;
    std::uint64_t stopping;
    std::uint64_t stoppedQpc;
    // Clearable, worker-owned gate; not a sticky loss or revoke word.
    std::uint64_t workerPauseReason;
    std::uint64_t fatalTransportReason;
    std::uint64_t reserved[5];
    StatusPayload owner;
    OwnerTransport ownerTransport;
    WorkerTransport worker;
    ConsoleDiagnostics console;
    // Immutable once logIdentityReady is release-published as 1. Same-file
    // archive reopen must not reset its identity, initial offset or calibration.
    LogIdentity log;
};

static_assert(static_cast<std::uint64_t>(TransportReason::Count) == 18);
static_assert(static_cast<std::uint64_t>(ReportPhaseV3::Faulted) ==
    static_cast<std::uint64_t>(ReportPhase::Faulted));
static_assert(static_cast<std::uint64_t>(ReportPhaseV3::WaitingLogger) == 9);
static_assert(static_cast<std::uint64_t>(ReportPhaseV3::Paused) == 10);
static_assert(sizeof(OwnerTransport) == 176 && sizeof(WorkerTransport) == 160);
static_assert(sizeof(ConsoleDiagnostics) == 64 && sizeof(LogIdentity) == 2144);
static_assert(offsetof(OwnerTransport, nativeSubmitCalls) == 120);
static_assert(offsetof(OwnerTransport, qualifiedSinkEpoch) == 160);
static_assert(offsetof(WorkerTransport, pauseReason) == 112);
static_assert(offsetof(WorkerTransport, matchedAwaitingSubmitSequence) == 144);
static_assert(offsetof(LogIdentity, fileId) == 8 && offsetof(LogIdentity, initialEOF) == 24);
static_assert(offsetof(LogIdentity, initialAtLineBoundary) == 88);
static_assert(offsetof(LogIdentity, path) == 96);
static_assert(offsetof(StatusWireV3, headerReady) == 128);
static_assert(offsetof(StatusWireV3, ownerSequence) == 136);
static_assert(offsetof(StatusWireV3, workerSequence) == 144);
static_assert(offsetof(StatusWireV3, consoleSequence) == 152);
static_assert(offsetof(StatusWireV3, logIdentityReady) == 160);
static_assert(offsetof(StatusWireV3, revokeReasons) == 168);
static_assert(offsetof(StatusWireV3, lossReasons) == 176);
static_assert(offsetof(StatusWireV3, stopping) == 184);
static_assert(offsetof(StatusWireV3, stoppedQpc) == 192);
static_assert(offsetof(StatusWireV3, workerPauseReason) == 200);
static_assert(offsetof(StatusWireV3, fatalTransportReason) == 208);
static_assert(offsetof(StatusWireV3, reserved) == 216);
static_assert(offsetof(StatusWireV3, owner) == 256);
static_assert(offsetof(StatusWireV3, ownerTransport) == 1352);
static_assert(offsetof(StatusWireV3, worker) == 1528);
static_assert(offsetof(StatusWireV3, console) == 1688);
static_assert(offsetof(StatusWireV3, log) == 1752);
static_assert(sizeof(StatusWireV3) == 3896 && sizeof(StatusWireV3) <= 4096);
static_assert(alignof(StatusWireV3) == 8 && std::is_trivial_v<StatusWireV3> &&
    std::is_standard_layout_v<StatusWireV3> && std::is_trivially_copyable_v<StatusWireV3>);
} // namespace rs2fix::reporting
