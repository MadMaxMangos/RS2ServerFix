#pragma once
#include "companion/steam_reporting_format_v3.h"
#include "companion/steam_reporting_receipts.h"
#include "companion/steam_reporting_status_v3.h"

namespace rs2fix::reporting {
inline constexpr std::size_t kNativeLedgerCapacity=256;
inline constexpr std::size_t kNativeReadyCapacity=8;
struct NativeHashOps {
    void* context;
    // Prepared SHA-256 provider/object owned by the sole receipt worker.
    bool (*digest)(void*,const void*,std::size_t,Sha256Digest*) noexcept;
};
enum class LedgerState : std::uint32_t { Empty, Reserved, Scalar, Ready, Matched };
struct NativeLedgerEntry {
    std::uint64_t sequence;
    std::uint64_t preparedQpc;
    std::uint32_t messageBytes;
    LedgerState state;
    union { ReportRecordV3 scalar; Sha256Digest digest; } body;
};
struct NativeReadyFrame {
    std::uint64_t ticket;
    std::uint64_t sequence;
    std::uint32_t ledgerIndex;
    std::uint32_t chars;
    wchar_t message[native_log::kMessageLimit+1];
};
// Allocate once, zeroed, before hook admission; retain for process lifetime if
// any callback can still access it. Worker owns all except readyRead (owner).
// readyWrite/readyRead transfer slot ownership with interlocked publication.
// Nothing in this primitive authorizes an engine call, chooses cadence or opens
// a file; the integrating worker/owner adapter must enforce those gates.
struct alignas(8) NativePipeline {
    StatusWireV3* status;
    ReportRingV3* ring;
    NativeHashOps hash;
    NativeFormatContext format;
    std::uint64_t readyWrite;
    std::uint64_t readyRead;
    std::uint64_t ledgerRead;
    std::uint64_t ledgerWrite;
    std::uint64_t nextFormat;
    std::uint64_t preparedSequence;
    std::uint64_t observedSequence;
    std::uint64_t startupObserved;
    std::uint64_t heldMatch;
    std::uint64_t initialized;
    // Worker-private formatting state only; no owner admission or record selection.
    bool recoveryDetail,terminalDetailSeen,builderDetailActive,builderDetail,builderPostBoundary;
    std::uint32_t detailBoundaryPairs;
    std::uint64_t detailBuildSequence,detailSourceEpoch,detailBindingEpoch,detailOverallDeadlineQpc;
    std::size_t bootstrapBytes;
    char bootstrap[native_log::kMessageLimit+1];
    char scratch[native_log::kMessageLimit+1];
    NativeLedgerEntry ledger[kNativeLedgerCapacity];
    NativeReadyFrame ready[kNativeReadyCapacity];
};
static_assert(sizeof(NativeLedgerEntry)<=384);
static_assert(std::is_trivial_v<NativePipeline> && std::is_standard_layout_v<NativePipeline>);
// Single worker initialization, after qualified file identity, before native
// submission. A rejected bootstrap is temporary FramingUnsupported, not loss.
TransportReason InitializeNativePipeline(NativePipeline&,StatusWireV3&,ReportRingV3&,
    const NativeFormatContext&,const NativeHashOps&,std::uint64_t qpc) noexcept;
// Worker: reserve ledger homes BEFORE destructive dequeue, then format into
// available ready slots. Does not publish fabricated owner-generated counters.
bool PrepareNativeFrames(NativePipeline&,std::uint64_t qpc) noexcept;
// Owner: acquire front immutable slot. The owner adapter must additionally
// require startupObserved before submitting any positive sequence. This queue
// primitive is not the lifecycle/service-admission gate.
// Release ONLY after normal native return
// and its owner-local submitted watermark update; no release on exception.
const NativeReadyFrame* PeekNativeFrame(NativePipeline&) noexcept;
bool ReleaseNativeFrame(NativePipeline&,std::uint64_t ticket) noexcept;
// Worker callback for the run-scoped scanner. A full match is held until a
// coherent owner submission authorizes acknowledgement. It never reads native
// objects or treats the mere presence of file bytes as a completed submission.
ReceiptDisposition MatchNativeReceipt(void*,const char*,std::size_t) noexcept;
bool AcknowledgeNativeReceipt(NativePipeline&,const OwnerSnapshotV3&) noexcept;
} // namespace rs2fix::reporting
