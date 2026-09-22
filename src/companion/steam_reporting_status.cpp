#include "companion/steam_reporting_status.h"
#include <Windows.h>
#include <cstring>
#include <limits>

#if !defined(_MSC_VER) || !defined(_M_X64)
#error Reporting payload release stores require the Windows MSVC AMD64 contract.
#endif

namespace rs2fix::reporting {
namespace {
volatile LONG64* Atomic(std::uint64_t& value) noexcept {
    return reinterpret_cast<volatile LONG64*>(&value);
}
std::uint64_t Mask(Reason reason) noexcept {
    const auto index = static_cast<std::size_t>(reason);
    return 1ULL << (index > 0 && index < kReasonCount ? index :
        static_cast<std::size_t>(Reason::StatusUnavailable));
}
void StorePayloadWord(std::uint64_t& destination, std::uint64_t word) noexcept {
    // Windows guarantees aligned 64-bit stores are atomic on AMD64. With the
    // pinned /volatile:ms contract, WriteRelease64 orders each payload store;
    // the unchanged interlocked odd/even sequence publishes the whole snapshot.
    // Only the sole-owner payload uses this path, never gates, latches or SPSC.
    WriteRelease64(Atomic(destination), static_cast<LONG64>(word));
}
static_assert(alignof(StatusWire)>=8 && offsetof(StatusWire,owner)%8==0 &&
    alignof(StatusPayload)>=8 && sizeof(StatusPayload)%8==0);
void StorePayload(StatusPayload& to, const StatusPayload& from) noexcept {
    // Use local memcpy for representation conversion. Atomic stores touch each
    // aligned live word, never bulk-copy over a concurrent reader.
    for (std::size_t offset = 0; offset < sizeof(to); offset += sizeof(std::uint64_t)) {
        std::uint64_t word{};
        std::memcpy(&word, reinterpret_cast<const unsigned char*>(&from) + offset, sizeof(word));
        auto* destination = reinterpret_cast<std::uint64_t*>(reinterpret_cast<unsigned char*>(&to) + offset);
        StorePayloadWord(*destination, word);
    }
}
void LoadPayload(const StatusPayload& from, StatusPayload& to) noexcept {
    for (std::size_t offset = 0; offset < sizeof(from); offset += sizeof(std::uint64_t)) {
        const auto* source = reinterpret_cast<const std::uint64_t*>(
            reinterpret_cast<const unsigned char*>(&from) + offset);
        const auto word = ReadStatusWord(*source);
        std::memcpy(reinterpret_cast<unsigned char*>(&to) + offset, &word, sizeof(word));
    }
}
bool AtMostMicroseconds(std::uint64_t ticks, std::uint64_t frequency,
    std::uint64_t micros) noexcept {
    // Compare rational values without ticks*1,000,000 overflow. Frequency is
    // bounded at initialization; the quotient/remainder construction is exact.
    const auto whole = frequency / 1000000;
    const auto rest = frequency % 1000000;
    const auto limit = whole * micros + (rest * micros) / 1000000;
    return ticks <= limit;
}
} // namespace

std::uint64_t ReadStatusWord(const std::uint64_t& value) noexcept {
    return static_cast<std::uint64_t>(InterlockedCompareExchange64(
        Atomic(const_cast<std::uint64_t&>(value)), 0, 0));
}
void StoreStatusWord(std::uint64_t& value, std::uint64_t desired) noexcept {
    InterlockedExchange64(Atomic(value), static_cast<LONG64>(desired));
}
bool InitializeStatus(StatusWire& wire, const StatusHeader& header,
    const StatusPayload& payload) noexcept {
    if (InterlockedCompareExchange64(Atomic(wire.headerReady), 2, 0) != 0) return false;
    wire.header = header;
    wire.header.magic = kStatusMagic;
    wire.header.schema = kStatusSchema;
    wire.header.bytes = sizeof(StatusWire);
    wire.header.artifactVersion = kReportingArtifactVersion;
    std::memset(wire.header.reserved, 0, sizeof(wire.header.reserved));
    // Header storage belongs to ReportingState, not a fallible logger object.
    StoreStatusWord(wire.ownerSequence, 1);
    StorePayload(wire.owner, payload);
    StoreStatusWord(wire.ownerSequence, 2);
    StoreStatusWord(wire.headerReady, 1);
    return true;
}
bool PublishStatus(StatusWire& wire, const StatusPayload& payload) noexcept {
    if (ReadStatusWord(wire.headerReady) != 1) return false;
    const auto sequence = ReadStatusWord(wire.ownerSequence);
    if ((sequence & 1) || sequence > (std::numeric_limits<std::uint64_t>::max)() - 2) {
        RevokeStatus(wire, Reason::CounterOverflow); return false;
    }
    // Only the startup/qualified owner writes this payload. Foreign fault paths
    // use separate interlocked latches, never this odd/even publication sequence.
    StoreStatusWord(wire.ownerSequence, sequence + 1);
    StorePayload(wire.owner, payload);
    StoreStatusWord(wire.ownerSequence, sequence + 2);
    return true;
}
void RevokeStatus(StatusWire& wire, Reason reason) noexcept {
    InterlockedOr64(Atomic(wire.revokeReasons), static_cast<LONG64>(Mask(reason)));
}
void LoseStatus(StatusWire& wire, Reason reason) noexcept {
    // Either word independently blocks admission/qualification. Set loss first
    // so no failure path needs a later queued record to become visible.
    InterlockedOr64(Atomic(wire.lossReasons), static_cast<LONG64>(Mask(reason)));
    RevokeStatus(wire, reason);
}
void StopStatus(StatusWire& wire, std::uint64_t qpc) noexcept {
    if (InterlockedCompareExchange64(Atomic(wire.stopping), 1, 0) == 0)
        StoreStatusWord(wire.stoppedQpc, qpc);
}
bool StatusRevoked(const StatusWire& wire) noexcept {
    return ReadStatusWord(wire.revokeReasons) != 0 || ReadStatusWord(wire.lossReasons) != 0 ||
        ReadStatusWord(wire.stopping) != 0;
}
bool ReadLocalStatus(const StatusWire& wire, StatusHeader* header, StatusPayload* payload) noexcept {
    if (!header || !payload) return false;
    *header = {}; *payload = {};
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        if (ReadStatusWord(wire.headerReady) != 1 || StatusRevoked(wire)) return false;
        const auto before = ReadStatusWord(wire.ownerSequence);
        if (before & 1) continue;
        const auto copyHeader = wire.header; // Immutable after release publication.
        StatusPayload copy{};
        LoadPayload(wire.owner, copy);
        const auto after = ReadStatusWord(wire.ownerSequence);
        if (StatusRevoked(wire)) return false;
        if (before != after || (after & 1)) continue;
        if (copyHeader.magic != kStatusMagic || copyHeader.schema != kStatusSchema ||
            copyHeader.bytes != sizeof(StatusWire) || copyHeader.artifactVersion != kReportingArtifactVersion)
            return false;
        *header = copyHeader; *payload = copy;
        return true;
    }
    return false;
}
bool IncrementCounter(std::uint64_t& value, std::uint64_t amount) noexcept {
    if (amount > (std::numeric_limits<std::uint64_t>::max)() - value) return false;
    value += amount;
    return true;
}
bool AccountDuration(DurationCounters& counters, std::uint64_t elapsed,
    std::uint64_t frequency) noexcept {
    if (!frequency || frequency > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) / 45)
        return false;
    constexpr std::uint64_t limits[]{10, 100, 1000, 5000, 50000};
    std::size_t bucket = 0;
    while (bucket < 5 && !AtMostMicroseconds(elapsed, frequency, limits[bucket])) ++bucket;
    const bool over = !AtMostMicroseconds(elapsed, frequency, 5000);
    // Owned local snapshot: reject overflow without publishing a partial metric.
    auto next = counters;
    if (!IncrementCounter(next.calls) || !IncrementCounter(next.elapsedTicks, elapsed) ||
        !IncrementCounter(next.buckets[bucket]) || (over && !IncrementCounter(next.overFiveMilliseconds))) return false;
    if (elapsed > next.maximumTicks) next.maximumTicks = elapsed;
    counters = next;
    return true;
}
} // namespace rs2fix::reporting
