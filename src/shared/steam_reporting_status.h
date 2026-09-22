#pragma once
#include <cstddef>
#include <cstdint>
#include <type_traits>

// Exact read-only wire contract shared by the companion and selected-PID tool.
// No pointer, native object, account identity or backend payload is exported.
namespace rs2fix::reporting {
inline constexpr std::uint64_t kStatusMagic = 0x3154505232535255ULL;
inline constexpr std::uint32_t kStatusSchema = 2;
inline constexpr std::uint32_t kReportingArtifactVersion = 0x00040100U; // 0.4.1.0
inline constexpr std::size_t kStatusReasonSlots = 64;
inline constexpr std::size_t kStatusDurationClasses = 4;
inline constexpr std::size_t kStatusDurationBuckets = 6;
enum HeaderValidity : std::uint32_t {
    ProcessIdentityValid = 1, RunIdentityValid = 2, ClockIdentityValid = 4,
    ConfigurationValid = 8, HostIdentityValid = 16,
    CompleteHeaderIdentity = 31
};
enum class ReportPhase : std::uint64_t {
    Uninitialized = 0, Initializing, Rejected, Prepared, AwaitingInit,
    Observing, Repairing, Stopping, Faulted
};
struct alignas(8) StatusHeader {
    std::uint64_t magic;
    std::uint32_t schema;
    std::uint32_t bytes;
    std::uint32_t artifactVersion;
    std::uint32_t configuredMode;
    std::uint32_t pid;
    std::uint32_t validity;
    std::uint64_t processCreation;
    std::uint64_t qpcFrequency;
    std::uint8_t runId[16];
    std::uint8_t hostDigest[32];
    std::uint64_t reserved[4];
};
struct DurationCounters {
    std::uint64_t calls;
    std::uint64_t elapsedTicks;
    std::uint64_t maximumTicks;
    std::uint64_t overFiveMilliseconds;
    // <=10us, <=100us, <=1ms, <=5ms, <=50ms, above50ms.
    std::uint64_t buckets[kStatusDurationBuckets];
};
struct StatusPayload {
    std::uint64_t phase;
    std::uint64_t reason;
    std::uint64_t ownerThreadId;
    std::uint64_t sourceEpoch;
    std::uint64_t bindingEpoch;
    std::uint64_t lastOwnerQpc;
    std::uint64_t lastManagementQpc;
    std::uint64_t lastBuilderQpc;
    std::uint64_t readyQpc;
    std::uint64_t pendingSinceQpc;
    std::uint64_t freshSinceQpc;
    std::uint64_t requestSequence;
    std::uint64_t witnessSequence;
    std::uint64_t buildSequence;
    std::uint64_t pending;
    std::uint64_t fresh;
    std::uint64_t pi;
    std::uint64_t bots;
    std::uint64_t maximum;
    std::uint64_t normalAttempts;
    std::uint64_t fullSelected;
    std::uint64_t selectedTrue;
    std::uint64_t normalReturns;
    std::uint64_t falseReturns;
    std::uint64_t nativeUnwinds;
    std::uint64_t managementCalls;
    std::uint64_t normalPumpClassifications;
    std::uint64_t normalBuilderClassifications;
    std::uint64_t builderBound;
    std::uint64_t reportSequence;
    std::uint64_t lastSelectedWitness;
    std::uint64_t distinctSelectedWitnesses;
    std::uint64_t reasons[kStatusReasonSlots];
    DurationCounters durations[kStatusDurationClasses];
    // Last committed top-level invocation's entry, not owner liveness.
    std::uint64_t timingAccountedThroughQpc;
};
struct alignas(8) StatusWire {
    StatusHeader header;
    // 0 uninitialized, 2 initializing, 1 final immutable header published.
    std::uint64_t headerReady;
    std::uint64_t ownerSequence;
    // These multiwriter sticky words are OUTSIDE the owner-only sequence.
    std::uint64_t revokeReasons;
    std::uint64_t lossReasons;
    std::uint64_t stopping;
    std::uint64_t stoppedQpc;
    std::uint64_t recordsWritten;
    std::uint64_t lastFlushedSequence;
    StatusPayload owner;
};
static_assert(sizeof(StatusHeader) == 128 && alignof(StatusHeader) == 8);
static_assert(sizeof(DurationCounters) == 80);
static_assert(sizeof(StatusPayload) == 1096);
static_assert(offsetof(StatusWire, headerReady) == 128 && offsetof(StatusWire, owner) == 192);
static_assert(sizeof(StatusWire) == 1288 && sizeof(StatusWire) <= 4096);
static_assert(std::is_trivial_v<StatusWire> && std::is_standard_layout_v<StatusWire>);
} // namespace rs2fix::reporting
