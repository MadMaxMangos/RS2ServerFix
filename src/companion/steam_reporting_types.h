#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

// Reporting has its own versioned vocabulary. Never extend the observer's
// 64-bit reason mask or reuse its Steam identity fields for reporting data.
namespace rs2fix::reporting {
enum class Mode : std::uint32_t { Invalid = 0, Disabled, Observe, Repair };
enum class Reason : std::uint32_t {
    None = 0, ConfigMissing, ConfigDisabled, ConfigInvalid, ObserverRequired,
    ReconIneligible, HostMismatch, SdkMismatch, SteamClientMismatch,
    ProfileMismatch, PreparationFailed, IdentityIncomplete, ClockFailed,
    CounterOverflow, ForeignThread, UnknownAncestry, TruncatedStack, Reentry,
    LifecycleCrossing, InitFailed, UnsupportedReinit, Stopping,
    SourceUnavailable, SourceLifetime, SourceClass, WorldNotReady, Travel,
    UnsupportedCounts, WrapperMismatch, ProxyUnavailable, Unregistered,
    PublicIpUnavailable, Pending, RequestFloor, ProducerAmbiguous, FreshnessExpired,
    TaskNotReady, TaskAmbiguous, TaskMismatch, HolderMismatch, TaskReused,
    BuilderChanged, InstallFailed, PostcheckFailed, StrandedWrapper,
    PreparedUnavailable, PreparedMalformed, PreparedLimit, PreparedMismatch,
    NativeBackoff, KnownSpin, NativeUnwind, WriteFault,
    RecordLoss, WriterFailed, LogLimit, StatusUnavailable, SpectatorsPresent,
    CapacityMismatch, Count
};
inline constexpr std::size_t kReasonCount = static_cast<std::size_t>(Reason::Count);
static_assert(kReasonCount <= 64);

enum class CallerClass : std::uint32_t {
    Unknown = 0, NormalPump, NormalBuilder, KnownSpin, ShutdownDrain, Truncated
};
enum class DurationClass : std::uint32_t {
    PumpForward = 0, PumpManagement, BuilderForward, BuilderProbe, Count
};
inline constexpr std::size_t kDurationClassCount =
    static_cast<std::size_t>(DurationClass::Count);

// Native PI_COUNT is NOT humans+bots and may exceed max (for example 65/64).
// Keep source human/bot validity separate from prepared native count equality.
struct NativeCounts {
    std::uint32_t pi;
    std::uint32_t bots;
    std::uint32_t maximum;
};
constexpr bool EqualCounts(const NativeCounts& a, const NativeCounts& b) noexcept {
    return a.pi == b.pi && a.bots == b.bots && a.maximum == b.maximum;
}
struct Config { Mode mode; };
inline constexpr std::uint32_t kConfigSchema = 2;
inline constexpr std::size_t kConfigBytes = 4096;
inline constexpr std::size_t kJsonBytes = 65536;
inline constexpr std::size_t kJsonDepth = 16;
inline constexpr std::size_t kJsonTokens = 8192;
inline constexpr std::size_t kCaptureFrames = 32;
inline constexpr std::size_t kTaskSlots = 128;
inline constexpr std::uint32_t kRequestFloorSeconds = 20;
inline constexpr std::uint32_t kFreshnessSeconds = 45;
inline constexpr std::uint32_t kManagementHz = 4;

const char* ModeName(Mode) noexcept;
const char* ReasonName(Reason) noexcept;
static_assert(std::is_trivial_v<NativeCounts> && std::is_standard_layout_v<NativeCounts>);
} // namespace rs2fix::reporting
