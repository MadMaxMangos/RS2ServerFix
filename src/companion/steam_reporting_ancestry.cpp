#include "companion/steam_reporting_ancestry.h"

namespace rs2fix::reporting {
static_assert(kCaptureFrames==32,"The first host ancestry profile has a 32-frame bound");
namespace {
constexpr AncestryProfile kProduction{
    0xBEFEB7, 0xBF7107, 0xBF813E, {0xBA5A33, 0xBA5A53},
    {0xA4B370, 0xA4B43E}, 0xA341A7, {0x5F48E6, 0x5F4953}, 0x585650,
    {0xA48F4D, 0xA49F93}, 0xA48BD4, {0xADE7D, 0xADE9D}, 0xA3498F};
constexpr bool Either(std::uint32_t value, const std::uint32_t (&choices)[2]) noexcept {
    return value == choices[0] || value == choices[1];
}
} // namespace

const AncestryProfile& ProductionAncestryProfile() noexcept { return kProduction; }
CallerClass ClassifyBuilderFrames(const AncestryProfile& profile, const std::uint32_t* frames, std::size_t count,
    bool truncated) noexcept {
    if (truncated || count>kCaptureFrames) return CallerClass::Truncated;
    if (!frames || count<6 || frames[0]!=profile.builderAdapterReturn || frames[1]!=profile.taskDispatchReturn ||
        frames[2]!=profile.taskPumpReturn || !Either(frames[3],profile.leechUpdateReturns)) return CallerClass::Unknown;

    // The shutdown drain calls Leech update directly, bypassing A4B2F0.
    // Its two exact return PCs belong to the same split-unwind exit helper.
    if (frames[4]==profile.shutdownReturn) {
        return Either(frames[5],profile.exitReturns) ?
            CallerClass::ShutdownDrain : CallerClass::Unknown;
    }
    if (!Either(frames[4],profile.leechTickReturns)) return CallerClass::Unknown;

    // A synchronous EOS loop may sit below an outer normal engine tick. Its
    // nearest parent wins before any attempt to examine those outer frames.
    if (Either(frames[5],profile.spinReturns)) return CallerClass::KnownSpin;
    if (count<8 || frames[5]!=profile.subsystemReturn || !Either(frames[6],profile.worldReturns) ||
        frames[7]!=profile.engineReturn) return CallerClass::Unknown;
    return CallerClass::NormalBuilder;
}

CallerClass ClassifyPumpFrames(const AncestryProfile& profile, const std::uint32_t* frames, std::size_t count,
    bool truncated) noexcept {
    if (truncated || count>kCaptureFrames) return CallerClass::Truncated;
    // The subsystem tick has already restored its frame and tail-jumped into
    // Steam-task processing. Requiring A341A7 here would reject the actual path.
    if (!frames || count<3 || frames[0]!=profile.callbackReturn || !Either(frames[1],profile.worldReturns) ||
        frames[2]!=profile.engineReturn) return CallerClass::Unknown;
    return CallerClass::NormalPump;
}
CallerClass ClassifyBuilderFrames(const std::uint32_t* frames, std::size_t count, bool truncated) noexcept {
    return ClassifyBuilderFrames(kProduction, frames, count, truncated);
}
CallerClass ClassifyPumpFrames(const std::uint32_t* frames, std::size_t count, bool truncated) noexcept {
    return ClassifyPumpFrames(kProduction, frames, count, truncated);
}
} // namespace rs2fix::reporting
