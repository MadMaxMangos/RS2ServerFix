#include "companion/steam_reporting_ancestry.h"
#include "test_framework.h"

#include <array>
#include <cstdint>
#include <initializer_list>

namespace rs2fix::testcases {
namespace {
using namespace reporting;
constexpr std::array<std::uint32_t,8> kNormalBuilder{
    0xBEFEB7,0xBF7107,0xBF813E,0xBA5A33,0xA4B370,0xA341A7,0x5F48E6,0x585650
};
constexpr std::array<std::uint32_t,3> kNormalPump{0xA3498F,0x5F48E6,0x585650};

void NormalAlternativesAndTailCall() {
    for (const auto update : {0xBA5A33U,0xBA5A53U}) {
        for (const auto tick : {0xA4B370U,0xA4B43EU}) {
            for (const auto world : {0x5F48E6U,0x5F4953U}) {
                auto frames=kNormalBuilder;
                frames[3]=update; frames[4]=tick; frames[6]=world;
                RS2_CHECK(ClassifyBuilderFrames(frames.data(),frames.size(),false)==CallerClass::NormalBuilder);
            }
        }
    }
    for (const auto world : {0x5F48E6U,0x5F4953U}) {
        const std::uint32_t frames[]{0xA3498F,world,0x585650};
        RS2_CHECK(ClassifyPumpFrames(frames,3,false)==CallerClass::NormalPump);
    }
    const std::uint32_t impossibleFrame[]{0xA3498F,0xA341A7,0x5F48E6,0x585650};
    RS2_CHECK(ClassifyPumpFrames(impossibleFrame,4,false)==CallerClass::Unknown);
    auto builder=kNormalBuilder; builder[6]=0x5F49B3;
    RS2_CHECK(ClassifyBuilderFrames(builder.data(),builder.size(),false)==CallerClass::Unknown);
}

void NearestSpinAndDrainWin() {
    for (const auto update : {0xBA5A33U,0xBA5A53U}) {
        for (const auto tick : {0xA4B370U,0xA4B43EU}) {
            for (const auto spin : {0xA48F4DU,0xA49F93U}) {
                const std::uint32_t frames[]{0xBEFEB7,0xBF7107,0xBF813E,update,tick,spin,
                    0xA341A7,0x5F48E6,0x585650,kUnqualifiedHostFrame};
                RS2_CHECK(ClassifyBuilderFrames(frames,10,false)==CallerClass::KnownSpin);
                RS2_CHECK(ClassifyBuilderFrames(frames,6,false)==CallerClass::KnownSpin);
                RS2_CHECK(ClassifyBuilderFrames(frames,5,false)==CallerClass::Unknown);
            }
        }
        for (const auto exitReturn : {0xADE7DU,0xADE9DU}) {
            const std::uint32_t frames[]{0xBEFEB7,0xBF7107,0xBF813E,update,0xA48BD4,exitReturn,
                0xA341A7,0x5F48E6,0x585650};
            RS2_CHECK(ClassifyBuilderFrames(frames,9,false)==CallerClass::ShutdownDrain);
            RS2_CHECK(ClassifyBuilderFrames(frames,6,false)==CallerClass::ShutdownDrain);
            RS2_CHECK(ClassifyBuilderFrames(frames,5,false)==CallerClass::Unknown);
        }
    }
    const std::uint32_t unknownDrain[]{0xBEFEB7,0xBF7107,0xBF813E,0xBA5A33,0xA48BD4,0xADEAA};
    RS2_CHECK(ClassifyBuilderFrames(unknownDrain,6,false)==CallerClass::Unknown);
}

void NoSkippingOrOuterFallback() {
    for (std::size_t i=0; i<kNormalBuilder.size(); ++i) {
        auto frames=kNormalBuilder; frames[i]=kUnqualifiedHostFrame;
        RS2_CHECK(ClassifyBuilderFrames(frames.data(),frames.size(),false)==CallerClass::Unknown);
    }
    for (std::size_t i=0; i<kNormalPump.size(); ++i) {
        auto frames=kNormalPump; frames[i]=kUnqualifiedHostFrame;
        RS2_CHECK(ClassifyPumpFrames(frames.data(),frames.size(),false)==CallerClass::Unknown);
    }
    const std::uint32_t intervening[]{0xBEFEB7,0xBF7107,0xBF813E,0xBA5A33,
        kUnqualifiedHostFrame,0xA4B370,0xA341A7,0x5F48E6,0x585650};
    RS2_CHECK(ClassifyBuilderFrames(intervening,9,false)==CallerClass::Unknown);
    const std::uint32_t deeperMatch[]{kUnqualifiedHostFrame,0xBEFEB7,0xBF7107,
        0xBF813E,0xBA5A33,0xA4B370,0xA341A7,0x5F48E6,0x585650};
    RS2_CHECK(ClassifyBuilderFrames(deeperMatch,9,false)==CallerClass::Unknown);
    const std::uint32_t badEngine[]{0xBEFEB7,0xBF7107,0xBF813E,0xBA5A33,0xA4B370,
        0xA341A7,0x5F48E6,kUnqualifiedHostFrame,0x585650};
    RS2_CHECK(ClassifyBuilderFrames(badEngine,9,false)==CallerClass::Unknown);
    const std::uint32_t spinAfterForeign[]{0xBEFEB7,0xBF7107,0xBF813E,0xBA5A33,
        kUnqualifiedHostFrame,0xA48F4D,0xA341A7,0x5F48E6,0x585650};
    RS2_CHECK(ClassifyBuilderFrames(spinAfterForeign,9,false)==CallerClass::Unknown);

    // Once the whole relevant boundary matched, outer application/OS frames
    // have no role in the classifier and are not required to be in this host.
    std::array<std::uint32_t,kCaptureFrames> outer{};
    outer.fill(kUnqualifiedHostFrame);
    for (std::size_t i=0; i<kNormalBuilder.size(); ++i) outer[i]=kNormalBuilder[i];
    RS2_CHECK(ClassifyBuilderFrames(outer.data(),outer.size(),false)==CallerClass::NormalBuilder);
    outer.fill(kUnqualifiedHostFrame);
    for (std::size_t i=0; i<kNormalPump.size(); ++i) outer[i]=kNormalPump[i];
    RS2_CHECK(ClassifyPumpFrames(outer.data(),outer.size(),false)==CallerClass::NormalPump);
}

void MissingAndTruncated() {
    for (std::size_t count=0; count<kNormalBuilder.size(); ++count)
        RS2_CHECK(ClassifyBuilderFrames(kNormalBuilder.data(),count,false)==CallerClass::Unknown);
    for (std::size_t count=0; count<kNormalPump.size(); ++count)
        RS2_CHECK(ClassifyPumpFrames(kNormalPump.data(),count,false)==CallerClass::Unknown);
    RS2_CHECK(ClassifyBuilderFrames(nullptr,0,false)==CallerClass::Unknown);
    RS2_CHECK(ClassifyPumpFrames(nullptr,3,false)==CallerClass::Unknown);
    RS2_CHECK(ClassifyBuilderFrames(kNormalBuilder.data(),8,true)==CallerClass::Truncated);
    RS2_CHECK(ClassifyPumpFrames(kNormalPump.data(),3,true)==CallerClass::Truncated);
    // An oversized count is rejected before any array access; no 33-element
    // allocation or padding is needed to make this safety case meaningful.
    RS2_CHECK(ClassifyBuilderFrames(kNormalBuilder.data(),33,false)==CallerClass::Truncated);
    RS2_CHECK(ClassifyPumpFrames(kNormalPump.data(),33,false)==CallerClass::Truncated);
    const std::uint32_t spin[]{0xBEFEB7,0xBF7107,0xBF813E,0xBA5A33,0xA4B370,0xA48F4D};
    const std::uint32_t drain[]{0xBEFEB7,0xBF7107,0xBF813E,0xBA5A33,0xA48BD4,0xADE7D};
    RS2_CHECK(ClassifyBuilderFrames(spin,6,true)==CallerClass::Truncated);
    RS2_CHECK(ClassifyBuilderFrames(drain,6,true)==CallerClass::Truncated);
}
} // namespace
void ReportingAncestryTests() {
    NormalAlternativesAndTailCall(); NearestSpinAndDrainWin();
    NoSkippingOrOuterFallback(); MissingAndTruncated();
}
} // namespace rs2fix::testcases
