#include "companion/steam_reporting_capture.h"
#include "test_framework.h"
#include <intrin.h>

using namespace rs2fix::reporting;
namespace {
CaptureProfile g_profile{};
std::uintptr_t g_host{};
std::uint32_t g_expected[8]{}, g_frames[kCaptureFrames]{};
std::size_t g_count{};
bool g_truncated{};
std::uint32_t Rva(const void* address) {
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(address) - g_host);
}
// This independent _ReturnAddress oracle is recorded BEFORE walking the stack,
// not derived from CaptureHostCallers output. Volatile return stores prevent
// tail-call elimination in the actual optimized Release executable.
__declspec(noinline) bool Bridge() {
    g_expected[0] = Rva(_ReturnAddress());
    volatile bool result = CaptureHostCallers(g_profile, g_frames, &g_count, &g_truncated);
    return result;
}
__declspec(noinline) bool Level1() {
    g_expected[1] = Rva(_ReturnAddress()); volatile bool result = Bridge(); return result;
}
__declspec(noinline) bool Level2() {
    g_expected[2] = Rva(_ReturnAddress()); volatile bool result = Level1(); return result;
}
__declspec(noinline) bool Level3() {
    g_expected[3] = Rva(_ReturnAddress()); volatile bool result = Level2(); return result;
}
__declspec(noinline) bool Level4() {
    g_expected[4] = Rva(_ReturnAddress()); volatile bool result = Level3(); return result;
}
__declspec(noinline) bool Level5() {
    g_expected[5] = Rva(_ReturnAddress()); volatile bool result = Level4(); return result;
}
struct Primary { virtual void Unused() {} unsigned char padding[88]{}; };
struct Secondary { virtual bool Tick() = 0; };
struct Tickable final : Primary, Secondary {
    __declspec(noinline) bool Tick() override {
        g_expected[6] = Rva(_ReturnAddress()); volatile bool result = Level5(); return result;
    }
};
__declspec(noinline) bool World(Secondary* tickable) {
    g_expected[7] = Rva(_ReturnAddress()); volatile bool result = tickable->Tick(); return result;
}
__declspec(noinline) bool Deep(unsigned depth, Secondary* tickable) {
    volatile bool result = depth ? Deep(depth - 1, tickable) : World(tickable);
    return result;
}
} // namespace
void ReportingCaptureTests() {
    const auto self = GetModuleHandleW(nullptr);
    g_host = reinterpret_cast<std::uintptr_t>(self);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_host);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(g_host + dos->e_lfanew);
    const void* callers[]{reinterpret_cast<const void*>(&Bridge)};
    RS2_CHECK(PrepareCaptureProfile(self, g_host, nt->OptionalHeader.SizeOfImage, callers, 1, &g_profile));
    Tickable object;
    auto* secondary = static_cast<Secondary*>(&object);
    RS2_CHECK(reinterpret_cast<std::uintptr_t>(secondary) - reinterpret_cast<std::uintptr_t>(&object) == 0x60);
    RS2_CHECK(World(secondary));
    RS2_CHECK(g_count >= 8 && !g_truncated);
    for (unsigned i = 0; i < 8; ++i) RS2_CHECK(g_frames[i] == g_expected[i]);
    const AncestryProfile native{g_expected[0],g_expected[1],g_expected[2],
        {g_expected[3],g_expected[3]}, {g_expected[4],g_expected[4]},g_expected[5],
        {g_expected[6],g_expected[6]},g_expected[7],{1,2},3,{4,5},6};
    RS2_CHECK(ClassifyBuilderFrames(native, g_frames, g_count, g_truncated) == CallerClass::NormalBuilder);
    const auto good = g_profile;
    g_profile.prefix[1] = g_profile.prefix[0]; // An intervening/unexpected own frame is NOT skipped.
    RS2_CHECK(!World(secondary) && g_count == 0);
    g_profile = good;
    RS2_CHECK(Deep(40, secondary) && g_truncated);
    RS2_CHECK(ClassifyBuilderFrames(native, g_frames, g_count, g_truncated) == CallerClass::Truncated);
    CaptureProfile rejected{};
    const void* foreign[]{reinterpret_cast<const void*>(&Sleep)};
    RS2_CHECK(!PrepareCaptureProfile(self, g_host, nt->OptionalHeader.SizeOfImage, foreign, 1, &rejected));
    RS2_CHECK(!PrepareCaptureProfile(self, g_host, nt->OptionalHeader.SizeOfImage, callers, 8, &rejected));
}
