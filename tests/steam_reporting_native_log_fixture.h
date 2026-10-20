#pragma once
#include <cstdint>

// Owned mock state only. Offsets match the native logger reader's object model;
// this is not UE code and never constitutes production/native ABI evidence.
namespace rs2fix::fixture_log {
inline constexpr std::uint32_t kBytes=0x4000;
inline constexpr std::uint32_t kSlot=0, kRedirector=0x100, kFile=0x200, kArchive=0xB00;
inline constexpr std::uint32_t kManagerSlot=0x1C00, kManager=0x1C10;
inline constexpr std::uint32_t kForce=0x1C20, kCritical=0x1C24, kExit=0x1C28, kTimes=0x1C2C;
inline constexpr std::uint32_t kInitialized=0x1C30, kNameSlot=0x1C38;
inline constexpr std::uint32_t kReentry=0x1C40, kSinks=0x1C60, kNames=0x2000, kLogName=0x3800;
}
bool PrepareFixtureNativeLog() noexcept;
void CloseFixtureNativeLog() noexcept;
