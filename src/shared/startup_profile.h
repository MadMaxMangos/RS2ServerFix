#pragma once
#include "shared/bootstrap_abi.h"
#include <cstddef>
#include <cstdint>
namespace rs2fix {
struct ByteSpan {
    std::uint32_t rva{};
    std::size_t size{};
    const std::uint8_t* bytes{};
};
struct StartupProfile {
    std::uint32_t imageSize{};
    std::uint32_t timestamp{};
    std::uint32_t checksums[2]{};
    std::size_t checksumCount{};
    std::uint32_t entryRva{};
    std::uint32_t returnRva{};
    std::uint32_t stateRva{};
    std::uint32_t stateValue{1};
    std::uint32_t initializerSlotRva{};
    std::uint32_t initializerRva{};
    const ByteSpan* spans{};
    std::size_t spanCount{};
};
struct MemoryRegion {
    std::uintptr_t base{};
    std::uintptr_t allocationBase{};
    std::size_t size{};
    DWORD state{};
    DWORD type{};
    DWORD protect{};
};
struct MemoryOps {
    void* context{};
    bool (*query)(void*, std::uintptr_t, MemoryRegion*, DWORD*) noexcept{};
    bool (*read)(void*, std::uintptr_t, void*, std::size_t, DWORD*) noexcept{};
};
enum class StartupGateResult : std::uint32_t {
    Ready, InvalidContext, DynamicLoad, WrongThread, WrongCaller,
    ImageUnavailable, ImageMismatch, CodeMismatch, WrongInitializer, WrongStage
};
const MemoryOps& ProductionMemoryOps() noexcept;
bool ReadImageRange(std::uintptr_t imageBase, std::size_t imageSize,
    std::uint32_t rva, void* output, std::size_t size, const MemoryOps& ops,
    DWORD* error) noexcept;
bool ImageRangeProtection(std::uintptr_t imageBase, std::size_t imageSize,
    std::uint32_t rva, std::size_t size, DWORD protection,
    const MemoryOps& ops, DWORD* error) noexcept;
bool ImageSectionMatches(std::uintptr_t imageBase, std::size_t imageSize,
    std::uint32_t rva, std::size_t size, DWORD required, DWORD forbidden,
    const MemoryOps& ops) noexcept;
StartupGateResult CheckStartupOpportunity(const BootstrapContextV3& context,
    const StartupProfile& profile, const MemoryOps& ops) noexcept;
const char* StartupGateResultName(StartupGateResult result) noexcept;
}
