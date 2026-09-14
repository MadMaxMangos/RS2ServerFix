#pragma once

#include "shared/bootstrap_abi.h"
#include "companion/build_identity.h"
#include "companion/recon_types.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>

namespace rs2fix {

inline constexpr std::size_t kMarkerPathCapacity = 32768;

struct MarkerData {
    SYSTEMTIME utc{};
    DWORD processId{};
    std::uint64_t executableSize{};
    Sha256Digest digest{};
    bool digestValid{};
    BuildIdentity buildIdentity{BuildIdentity::Indeterminate};
    bool genuineSystem32{};
    DWORD genuineExportsMask{};
    DWORD triggerKind{};
    ReconMode mode{ReconMode::Passive};
    ReconResult recon{};
    DWORD initializeResult{kInitInvalidContext};
    DWORD primaryWriteError{};
    bool bootstrapBesideExecutable{};
    bool companionBesideExecutable{};
    bool complete{};
    wchar_t executableLeaf[260]{};
};

struct MarkerFileOps {
    void* context{};
    HANDLE (*createAlways)(void*, const wchar_t*, DWORD*) noexcept{};
    bool (*write)(void*, HANDLE, const void*, DWORD, DWORD*, DWORD*) noexcept{};
    bool (*flush)(void*, HANDLE, DWORD*) noexcept{};
    bool (*close)(void*, HANDLE, DWORD*) noexcept{};
    bool (*remove)(void*, const wchar_t*, DWORD*) noexcept{};
};
const MarkerFileOps& ProductionMarkerFileOps() noexcept;

struct MarkerWriteResult {
    bool written{};
    bool usedFallback{};
    DWORD primaryError{};
    DWORD finalError{};
    DWORD cleanupError{};
    wchar_t writtenPath[kMarkerPathCapacity]{};
};

bool FormatMarkerUtf8(
    const MarkerData& data,
    char* output,
    std::size_t capacity,
    std::size_t* bytesUsed) noexcept;

bool WriteMarkerWithFallback(
    const wchar_t* primaryDirectory,
    const wchar_t* fallbackDirectory,
    const MarkerData& data,
    MarkerWriteResult* result,
    const MarkerFileOps& ops = ProductionMarkerFileOps()) noexcept;

// Report completeness and qualification/activation acceptance are distinct.
bool MarkerStateAccepted(const MarkerData& data) noexcept;

} // namespace rs2fix
