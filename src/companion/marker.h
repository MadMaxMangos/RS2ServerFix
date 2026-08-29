#pragma once

#include "bootstrap/bootstrap_types.h"
#include "companion/build_identity.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>

namespace rs2fix {

inline constexpr std::size_t kMarkerPathCapacity = 32768;

struct MarkerData {
    DWORD processId{};
    std::uint64_t executableSize{};
    Sha256Digest digest{};
    bool digestValid{};
    BuildIdentity buildIdentity{BuildIdentity::Indeterminate};
    GenuineResolverStatus resolverStatus{GenuineResolverStatus::LoadFailed};
    DWORD resolverError{};
    DWORD initializeResult{kInitInvalidContext};
    DWORD primaryWriteError{};
    bool bootstrapBesideExecutable{};
    bool companionBesideExecutable{};
    bool complete{};
    wchar_t executableLeaf[260]{};
};

struct MarkerWriteResult {
    bool written{};
    bool usedFallback{};
    DWORD primaryError{};
    DWORD finalError{};
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
    MarkerWriteResult* result) noexcept;

} // namespace rs2fix
