#pragma once

#include "companion/build_identity.h"

#include <Windows.h>

#include <cstdint>

namespace rs2fix {

struct FileHashResult {
    Sha256Digest digest{};
    std::uint64_t fileSize{};
    DWORD error{};
    bool digestValid{};
    bool timedOut{};
};

FileHashResult HashFileSha256(
    const wchar_t* path,
    ULONGLONG softDeadlineTick) noexcept;

} // namespace rs2fix
