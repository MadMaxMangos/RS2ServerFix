#pragma once

#include "shared/digest.h"

#include <Windows.h>

#include <cstdint>
#include <cstddef>

namespace rs2fix {

struct FileHashResult {
    Sha256Digest digest{};
    std::uint64_t fileSize{};
    DWORD error{};
    bool digestValid{};
    bool timedOut{};
};

struct HashReadOps {
    void* context{};
    ULONGLONG (*ticks)(void*) noexcept{};
    bool (*read)(void*, HANDLE, void*, DWORD, DWORD*, DWORD*) noexcept{};
};
const HashReadOps& ProductionHashReadOps() noexcept;
// Reads only this already-open handle at its current position; never reopens it.
FileHashResult HashHandleSha256(
    HANDLE file, ULONGLONG softDeadlineTick,
    const HashReadOps& ops = ProductionHashReadOps()) noexcept;
bool HashBytesSha256(const void* bytes, std::size_t size,
    Sha256Digest* digest, DWORD* error = nullptr) noexcept;

FileHashResult HashFileSha256(
    const wchar_t* path,
    ULONGLONG softDeadlineTick) noexcept;

} // namespace rs2fix
