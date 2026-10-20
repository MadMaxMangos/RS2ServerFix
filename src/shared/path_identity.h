#pragma once
#include <Windows.h>
#include <cstddef>

namespace rs2fix {
inline constexpr std::size_t kPathCapacity = 32768;
inline constexpr std::size_t kBootstrapPathCapacity = 512;
struct FileIdentity {
    DWORD volumeSerial{};
    DWORD fileIndexHigh{};
    DWORD fileIndexLow{};
    bool valid{};
};
// Reporting V3 uses FileIdInfo's complete tuple. Do not narrow this to the
// legacy BY_HANDLE_FILE_INFORMATION index: its upper 64 bits can be meaningful.
struct FileIdentity128 {
    ULONGLONG volumeSerial{};
    BYTE fileId[16]{};
    bool valid{};
};
bool BuildSystemX3AudioPath(wchar_t*, std::size_t, DWORD*) noexcept;
bool GetBoundedModulePath(HMODULE, wchar_t*, std::size_t, DWORD*) noexcept;
bool ExtractDirectoryAndLeaf(const wchar_t* path, std::size_t pathCapacity,
    wchar_t* directory, std::size_t directoryCapacity,
    wchar_t* leaf, std::size_t leafCapacity, DWORD* error) noexcept;
// output may equal directory; leaf must not overlap output.
bool AppendPathLeaf(const wchar_t* directory, std::size_t directoryCapacity,
    const wchar_t* leaf, std::size_t leafCapacity,
    wchar_t* output, std::size_t outputCapacity, DWORD* error) noexcept;
bool QueryFileIdentity(const wchar_t*, FileIdentity*, DWORD*) noexcept;
bool SameFileIdentity(const FileIdentity&, const FileIdentity&) noexcept;
// The caller retains its already opened, read-only receipt handle. No path
// reopen, ownership transfer, or fallback to a truncated identity on failure.
bool QueryFileIdentity128(HANDLE file, FileIdentity128*, DWORD*) noexcept;
bool SameFileIdentity128(const FileIdentity128&, const FileIdentity128&) noexcept;
} // namespace rs2fix
