#pragma once

#include <Windows.h>

#include <cstddef>

namespace rs2fix {

inline constexpr std::size_t kPathCapacity = 32768;

struct FileIdentity {
    DWORD volumeSerial{};
    DWORD fileIndexHigh{};
    DWORD fileIndexLow{};
    bool valid{};
};

bool BuildSystemFaultrepPath(
    wchar_t* output,
    std::size_t capacity,
    DWORD* error) noexcept;

bool GetBoundedModulePath(
    HMODULE module,
    wchar_t* output,
    std::size_t capacity,
    DWORD* error) noexcept;

bool ExtractDirectoryAndLeaf(
    const wchar_t* path,
    wchar_t* directory,
    std::size_t directoryCapacity,
    wchar_t* leaf,
    std::size_t leafCapacity,
    DWORD* error) noexcept;

bool AppendPathLeaf(
    const wchar_t* directory,
    const wchar_t* leaf,
    wchar_t* output,
    std::size_t capacity,
    DWORD* error) noexcept;

bool QueryFileIdentity(
    const wchar_t* path,
    FileIdentity* identity,
    DWORD* error) noexcept;

bool SameFileIdentity(
    const FileIdentity& left,
    const FileIdentity& right) noexcept;

} // namespace rs2fix
