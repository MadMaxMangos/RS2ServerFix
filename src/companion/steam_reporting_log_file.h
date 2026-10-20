#pragma once
#include "shared/path_identity.h"
#include "shared/steam_reporting_status_v3.h"

namespace rs2fix::reporting {
inline constexpr std::size_t kNativeLogPathChars=1024;
inline constexpr DWORD kNativeReadCycleBytes=256*1024;
struct NativeLogFile {
    HANDLE handle;
    FileIdentity128 identity;
    std::uint64_t initialEOF;
    std::uint64_t maximumSize;
    bool initialAtLineBoundary;
    DWORD lastError;
    wchar_t path[kNativeLogPathChars];
};
// Copied metadata only; never a native object pointer. Does not normalize away
// dot/reparse/ADS/device syntax or resolve a relative path against the CWD.
bool NativeLogPathSyntax(const std::uint16_t*,std::size_t chars,
    wchar_t (&path)[kNativeLogPathChars]) noexcept;
// Worker-only OPEN_EXISTING / GENERIC_READ. No directory/file creation, ACL
// alteration, append, flush, rename or rotation. Caller starts with zeroed POD.
TransportReason OpenNativeLogFile(NativeLogFile&,const std::uint16_t*,std::size_t chars) noexcept;
// Same-file archive reopen: compare a newly qualified path handle with the
// retained receipt handle; preserve initialEOF and the caller's parser cursor.
TransportReason RequalifyNativeLogFile(NativeLogFile&,const std::uint16_t*,std::size_t chars) noexcept;
TransportReason CheckNativeLogFile(NativeLogFile&,std::uint64_t* size) noexcept;
// Explicit offset permits re-reading an unprocessed read suffix. Counts must be
// included in the worker's aggregate per-cycle budget, including unrelated bytes.
TransportReason ReadNativeLogFile(NativeLogFile&,std::uint64_t offset,void*,
    DWORD requested,DWORD* received) noexcept;
// Worker termination/preparation rollback only, never from a game hook.
void CloseNativeLogFile(NativeLogFile&) noexcept;
}

