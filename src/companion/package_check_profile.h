#pragma once

#include "companion/build_identity.h"
#include "shared/digest.h"

#include <cstddef>
#include <cstdint>

namespace rs2fix {

// Ranked/stats package safelist bypass (reporting companion only).
//
// HandleRemoteMD5s(float,bool) is the only writer of the package verdict
// globals and is reached only from TickServerRanking. Its entry is replaced by
// a 41-byte tail-jump stub. The stub is the function's own download-failure
// exit (mov [passed],0; mov r8d,[Waiting.Num]; xor edx,edx; lea rcx,[Waiting];
// call TArray<FString>::Remove) with the verdict kept at passed and grey
// cleared. It writes only globals the original writes, and calls only the
// function the original calls, with the same arguments. The stub's six
// instructions cannot fault in normal execution, and its tail jump leaves no
// frame. An asynchronous unwind (all-thread crash capture or profiler/ETW stack
// sample) while this thread's PC is inside the stub would apply the original
// prologue's unwind codes: a 0x44-byte prologue, pushes at offsets 4..0xC, and a
// 0x580 allocation at 0x1A. This can mis-walk only that thread's diagnostic
// stack. The window is a few instructions per TickServerRanking call that has
// queued packages.
inline constexpr std::size_t kPackageCheckStubSize = 41;
inline constexpr std::size_t kPackageCheckFunctionCapacity = 0x600;
// 44 8B 05 rel32 | 33 D2 | 48 8D 0D rel32 | E8 rel32
inline constexpr std::size_t kPackageCheckClearSize = 21;
// 44 89 35 rel32
inline constexpr std::size_t kPackageCheckStoreSize = 7;

struct PackageCheckProfile {
    std::uint32_t functionRva;    // HandleRemoteMD5s
    std::uint32_t functionSize;
    std::uint32_t passedStoreRva; // original: mov dword [passed], r14d
    std::uint32_t greyStoreRva;   // original: mov dword [grey], r14d
    std::uint32_t clearRva;       // original: Remove(&Waiting, 0, Waiting.Num)
    std::uint32_t passedRva;      // GPackagesPassedMD5Checks
    std::uint32_t greyRva;        // GPackagesPassedGreyMD5Checks
    std::uint32_t waitingRva;     // GPackagesWaitingForRemoteMD5s; ArrayNum at +8
    std::uint32_t removeRva;      // TArray<FString>::Remove(Index, Count)
    Sha256Digest hostDigest;
    Sha256Digest originalDigest;  // all functionSize bytes, as loaded
    Sha256Digest patchedDigest;   // the same bytes with the stub at entry
};

// The 1,514 function bytes, the reference sites and every target RVA are
// identical in the two exact production PEs; only the host identity differs.
inline constexpr PackageCheckProfile kFullDumpPackageCheckProfile{
    0xACD860, 0x5EA, 0xACDA1D, 0xACDC9F, 0xACDA24,
    0x1471904, 0x16F2798, 0x1772950, 0x1AE10,
    kCurrentFullDumpDigest,
    {0x2E,0x08,0xBA,0xFF,0x7C,0x60,0x54,0xD1,
     0x1F,0x77,0x32,0xC6,0xD0,0xCB,0xB0,0x7D,
     0x9B,0xE2,0x85,0x37,0x04,0x7E,0x74,0x30,
     0x43,0x4D,0xE5,0xA4,0x85,0x7F,0x3B,0x15},
    {0x03,0x5A,0xC4,0x29,0x66,0x6C,0xFA,0x61,
     0xAC,0x47,0x9C,0x1D,0x56,0xEC,0x71,0x2F,
     0x77,0xE3,0xDD,0xAB,0x6B,0x92,0x21,0xA0,
     0x45,0x17,0x53,0x9B,0xCE,0x4E,0x97,0x7B}
};
inline constexpr PackageCheckProfile kStockPackageCheckProfile = []() constexpr {
    auto profile = kFullDumpPackageCheckProfile;
    profile.hostDigest = kCurrentStockDigest;
    return profile;
}();

} // namespace rs2fix
