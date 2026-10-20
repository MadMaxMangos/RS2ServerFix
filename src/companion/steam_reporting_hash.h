#pragma once
#include "companion/steam_reporting_pipeline.h"
#include <bcrypt.h>

namespace rs2fix::reporting {
// Prepared off-hook before arming; then used by exactly one receipt worker.
// Provider/object lifetime must exceed every possible use of NativeHashOps.
struct PreparedNativeHash {
    BCRYPT_ALG_HANDLE algorithm;
    BCRYPT_HASH_HANDLE hash;
    void* object;
    ULONG objectBytes;
    DWORD lastError;
    bool failed;
};
bool PrepareNativeHash(PreparedNativeHash&) noexcept;
NativeHashOps NativeHashOperations(PreparedNativeHash&) noexcept;
// Only preparation rollback or a finished worker with no remaining users.
// Never call from a game hook or while another thread can be hashing.
void CloseNativeHash(PreparedNativeHash&) noexcept;
}

