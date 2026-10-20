#include "companion/steam_reporting_hash.h"

namespace rs2fix::reporting {
namespace {
bool Fail(PreparedNativeHash& h,DWORD error) noexcept {
    h.lastError=error ? error : ERROR_GEN_FAILURE; h.failed=true; return false;
}
bool Digest(void* context,const void* input,std::size_t bytes,Sha256Digest* output) noexcept {
    if (output) *output={};
    if (!context) return false;
    auto& h=*static_cast<PreparedNativeHash*>(context);
    if (h.failed) return false;
    if (!output || (!input && bytes) || bytes>native_log::kMessageLimit || !h.hash)
        return Fail(h,ERROR_INVALID_PARAMETER);
    auto status=BCryptHashData(h.hash,const_cast<PUCHAR>(static_cast<const UCHAR*>(input)),
        static_cast<ULONG>(bytes),0);
    if (status<0) return Fail(h,static_cast<DWORD>(status));
    Sha256Digest digest{};
    status=BCryptFinishHash(h.hash,digest.data(),static_cast<ULONG>(digest.size()),0);
    if (status<0) return Fail(h,static_cast<DWORD>(status));
    *output=digest; h.lastError=ERROR_SUCCESS;
    // The reusable handle resets after successful FinishHash. No per-frame
    // provider creation, object allocation or teardown is needed.
    return true;
}
}
bool PrepareNativeHash(PreparedNativeHash& h) noexcept {
    if (h.algorithm || h.hash || h.object || h.failed) return false;
    auto status=BCryptOpenAlgorithmProvider(&h.algorithm,BCRYPT_SHA256_ALGORITHM,
        nullptr,BCRYPT_HASH_REUSABLE_FLAG);
    if (status<0) return Fail(h,static_cast<DWORD>(status));
    ULONG received{},hashBytes{};
    status=BCryptGetProperty(h.algorithm,BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&h.objectBytes),sizeof(h.objectBytes),&received,0);
    if (status<0) return Fail(h,static_cast<DWORD>(status));
    if (received!=sizeof(h.objectBytes) || !h.objectBytes || h.objectBytes>65536)
        return Fail(h,ERROR_INVALID_DATA);
    status=BCryptGetProperty(h.algorithm,BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hashBytes),sizeof(hashBytes),&received,0);
    if (status<0) return Fail(h,static_cast<DWORD>(status));
    if (received!=sizeof(hashBytes) || hashBytes!=Sha256Digest{}.size())
        return Fail(h,ERROR_INVALID_DATA);
    h.object=VirtualAlloc(nullptr,h.objectBytes,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (!h.object) return Fail(h,ERROR_NOT_ENOUGH_MEMORY);
    status=BCryptCreateHash(h.algorithm,&h.hash,static_cast<PUCHAR>(h.object),
        h.objectBytes,nullptr,0,BCRYPT_HASH_REUSABLE_FLAG);
    return status<0 ? Fail(h,static_cast<DWORD>(status)) : true;
}
NativeHashOps NativeHashOperations(PreparedNativeHash& h) noexcept { return {&h,Digest}; }
void CloseNativeHash(PreparedNativeHash& h) noexcept {
    if (h.hash) BCryptDestroyHash(h.hash);
    if (h.object) { SecureZeroMemory(h.object,h.objectBytes); VirtualFree(h.object,0,MEM_RELEASE); }
    if (h.algorithm) BCryptCloseAlgorithmProvider(h.algorithm,0);
    h={};
}
}

