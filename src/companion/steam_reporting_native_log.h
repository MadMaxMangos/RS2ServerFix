#pragma once
#include "companion/steam_reporting_native_source.h"
#include "companion/steam_reporting_transport.h"

namespace rs2fix::reporting {
// The only potentially throwing callback is the independently qualified native
// FOutputDevice::Log. All other operations are our bounded guards/mailboxes.
using NativeLogFunction=void (*)(void*,const wchar_t*);
struct NativeLogServiceOps {
    void* context;
    TransportReason (*snapshot)(void*,NativeLogSnapshot*) noexcept;
    bool (*request)(void*,std::uint64_t,const NativeLogSnapshot&) noexcept;
    std::uint64_t (*qualified)(void*) noexcept;
    const NativeReadyFrame* (*front)(void*,std::uint64_t) noexcept;
    bool (*returned)(void*,std::uint64_t) noexcept;
    bool (*clock)(void*,std::uint64_t*) noexcept;
};
struct NativeLogService {
    StatusWireV3* status;
    OwnerTransport* counters;
    NativeTransport* transport;
    NativeLogReadContext read;
    NativeLogServiceOps ops;
    NativeLogFunction log;
    NativeLogSnapshot snapshot;
    std::uint64_t frequency,lastClock,lastService,epoch;
    // Sliding, not tumbling, window: a blocked first call must not allow its
    // late second frame to combine with the next opportunity into >8 per second.
    std::uint64_t submittedAt[8];
    std::uint32_t submittedHead,submittedCount;
    bool haveClock,haveService,haveSnapshot;
};
struct NativeServiceResult {
    TransportReason reason;
    bool qualified;
    std::uint32_t submitted;
};
// Caller must already pass the cold exact-build native profile/import gate.
// This only constructs the owner-resident service; no native call here.
bool InitializeNativeLogService(NativeLogService&,StatusWireV3&,OwnerTransport&,
    NativeTransport*,const NativeLogReadContext&,std::uint32_t entryRva=0x9CF10) noexcept;
bool NativeLogServiceDue(const NativeLogService&,std::uint64_t now) noexcept;
// Caller invokes ONLY in AfterPump's normal __try continuation after original
// returns, with DIRECTLY captured NormalPump ancestry and topLevel=true. Never
// call from builders/End/finally/unwind. No stack capture occurs in this helper.
NativeServiceResult ServiceNativeLog(NativeLogService&,CallerClass,bool topLevel,
    std::uint64_t now,DWORD originalOutgoingLastError);
#if defined(RS2_REPORTING_TESTING)
bool InitializeNativeLogServiceForTest(NativeLogService&,StatusWireV3&,OwnerTransport&,
    DWORD ownerThreadId,const NativeLogServiceOps&,NativeLogFunction) noexcept;
#endif
}
