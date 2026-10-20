#include "companion/steam_reporting_native_log.h"
#include <cstring>

namespace rs2fix::reporting {
namespace {
TransportReason Snapshot(void* context,NativeLogSnapshot* out) noexcept {
    return ReadNativeLogSnapshot(static_cast<NativeLogService*>(context)->read,out);
}
bool Request(void* context,std::uint64_t epoch,const NativeLogSnapshot& snapshot) noexcept {
    return RequestNativeLogFile(static_cast<NativeLogService*>(context)->transport,epoch,
        snapshot.prefixMode,snapshot.path,snapshot.pathChars);
}
std::uint64_t Qualified(void* context) noexcept {
    return NativeTransportQualifiedEpoch(static_cast<NativeLogService*>(context)->transport);
}
const NativeReadyFrame* Front(void* context,std::uint64_t epoch) noexcept {
    return NativeTransportFrame(static_cast<NativeLogService*>(context)->transport,epoch);
}
bool Returned(void* context,std::uint64_t ticket) noexcept {
    return NativeTransportReturned(static_cast<NativeLogService*>(context)->transport,ticket);
}
bool Clock(void*,std::uint64_t* out) noexcept {
    LARGE_INTEGER now{};
    if (!QueryPerformanceCounter(&now) || now.QuadPart<=0) return false;
    *out=static_cast<std::uint64_t>(now.QuadPart); return true;
}
bool Sample(NativeLogService& s,std::uint64_t& now) noexcept {
    now=0;
    if (!s.ops.clock(s.ops.context,&now) || !now || (s.haveClock && now<s.lastClock)) {
        RevokeStatus(*s.status,Reason::ClockFailed); return false;
    }
    s.lastClock=now; s.haveClock=true; return true;
}
bool Add(NativeLogService& s,std::uint64_t& word,std::uint64_t delta=1) noexcept {
    if (delta>UINT64_MAX-word) { RevokeStatus(*s.status,Reason::CounterOverflow); return false; }
    word+=delta; return true;
}
bool Initialize(NativeLogService& s,StatusWireV3& status,OwnerTransport& counters,DWORD thread,
    const NativeLogServiceOps& ops,NativeLogFunction log) noexcept {
    if (s.status || !thread || thread!=GetCurrentThreadId() || ReadStatusWord(status.headerReady)!=1 ||
        !status.header.qpcFrequency || !ops.snapshot || !ops.request || !ops.qualified ||
        !ops.front || !ops.returned || !ops.clock || !log) return false;
    s.status=&status; s.counters=&counters; s.frequency=status.header.qpcFrequency;
    s.read.ownerThreadId=thread; s.ops=ops; s.log=log;
    return true;
}
TransportReason Qualify(NativeLogService& s) noexcept {
    NativeLogSnapshot current{};
    const auto reason=s.ops.snapshot(s.ops.context,&current);
    if (reason!=TransportReason::None) {
        s.counters->qualifiedSinkEpoch=0;
        if (reason>=TransportReason::ReceiptGap) LatchTransportFault(*s.status,reason);
        return reason;
    }
    if (!s.haveSnapshot || std::memcmp(&current,&s.snapshot,sizeof(current))) {
        if (s.epoch==UINT64_MAX) { RevokeStatus(*s.status,Reason::CounterOverflow); return TransportReason::ProfileUnsafe; }
        const auto next=s.epoch+1;
        if (!s.ops.request(s.ops.context,next,current)) return TransportReason::AwaitingLogger;
        s.snapshot=current; s.haveSnapshot=true; s.epoch=next;
        s.counters->qualifiedSinkEpoch=0;
    }
    if (s.ops.qualified(s.ops.context)!=s.epoch) {
        s.counters->qualifiedSinkEpoch=0;
        return s.counters->startupSubmitted ? TransportReason::SameFileRequalification : TransportReason::AwaitingLogger;
    }
    s.counters->qualifiedSinkEpoch=s.epoch;
    return TransportReason::None;
}
bool RateAllows(NativeLogService& s,std::uint64_t now) noexcept {
    if (s.submittedCount>8 || s.submittedHead>=8) {
        RevokeStatus(*s.status,Reason::StatusUnavailable); return false;
    }
    while (s.submittedCount) {
        const auto oldest=s.submittedAt[s.submittedHead];
        if (now<oldest) { RevokeStatus(*s.status,Reason::ClockFailed); return false; }
        if (now-oldest<s.frequency) break;
        s.submittedHead=(s.submittedHead+1)%8; --s.submittedCount;
    }
    s.counters->submitWindowStartQpc=s.submittedCount ? s.submittedAt[s.submittedHead] : now;
    s.counters->submitWindowCount=s.submittedCount;
    return s.submittedCount<8;
}
// Native code may throw C++ or SEH exceptions. Mark but never swallow them or
// enter another logger while unwinding. This must stay in the normal pump try.
__declspec(noinline) void Invoke(NativeLogService& s,const NativeReadyFrame& frame,DWORD outgoing) {
    bool normal=false;
    __try {
        SetLastError(outgoing);
        s.log(reinterpret_cast<void*>(s.snapshot.redirector),frame.message);
        normal=true;
    } __finally {
        if (!normal) LatchTransportFault(*s.status,TransportReason::NativeLogException);
        SetLastError(outgoing);
    }
}
}
bool InitializeNativeLogService(NativeLogService& s,StatusWireV3& status,OwnerTransport& counters,
    NativeTransport* transport,const NativeLogReadContext& read,std::uint32_t entryRva) noexcept {
    // Caller's compile-time selected cold profile authenticates this entry.
    // Production always supplies the accepted current-build Log RVA, not Logf.
    if (!transport || !entryRva || !read.memory.read || !read.memory.query || read.hostImageSize<=entryRva ||
        !read.hostBase || read.hostBase>UINTPTR_MAX-read.hostImageSize) return false;
    const NativeLogServiceOps ops{&s,Snapshot,Request,Qualified,Front,Returned,Clock};
    if (!Initialize(s,status,counters,read.ownerThreadId,ops,
        reinterpret_cast<NativeLogFunction>(read.hostBase+entryRva))) return false;
    s.transport=transport; s.read=read;
    return true;
}
bool NativeLogServiceDue(const NativeLogService& s,std::uint64_t now) noexcept {
    if (!s.status || !s.frequency || GetCurrentThreadId()!=s.read.ownerThreadId ||
        StatusRevoked(*s.status) || !now) return false;
    const auto interval=s.frequency/4+(s.frequency%4!=0);
    return !s.haveService || now<s.lastService || now-s.lastService>=interval;
}
NativeServiceResult ServiceNativeLog(NativeLogService& s,CallerClass caller,bool topLevel,
    std::uint64_t now,DWORD outgoing) {
    NativeServiceResult result{TransportReason::None,false,0};
    if (!topLevel || caller!=CallerClass::NormalPump || !NativeLogServiceDue(s,now)) return result;
    if (s.haveClock && now<s.lastClock) { RevokeStatus(*s.status,Reason::ClockFailed); return result; }
    s.lastClock=now; s.haveClock=true; s.lastService=now; s.haveService=true;
    result.reason=Qualify(s);
    if (result.reason!=TransportReason::None || StatusRevoked(*s.status)) return result;
    result.qualified=true;
    for (unsigned count=0;count<2;++count) {
        const auto* frame=s.ops.front(s.ops.context,s.epoch);
        if (!frame) break;
        if (frame->sequence && !ReadStatusWord(s.status->worker.startupObserved)) break;
        if (!native_log::ValidMessage(frame->message,frame->chars) ||
            (frame->sequence==0 ? s.counters->startupSubmitted!=0 :
                !s.counters->startupSubmitted || s.counters->submittedSequence==UINT64_MAX ||
                frame->sequence!=s.counters->submittedSequence+1 ||
                frame->sequence>s.counters->generatedSequence)) {
            LoseStatus(*s.status,Reason::RecordLoss); break;
        }
        // Re-probe every frame, not merely once per opportunity. A native call
        // may have blocked or changed the logger since the preceding frame.
        const auto epoch=s.epoch;
        result.reason=Qualify(s);
        if (result.reason!=TransportReason::None || s.epoch!=epoch || StatusRevoked(*s.status)) {
            if (result.reason==TransportReason::None && s.epoch!=epoch)
                result.reason=TransportReason::SameFileRequalification;
            result.qualified=false; break;
        }
        std::uint64_t start{};
        if (!Sample(s,start) || !RateAllows(s,start) || StatusRevoked(*s.status)) break;
        if (!Add(s,s.counters->nativeSubmitCalls)) break;
        s.submittedAt[(s.submittedHead+s.submittedCount)%8]=start;
        ++s.submittedCount;
        s.counters->submitWindowCount=s.submittedCount;
        s.counters->submitWindowStartQpc=s.submittedAt[s.submittedHead];
        Invoke(s,*frame,outgoing);
        // A normal return is a fact even if the subsequent clock/metric fails.
        // Release only after recording it locally; owner publishes in its region.
        if (frame->sequence) s.counters->submittedSequence=frame->sequence;
        else s.counters->startupSubmitted=1;
        const auto ticket=frame->ticket;
        ++result.submitted;
        if (!s.ops.returned(s.ops.context,ticket)) { LoseStatus(*s.status,Reason::RecordLoss); break; }
        std::uint64_t end{};
        if (!Sample(s,end)) break;
        const auto elapsed=end-start;
        if (!Add(s,s.counters->nativeSubmitElapsedTicks,elapsed)) break;
        if (elapsed>s.counters->nativeSubmitMaximumTicks) s.counters->nativeSubmitMaximumTicks=elapsed;
        if (elapsed>s.frequency/200 && !Add(s,s.counters->nativeSubmitOverFiveMilliseconds)) break;
        s.counters->lastNativeSubmitQpc=end;
    }
    if (StatusRevoked(*s.status)) result.qualified=false;
    SetLastError(outgoing);
    return result;
}
#if defined(RS2_REPORTING_TESTING)
bool InitializeNativeLogServiceForTest(NativeLogService& s,StatusWireV3& status,
    OwnerTransport& counters,DWORD thread,const NativeLogServiceOps& ops,NativeLogFunction log) noexcept {
    return Initialize(s,status,counters,thread,ops,log);
}
#endif
}
