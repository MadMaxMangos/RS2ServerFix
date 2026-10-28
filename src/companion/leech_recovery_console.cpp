#include "companion/leech_recovery_console.h"
#include "companion/leech_recovery.h"
#include "companion/steam_reporting_runtime.h"
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <intrin.h>
#include <iterator>

namespace rs2fix::reporting {
namespace {
#include "companion/leech_recovery_console_profile_data.inc"
PVOID volatile g_console{};

bool Range(const MemoryOps& m,std::uintptr_t at,std::size_t bytes,bool writable,
    bool privateOnly) noexcept {
    if(!m.query || !m.read || !at || !bytes || bytes>UINTPTR_MAX-at) return false;
    const auto end=at+bytes;
    for(unsigned regions=0;at<end;++regions) {
        MemoryRegion r{};DWORD error{};
        if(regions==32 || !m.query(m.context,at,&r,&error) || r.state!=MEM_COMMIT ||
            (r.protect!=PAGE_READWRITE && (writable || r.protect!=PAGE_READONLY)) ||
            (privateOnly && r.type!=MEM_PRIVATE) || !r.size || r.base>at ||
            r.size>UINTPTR_MAX-r.base || at>=r.base+r.size) return false;
        at=(std::min)(end,r.base+r.size);
    }
    return true;
}
bool Read(const MemoryOps& m,std::uintptr_t at,void* out,std::size_t bytes,
    bool writable=false,bool heap=false) noexcept {
    DWORD error{};
    return Range(m,at,bytes,writable,heap) && m.read(m.context,at,out,bytes,&error);
}
bool RegistryPass(const RecoveryNativeContext& c,LeechConsoleRegistry& out) noexcept {
    out={};
    if(!c.hostBase || c.hostBase>UINTPTR_MAX-c.hostImageSize ||
        kLeechConsoleRegistryRva>=c.hostImageSize || 16>c.hostImageSize-kLeechConsoleRegistryRva) return false;
    const auto at=c.hostBase+kLeechConsoleRegistryRva;
    DWORD error{};
    if(!ImageRangeProtection(c.hostBase,c.hostImageSize,kLeechConsoleRegistryRva,16,PAGE_READWRITE,c.memory,&error) ||
        !Read(c.memory,at,&out,16,true) || out.count<0 || out.capacity<out.count ||
        out.capacity>static_cast<std::int32_t>(kLeechConsoleRegistryLimit) ||
        (out.capacity==0 ? out.data!=0 : (!out.data || (out.data&7) ||
            !Range(c.memory,out.data,static_cast<std::size_t>(out.capacity)*8,true,true)))) return false;
    if(out.count && !Read(c.memory,out.data,out.entries,static_cast<std::size_t>(out.count)*8,true,true)) return false;
    // Dispatch unconditionally dereferences every initialized registry entry.
    for(std::int32_t i=0;i<out.count;++i) if(!out.entries[i] || (out.entries[i]&7)) return false;
    return true;
}
bool OutputPass(const RecoveryNativeContext& c,std::uintptr_t at,unsigned char (&copy)[0x24]) noexcept {
    if(!at || (at&7) || !Read(c.memory,at,copy,sizeof(copy),true,true)) return false;
    std::uintptr_t table{},data{};std::int32_t suppression{},tag{},line{},count{},capacity{};
    std::memcpy(&table,copy,8);std::memcpy(&suppression,copy+8,4);
    std::memcpy(&tag,copy+12,4);std::memcpy(&line,copy+16,4);
    // Native FString is pack4: do not create an unaligned C++ pointer lvalue.
    std::memcpy(&data,copy+0x14,8);std::memcpy(&count,copy+0x1C,4);std::memcpy(&capacity,copy+0x20,4);
    if(table!=c.hostBase+kLeechConsoleReplyVtableRva || suppression!=1 || tag || line!=1 ||
        count<0 || capacity<count || capacity>static_cast<std::int32_t>(kLeechConsoleOutputCapacity)) return false;
    if(capacity==0) return count==0 && data==0;
    // Positive capacity requires a real fully writable allocation EVEN when
    // Num==0. A null buffer with spare capacity would make native append write0.
    if(!data || (data&1) || !Range(c.memory,data,static_cast<std::size_t>(capacity)*2,true,true)) return false;
    wchar_t terminator{};
    return !count || (Read(c.memory,data+static_cast<std::size_t>(count-1)*2,&terminator,2,true,true) && !terminator);
}
void Unavailable(LeechConsoleAdapter& a,LeechConsoleReason reason) noexcept {
    InterlockedExchange(&a.reason,static_cast<LONG>(reason));
    if(a.recovery) InterlockedExchange(&a.recovery->control.consoleRegistration,
        static_cast<LONG>(recovery::ConsoleRegistration::Unavailable));
}
bool Operational(LeechConsoleAdapter& a) noexcept {
    auto* r=a.recovery;
    // Thread check comes BEFORE reading owner-mutable fields or borrowed data.
    if(!r || !r->runtime || !RuntimeOwner(*r->runtime)) return false;
    auto& s=*r->runtime;
    return recovery::ReadConsoleRegistration(r->control)==recovery::ConsoleRegistration::Available &&
        !ReadStatusWord(s.config.status->stopping) && !InterlockedCompareExchange(&r->control.stop,0,0) &&
        r->prepared && r->controlStarted && RecoveryRuntimeSafeOwner(s) && !a.constructing && !a.replying &&
        !s.pumpDepth && !s.builderDepth && !s.timingDepth && !r->callbackDepth;
}
bool Qualified(LeechConsoleAdapter& a) noexcept {
    auto& r=*a.recovery;DWORD error{};
    return r.native.imports &&
        ValidateNativeLeechConsoleProfile(r.native.hostBase,r.startup,r.native.memory,*r.native.imports,&error)==ProfileResult::Ready &&
        ValidateNativeRecoveryMetadataProfile(r.native.hostBase,r.startup,r.native.memory,*r.native.imports,&error)==ProfileResult::Ready;
}
// This is a call into pinned native FString append, not a logger. A native
// C++/SEH exception propagates; no host exception is caught as a probe failure.
__declspec(noinline) void InvokeReply(LeechConsoleAdapter& a,void* output,const wchar_t* text,DWORD incoming) {
#if defined(RS2_RECOVERY_GUARD_PROBE)
    (void)output;(void)text;Unavailable(a,LeechConsoleReason::Profile);SetLastError(incoming);
#else
    bool returned=false;a.replying=true;
    __try {
        SetLastError(incoming);a.calls.reply(output,text,0x2F8);returned=true;
    } __finally {
        a.replying=false;
        if(!returned) Unavailable(a,LeechConsoleReason::NativeException);
        SetLastError(incoming);
    }
#endif
}
bool Reply(LeechConsoleAdapter& a,void* output,const wchar_t* text,DWORD incoming) {
    std::size_t length{};
    while(length<=kLeechConsoleReplyCharacters && text[length]) {
        if((text[length]<L' ' || text[length]>L'~') && text[length]!=L'\n') return false;
        ++length;
    }
    if(!length || length>kLeechConsoleReplyCharacters || std::wcsncmp(text,L"rs2leech: ",10) ||
        !Operational(a) || !a.calls.reply || !Qualified(a) ||
        !ReadLeechConsoleOutput(a.recovery->native,reinterpret_cast<std::uintptr_t>(output))) return false;
    DWORD error{};
    // Last native lease immediately before EVERY call; do not cache GMalloc
    // readiness across commands or rely only on cold registration.
    if(RequireRecoveryMetadataAllocator(a.recovery->native,a.allocator,&error)!=RecoveryNativeResult::Ready) return false;
    InvokeReply(a,output,text,incoming);return true;
}
bool CopyCommand(const MemoryOps& m,const wchar_t* input,
    wchar_t (&copy)[recovery::kConsoleCommandCharacters+1],std::size_t& count) noexcept {
    count=0;if(!input || (reinterpret_cast<std::uintptr_t>(input)&1)) return false;
    wchar_t first[recovery::kConsoleCommandCharacters+1]{};
    for(;count<std::size(first);++count) {
        const auto address=reinterpret_cast<std::uintptr_t>(input);
        if(count*2>UINTPTR_MAX-address || !Read(m,address+count*2,&first[count],2)) return false;
        if(!first[count]) break;
    }
    if(count==std::size(first) || !Read(m,reinterpret_cast<std::uintptr_t>(input),copy,(count+1)*2) ||
        std::memcmp(first,copy,(count+1)*2)) return false;
    return true;
}
const wchar_t* PhaseText(std::uint64_t phase) noexcept {
    switch(static_cast<RecoveryPhase>(phase)) {
    case RecoveryPhase::Disabled:return L"disabled";case RecoveryPhase::Armed:return L"armed";
    case RecoveryPhase::Observed:return L"published-locally";case RecoveryPhase::Rejected:return L"rejected";
    case RecoveryPhase::Failed:return L"failed";default:return L"in-progress";
    }
}
const wchar_t* ReasonText(std::uint64_t reason) noexcept {
    switch(static_cast<RecoveryReason>(reason)) {
    case RecoveryReason::None:return L"none";
    case RecoveryReason::PermissionDisabled:return L"permission-disabled";
    case RecoveryReason::InvalidRequest:return L"invalid-request";
    case RecoveryReason::SourceUnavailable:return L"source-unavailable";
    case RecoveryReason::SpectatorsPresent:return L"spectators-present";
    case RecoveryReason::CountsInvalid:return L"counts-invalid";
    case RecoveryReason::HeartbeatUnavailable:return L"heartbeat-unreadable";
    case RecoveryReason::FinishTimeout:return L"finish-timeout";
    case RecoveryReason::QuotaUnavailable:return L"record-credit-unavailable";
    case RecoveryReason::MetadataCountLimit:return L"metadata-count-limit";
    case RecoveryReason::MetadataTimeout:return L"metadata-timeout";
    case RecoveryReason::NativeProfileMismatch:return L"native-profile-mismatch";
    case RecoveryReason::GuardSnapshotInvalidContext:return L"snapshot-context";
    case RecoveryReason::GuardSnapshotUnreadable:return L"snapshot-unreadable";
    case RecoveryReason::GuardSnapshotChanged:return L"snapshot-changed";
    case RecoveryReason::GuardSnapshotBudget:return L"snapshot-budget";
    case RecoveryReason::GuardSnapshotShape:return L"snapshot-shape";
    case RecoveryReason::GuardSnapshotAlias:return L"snapshot-alias";
    case RecoveryReason::GuardSnapshotDescriptor:return L"snapshot-descriptor";
    case RecoveryReason::GuardSnapshotPool:return L"snapshot-pool";
    case RecoveryReason::GuardSnapshotReadiness:return L"snapshot-readiness";
    case RecoveryReason::GuardSnapshotHook:return L"snapshot-hook";
    case RecoveryReason::GuardSnapshotAllocator:return L"snapshot-allocator";
    case RecoveryReason::GuardSnapshotImport:return L"snapshot-import";
    case RecoveryReason::GuardSnapshotProvenance:return L"snapshot-provenance";
    case RecoveryReason::GuardReadiness:return L"native-readiness";
    case RecoveryReason::GuardStandalone:return L"standalone-state";
    case RecoveryReason::GuardSession:return L"session-identity";
    case RecoveryReason::GuardIssuedId:return L"issued-request-id";
    case RecoveryReason::GuardFinishFree:return L"finish-slot-unavailable";
    case RecoveryReason::GuardCreateFree:return L"create-slot-unavailable";
    case RecoveryReason::GuardHeartbeatSlot:return L"heartbeat-slot";
    case RecoveryReason::GuardHeartbeatType:return L"heartbeat-type";
    case RecoveryReason::GuardHeartbeatId:return L"heartbeat-id";
    case RecoveryReason::GuardGenericId:return L"generic-id";
    case RecoveryReason::GuardGenericHolder:return L"generic-holder";
    case RecoveryReason::GuardHeartbeatReferences:return L"heartbeat-references";
    case RecoveryReason::PumpHeadroomUnavailable:return L"pump-headroom";
    case RecoveryReason::BotsUnsupported:return L"bots-training-policy";
    case RecoveryReason::PopulationUnsupported:return L"population-or-mode";
    case RecoveryReason::HeartbeatStateUnsupported:return L"heartbeat-state";
    case RecoveryReason::HeartbeatScheduleInvalid:return L"heartbeat-schedule";
    case RecoveryReason::HeartbeatErrors:return L"heartbeat-errors-invalid";
    case RecoveryReason::HeartbeatThrottled:return L"heartbeat-throttle-invalid";
    case RecoveryReason::HeartbeatExpedited:return L"heartbeat-expedite-invalid";
    case RecoveryReason::HeartbeatIntervalUnsupported:return L"heartbeat-interval";
    case RecoveryReason::HeartbeatOverridesUnsupported:return L"heartbeat-overrides";
    case RecoveryReason::HeartbeatRetryUnsupported:return L"heartbeat-retry-limit";
    default:return L"see-reason-code";
    }
}
std::int32_t Execute(LeechConsoleAdapter& a,void* self,std::uintptr_t caller,
    const wchar_t* command,void* output) {
    const DWORD incoming=GetLastError();
    if(!a.recovery || self!=&a.object || caller!=a.recovery->native.hostBase+kLeechConsoleReturnRva) return 0;
    InterlockedExchange(&a.execObserved,1);
    if(!a.recovery->runtime || !RuntimeOwner(*a.recovery->runtime)) {
        InterlockedExchange(&a.foreignObserved,1);SetLastError(incoming);return 0;
    }
    wchar_t copy[recovery::kConsoleCommandCharacters+1]{};std::size_t count{};
    char confirmation[recovery::kConsoleConfirmationCharacters+1]{};
    recovery::ConsoleConfirmation(a.recovery->control.identity.runId,confirmation);
    if(!CopyCommand(a.recovery->native.memory,command,copy,count)) {SetLastError(incoming);return 0;}
    const auto parsed=recovery::ParseConsoleCommand(copy,count,confirmation);
    if(parsed==recovery::ConsoleCommand::Unrelated) {SetLastError(incoming);return 0;}
    if(!Operational(a)) {SetLastError(incoming);return 1;}
    if(!ReadLeechConsoleOutput(a.recovery->native,reinterpret_cast<std::uintptr_t>(output))) {
        InterlockedExchange(&a.unsupportedOutputObserved,1);SetLastError(incoming);return 1;
    }
    if(parsed==recovery::ConsoleCommand::Invalid) {
        Reply(a,output,L"rs2leech: use status or recover <run token>; invalid command/token; no request queued.\n",incoming);
    } else if(parsed==recovery::ConsoleCommand::Status) {
        wchar_t text[kLeechConsoleReplyCharacters+1]{};
        const auto& r=*a.recovery;
        const auto claimed=InterlockedCompareExchange(&a.recovery->control.latched,0,0);
        const bool retry=!claimed &&
            (r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Armed) || (r.value.flags&RecoveryPreflightRetryable)) &&
            InterlockedCompareExchange(&a.recovery->control.result,0,0)==static_cast<LONG>(recovery::ControlResult::Ready);
        if(swprintf_s(text,L"rs2leech: phase=%ls; reason=%llu(%ls); stage=%llu; claimed=%ld; op=%llu; retry=%ls; bots=%u; owner=yes; principal=server-admin; confirm=%hs\n",
            PhaseText(r.value.phase),r.value.reason,ReasonText(r.value.reason),r.value.nativeStage,claimed,
            r.value.operationSequence,retry ? L"yes" : L"no",r.runtime->source.outer.bots,confirmation)>0) Reply(a,output,text,incoming);
    } else {
        // Feedback capability must be qualified BEFORE claiming. Native SDK
        // work is deferred to the existing owner AfterPump state machine.
        DWORD error{};
        if(!Qualified(a) || RequireRecoveryMetadataAllocator(a.recovery->native,a.allocator,&error)!=RecoveryNativeResult::Ready) {
            SetLastError(incoming);return 1;
        }
        const bool claimed=recovery::ClaimConsoleControlRequest(a.recovery->control);
        Reply(a,output,claimed ? L"rs2leech: request queued; native completion and browser repair are not yet confirmed.\n" :
            L"rs2leech: not queued; busy, native attempt spent, disabled, or stopped. Use status.\n",incoming);
    }
    SetLastError(incoming);return 1;
}
__declspec(noinline) std::int32_t Exec(void* self,const wchar_t* command,void* output) {
    auto* a=static_cast<LeechConsoleAdapter*>(InterlockedCompareExchangePointer(&g_console,nullptr,nullptr));
    return a ? Execute(*a,self,reinterpret_cast<std::uintptr_t>(_ReturnAddress()),command,output) : 0;
}
void* NoDelete(void* self,std::uint32_t) noexcept {return self;}
const std::uintptr_t kVtable[]{reinterpret_cast<std::uintptr_t>(&Exec),reinterpret_cast<std::uintptr_t>(&NoDelete)};
[[maybe_unused]] bool Pin(HMODULE expected) noexcept {
    HMODULE pinned{};
    return expected && GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(&Exec),&pinned) && pinned==expected;
}
__declspec(noinline) void Construct(LeechConsoleAdapter& a,DWORD incoming) {
#if defined(RS2_RECOVERY_GUARD_PROBE)
    Unavailable(a,LeechConsoleReason::Profile);SetLastError(incoming);
#else
    bool returned=false;a.constructing=true;
    __try {
        SetLastError(incoming);
        a.calls.construct(&a.object);
        // The ctor leaves a pure-virtual base vtable. No intervening call may
        // occur before replacing it, even for diagnostics or LastError reads.
        a.object.vtable=kVtable;
        returned=true;
    } __finally {
        a.constructing=false;
        if(!returned) Unavailable(a,LeechConsoleReason::NativeException);
        SetLastError(incoming);
    }
#endif
}
} // namespace
ProfileResult ValidateNativeLeechConsoleProfile(std::uintptr_t base,const StartupProfile& startup,
    const MemoryOps& memory,const NativeImportOps& imports,DWORD* error) noexcept {
    return ValidateNativeLoggingProfile(base,startup,kConsoleProduction,memory,imports,error);
}
const char* NativeLeechConsoleInventorySha256() noexcept {return kConsoleInventorySha256;}
bool ReadLeechConsoleRegistry(const RecoveryNativeContext& c,LeechConsoleRegistry* out) noexcept {
    if(!out) return false;*out={};
    LeechConsoleRegistry first{},second{};
    if(!RegistryPass(c,first) || !RegistryPass(c,second) || std::memcmp(&first,&second,sizeof(first))) return false;
    *out=first;return true;
}
bool ReadLeechConsoleOutput(const RecoveryNativeContext& c,std::uintptr_t output) noexcept {
    if(!c.hostBase || c.hostBase>UINTPTR_MAX-c.hostImageSize ||
        kLeechConsoleReplyVtableRva>=c.hostImageSize || 16>c.hostImageSize-kLeechConsoleReplyVtableRva) return false;
    unsigned char first[0x24]{},second[0x24]{};
    return OutputPass(c,output,first) && OutputPass(c,output,second) && !std::memcmp(first,second,sizeof(first));
}
void PrepareLeechConsole(LeechConsoleAdapter& a,LeechRecovery& r,HMODULE companion) noexcept {
    a.recovery=&r;a.companion=companion;
#if defined(RS2_RECOVERY_GUARD_PROBE)
    a.calls={};
#else
    a.calls={reinterpret_cast<LeechConsoleConstructFn>(r.native.hostBase+0x3B50),
        reinterpret_cast<LeechConsoleReplyFn>(r.native.hostBase+kLeechConsoleReplyEntryRva),Pin};
#endif
}
bool LeechConsoleRegistrationDue(const Runtime& state) noexcept {
#if defined(RS2_RECOVERY_GUARD_PROBE)
    (void)state;return false;
#else
    if(!RuntimeOwner(state) || !state.sdkReady || !state.sourceReady ||
        !state.config.status || StatusRevoked(*state.config.status) ||
        ReadStatusWord(state.config.status->stopping)) return false;
    const auto* r=state.config.recovery;
    return r && r->prepared && r->controlStarted && r->control.consoleRequested &&
        r->control.scope.schema==2 && !r->console.attempted && !r->requested &&
        !InterlockedCompareExchange(const_cast<volatile LONG*>(&r->control.stop),0,0) &&
        InterlockedCompareExchange(const_cast<volatile LONG*>(&r->control.result),0,0)==static_cast<LONG>(recovery::ControlResult::Ready) &&
        recovery::ReadConsoleRegistration(r->control)==recovery::ConsoleRegistration::NotRegistered;
#endif
}
void RegisterLeechConsole(Runtime& state,CallerClass classification,std::size_t frameCount,bool truncated) {
    if(!RuntimeOwner(state) || !LeechConsoleRegistrationDue(state) ||
        !RecoveryPumpHeadroomAvailable(classification,frameCount,truncated) ||
        !RuntimeCaptureAdmission(state) || !state.sdkReady || !state.sourceReady ||
        state.pumpDepth!=1 || state.builderDepth || state.timingDepth!=1) return;
    auto& r=*state.config.recovery;auto& a=r.console;
    if(r.callbackDepth || r.requested || !RecoveryRuntimeSafeOwner(state)) return;
    const DWORD incoming=GetLastError();a.attempted=true;
    LeechConsoleRegistry before{},after{};DWORD error{};
    if(!a.calls.construct || !a.calls.reply || !a.calls.pin || !Qualified(a)) Unavailable(a,LeechConsoleReason::Profile);
    else if(!ReadLeechConsoleRegistry(r.native,&before) || before.count>=before.capacity) Unavailable(a,LeechConsoleReason::Registry);
    else if(!ReadImageRange(r.native.hostBase,r.native.hostImageSize,r.native.layout->gmalloc,&a.allocator,sizeof(a.allocator),r.native.memory,&error) ||
        RequireRecoveryMetadataAllocator(r.native,a.allocator,&error)!=RecoveryNativeResult::Ready) Unavailable(a,LeechConsoleReason::Allocator);
    else if(!a.calls.pin(a.companion)) Unavailable(a,LeechConsoleReason::ModulePin);
    else if(InterlockedCompareExchangePointer(&g_console,&a,nullptr)!=nullptr) Unavailable(a,LeechConsoleReason::Publication);
    else {
        // Spare capacity avoids Add's realloc branch. The reached allocator
        // closure is nevertheless pinned by the approved metadata overlay.
        LeechConsoleRegistry finalBefore{};
        if(!ReadLeechConsoleRegistry(r.native,&finalBefore) || std::memcmp(&before,&finalBefore,sizeof(before)) ||
            RequireRecoveryMetadataAllocator(r.native,a.allocator,&error)!=RecoveryNativeResult::Ready) {
            Unavailable(a,LeechConsoleReason::Registry);SetLastError(incoming);return;
        }
        Construct(a,incoming);
        const auto object=reinterpret_cast<std::uintptr_t>(&a.object);
        if(!ReadLeechConsoleRegistry(r.native,&after) || after.count!=before.count+1 ||
            after.capacity!=before.capacity || after.data!=before.data ||
            after.entries[before.count]!=object ||
            std::memcmp(before.entries,after.entries,static_cast<std::size_t>(before.count)*8) ||
            a.object.vtable!=kVtable) Unavailable(a,LeechConsoleReason::Postcheck);
        else if(InterlockedCompareExchange(&r.control.consoleRegistration,
            static_cast<LONG>(recovery::ConsoleRegistration::Available),
            static_cast<LONG>(recovery::ConsoleRegistration::NotRegistered))!=
                static_cast<LONG>(recovery::ConsoleRegistration::NotRegistered)) Unavailable(a,LeechConsoleReason::Publication);
    }
    SetLastError(incoming);
}
#if defined(RS2_REPORTING_TESTING)
std::int32_t ExecuteLeechConsoleForTest(LeechConsoleAdapter& a,void* self,std::uintptr_t caller,
    const wchar_t* command,void* output) {return Execute(a,self,caller,command,output);}
void ResetLeechConsoleForTest() noexcept {InterlockedExchangePointer(&g_console,nullptr);}
#endif
} // namespace rs2fix::reporting
