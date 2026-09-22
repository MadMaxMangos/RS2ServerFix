#include "companion/steam_observer.h"
#include "companion/steam_observer_log.h"
#include "shared/path_identity.h"
#include <cstring>
#include <intrin.h>
#include <limits>

namespace rs2fix::observer {
namespace {
bool DataProtection(DWORD protection) noexcept {
    // A real SEC_IMAGE probe shows COW becomes RW on first write and cannot be
    // restored to WRITECOPY exactly. Decline that state BEFORE any mutation.
    return protection==PAGE_READONLY || protection==PAGE_READWRITE;
}
bool EqualSlice(const char* bytes, std::size_t size, const char* expected) noexcept {
    const auto length=std::strlen(expected);
    return size==length && !std::memcmp(bytes,expected,length);
}
bool Number(const char* bytes, std::size_t size, std::uint32_t* output) noexcept {
    if (!size || size>10) return false;
    std::uint32_t value=0;
    for (std::size_t i=0; i<size; ++i) {
        if (bytes[i]<'0' || bytes[i]>'9') return false;
        const auto digit=static_cast<std::uint32_t>(bytes[i]-'0');
        if (value>(UINT32_MAX-digit)/10) return false;
        value=value*10+digit;
    }
    *output=value;
    return true;
}
Reason ReadConfig(const wchar_t* directory, Config* config) noexcept {
    auto* path=static_cast<wchar_t*>(VirtualAlloc(nullptr,kPathCapacity*sizeof(wchar_t),
        MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if (!path) return Reason::PreparationFailed;
    DWORD error{};
    if (!AppendPathLeaf(directory,kPathCapacity,L"RS2SteamObserve.ini",20,
        path,kPathCapacity,&error)) {
        VirtualFree(path,0,MEM_RELEASE); return Reason::ConfigInvalid;
    }
    HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    error=GetLastError();
    VirtualFree(path,0,MEM_RELEASE);
    if (file==INVALID_HANDLE_VALUE)
        return error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND ?
            Reason::ConfigMissing : Reason::ConfigInvalid;
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    char bytes[4096]{};
    DWORD got{};
    Reason result=Reason::ConfigInvalid;
    if (GetFileInformationByHandle(file,&info) &&
        !(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) &&
        GetFileSizeEx(file,&size) && size.QuadPart>0 && size.QuadPart<=sizeof(bytes) &&
        ReadFile(file,bytes,static_cast<DWORD>(size.QuadPart),&got,nullptr) &&
        got==static_cast<DWORD>(size.QuadPart)) result=ParseConfig(bytes,got,config);
    if (!CloseHandle(file)) return Reason::ConfigInvalid;
    return result;
}
bool ReadCell(const BootstrapContextV3& context, const StartupProfile& startup,
    std::uint32_t rva, const MemoryOps& memory, void** output, DWORD* error) noexcept {
    return ReadImageRange(reinterpret_cast<std::uintptr_t>(context.hostModule),
        startup.imageSize,rva,output,sizeof(*output),memory,error);
}
bool ProtectedCells(const BootstrapContextV3& context, const StartupProfile& startup,
    const std::uint32_t* rvas, unsigned count, const MemoryOps& memory, DWORD protection,
    void* const* expected, DWORD* error) noexcept {
    const auto base=reinterpret_cast<std::uintptr_t>(context.hostModule);
    for (unsigned i=0; i<count; ++i) {
        void* actual{};
        if (!ImageRangeProtection(base,startup.imageSize,rvas[i],sizeof(void*),
            protection,memory,error) || !ReadCell(context,startup,rvas[i],memory,&actual,error) ||
            actual!=expected[i]) return false;
    }
    return true;
}
struct IdentityContext { HostHashLease* host; HostHashLease* sdk; };
bool Stable(void* context, DWORD* error) noexcept {
    const auto& leases=*static_cast<IdentityContext*>(context);
    return leases.host->ValidateStable(error)==FixReason::None &&
        leases.sdk->ValidateStable(error)==FixReason::None;
}
bool Protect(void*, std::uintptr_t address, std::size_t size, DWORD protection,
    DWORD* old, DWORD* error) noexcept {
    const auto result=VirtualProtect(reinterpret_cast<void*>(address),size,protection,old);
    if (error) *error=result ? ERROR_SUCCESS : GetLastError();
    return result!=FALSE;
}
bool CompareExchange(void*, std::uintptr_t address, void* expected, void* desired,
    void** observed, DWORD* error) noexcept {
    // A third-party mapping/protection race cannot be mistaken for no mutation.
    // Failure here enters exact rollback verification, then fail-fast if unknown.
    __try {
        *observed=InterlockedCompareExchangePointer(
            reinterpret_cast<void* volatile*>(address),desired,expected);
        if (error) *error=ERROR_SUCCESS;
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        if (error) *error=ERROR_NOACCESS;
        return false;
    }
}
[[noreturn]] void FatalInstall(const InstallResult& result) noexcept {
    // Bounded diagnostic is also carried in the fail-fast exception, even if a
    // startup console does not exist yet. Never wait for a reporter on this path.
    EXCEPTION_RECORD exception{};
    exception.ExceptionCode=0xC0000409;
    exception.ExceptionFlags=EXCEPTION_NONCONTINUABLE;
    exception.NumberParameters=3;
    exception.ExceptionInformation[0]=FAST_FAIL_FATAL_APP_EXIT;
    exception.ExceptionInformation[1]=static_cast<ULONG_PTR>(result.reason);
    exception.ExceptionInformation[2]=result.error;
    RaiseFailFastException(&exception,nullptr,0);
    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
}
} // namespace

Reason ReadObserverConfig(const wchar_t* directory, Config* output) noexcept {
    if (!directory || !output) return Reason::ConfigInvalid;
    return ReadConfig(directory,output);
}

Reason ParseConfig(const char* bytes, std::size_t size, Config* output) noexcept {
    if (!bytes || !output || !size || size>4096) return Reason::ConfigInvalid;
    *output={false,512};
    bool haveEnabled=false, haveLimit=false;
    std::size_t cursor=0;
    while (cursor<size) {
        const std::size_t lineStart=cursor;
        while (cursor<size && bytes[cursor]!='\n') {
            const auto c=static_cast<unsigned char>(bytes[cursor]);
            if (!c || c>127 || (c<32 && c!='\t' && c!='\r')) return Reason::ConfigInvalid;
            ++cursor;
        }
        std::size_t first=lineStart, last=cursor;
        if (cursor<size) ++cursor;
        if (last>first && bytes[last-1]=='\r') --last;
        while (first<last && (bytes[first]==' ' || bytes[first]=='\t')) ++first;
        while (last>first && (bytes[last-1]==' ' || bytes[last-1]=='\t')) --last;
        if (first==last) continue;
        std::size_t separator=first;
        while (separator<last && bytes[separator]!='=') ++separator;
        if (separator==last) return Reason::ConfigInvalid;
        std::size_t keyEnd=separator, valueStart=separator+1;
        while (keyEnd>first && (bytes[keyEnd-1]==' ' || bytes[keyEnd-1]=='\t')) --keyEnd;
        while (valueStart<last && (bytes[valueStart]==' ' || bytes[valueStart]=='\t')) ++valueStart;
        std::uint32_t value{};
        if (!Number(bytes+valueStart,last-valueStart,&value)) return Reason::ConfigInvalid;
        if (EqualSlice(bytes+first,keyEnd-first,"enabled")) {
            if (haveEnabled || value>1 || last-valueStart!=1) return Reason::ConfigInvalid;
            haveEnabled=true; output->enabled=value!=0;
        } else if (EqualSlice(bytes+first,keyEnd-first,"max_log_mib")) {
            if (haveLimit || value<16 || value>1024) return Reason::ConfigInvalid;
            haveLimit=true; output->maxLogMiB=value;
        } else return Reason::ConfigInvalid;
    }
    if (!haveEnabled) return Reason::ConfigInvalid;
    return output->enabled ? Reason::None : Reason::ConfigDisabled;
}

InstallResult InstallObserver(const BootstrapContextV3& context, const StartupProfile& startup,
    const Profile& profile, DispatchState& state, const TransactionOps& ops,
    const ServerPumpCell* serverPump) noexcept {
    InstallResult result{false,false,Reason::InvalidContext,ERROR_INVALID_DATA};
    if (!ops.protect || !ops.compareExchange || !ops.stableIdentity ||
        !ops.memory.query || !ops.memory.read || ops.pageSize<sizeof(void*) ||
        (ops.pageSize&(ops.pageSize-1))) return result;
    if (serverPump && (!serverPump->original || !serverPump->wrapper ||
        serverPump->original==serverPump->wrapper || !serverPump->validateNativeProfile))
        return result;
    const auto base=reinterpret_cast<std::uintptr_t>(context.hostModule);
    if (!base || startup.imageSize>(std::numeric_limits<std::uintptr_t>::max)()-base)
        return result;
    const unsigned count=serverPump ? 4u : 3u;
    const std::uint32_t rvas[]{profile.factoryIatRva,profile.shutdownIatRva,profile.initIatRva,
        serverPump ? serverPump->iatRva : 0};
    void* originals[]{
        reinterpret_cast<void*>(state.config.factory),reinterpret_cast<void*>(state.config.shutdown),
        reinterpret_cast<void*>(state.config.init),
        serverPump ? reinterpret_cast<void*>(serverPump->original) : nullptr};
    void* wrappers[]{
        reinterpret_cast<void*>(&FactoryEntry),reinterpret_cast<void*>(&ShutdownEntry),
        reinterpret_cast<void*>(&InitEntry),
        serverPump ? reinterpret_cast<void*>(serverPump->wrapper) : nullptr};
    std::uintptr_t page{};
    DWORD protection{};
    for (unsigned i=0; i<count; ++i) {
        if (!originals[i] || (rvas[i]&7) || rvas[i]>=startup.imageSize ||
            sizeof(void*)>startup.imageSize-rvas[i]) return result;
        for (unsigned j=0; j<i; ++j) if (rvas[i]==rvas[j]) return result;
        const auto thisPage=(base+rvas[i])&~(static_cast<std::uintptr_t>(ops.pageSize)-1);
        if ((i && thisPage!=page) || thisPage<base ||
            ops.pageSize>startup.imageSize-(thisPage-base) ||
            (base+rvas[i])-thisPage>ops.pageSize-sizeof(void*)) {
            result.reason=Reason::PageMismatch; return result;
        }
        page=thisPage;
        MemoryRegion region{};
        if (!ops.memory.query(ops.memory.context,base+rvas[i],&region,&result.error) ||
            region.state!=MEM_COMMIT || region.type!=MEM_IMAGE || region.allocationBase!=base ||
            (i && region.protect!=protection) ||
            !ImageSectionMatches(base,startup.imageSize,rvas[i],8,IMAGE_SCN_MEM_READ,
                IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_DISCARDABLE,ops.memory)) return result;
        if (!DataProtection(region.protect)) {
            result.reason=Reason::UnsupportedProtection; return result;
        }
        protection=region.protect;
    }
    result.reason=CheckColdProfile(context,startup,profile,ops.memory,&result.error);
    if (result.reason!=Reason::None) return result;
    if (serverPump && !serverPump->validateNativeProfile(serverPump->profileContext,&result.error)) {
        result.reason=Reason::ProfileMismatch; return result;
    }
    if (!ops.stableIdentity(ops.context,&result.error) ||
        !ProtectedCells(context,startup,rvas,count,ops.memory,protection,originals,&result.error)) {
        result.reason=Reason::VerifyFailed; return result;
    }
    if (ReadGate(state)!=Gate::Preparing) {
        result.reason=Reason::Contaminated; return result;
    }
    constexpr DWORD writable=PAGE_READWRITE;
    DWORD ignored{};
    bool pointerWriteAttempted=false;
    bool ok=ops.protect(ops.context,page,ops.pageSize,writable,&ignored,&result.error);
    result.reason=Reason::ProtectFailed;
    if (ok) {
        result.reason=Reason::CellChanged;
        for (unsigned i=0; i<count; ++i) {
            void* observed{};
            if (ReadGate(state)!=Gate::Preparing) { ok=false; break; }
            pointerWriteAttempted=true;
            if (!ops.compareExchange(ops.context,base+rvas[i],originals[i],wrappers[i],
                    &observed,&result.error) || observed!=originals[i]) { ok=false; break; }
        }
    }
    if (ok) {
        result.reason=Reason::ProtectFailed;
        ok=ops.protect(ops.context,page,ops.pageSize,protection,&ignored,&result.error);
    }
    if (ok) {
        result.reason=Reason::VerifyFailed;
        ok=ProtectedCells(context,startup,rvas,count,ops.memory,protection,wrappers,&result.error) &&
            ops.stableIdentity(ops.context,&result.error);
    }
    if (ok) {
        result.reason=CheckColdProfile(context,startup,profile,ops.memory,&result.error);
        ok=result.reason==Reason::None;
    }
    if (ok && serverPump) {
        result.reason=Reason::ProfileMismatch;
        ok=serverPump->validateNativeProfile(serverPump->profileContext,&result.error);
    }
    // The only commit point. No file/SDK call, ownership transfer or fallible
    // check may follow it inside the transaction.
    if (ok && InterlockedCompareExchange(&state.gate,static_cast<LONG>(Gate::Armed),
        static_cast<LONG>(Gate::Preparing))==static_cast<LONG>(Gate::Preparing))
        return {true,false,Reason::None,ERROR_SUCCESS};
    if (ok || ReadGate(state)==Gate::Contaminated) result.reason=Reason::Contaminated;
    const DWORD failureError=result.error;
    // A policy may reject EVERY protection call. Before requesting write access
    // again, prove an untouched transaction with reads alone. API failure is not
    // itself proof of unchanged state: pointers, protection and leases all matter.
    if (!pointerWriteAttempted &&
        ProtectedCells(context,startup,rvas,count,ops.memory,protection,originals,&result.error) &&
        ops.stableIdentity(ops.context,&result.error)) {
        InterlockedExchange(&state.gate,static_cast<LONG>(Gate::Disabled));
        result.error=failureError;
        return result;
    }
    // Even a failed VirtualProtect may require restoration. Inspect/correct all
    // selected cells, but CAS only our own pointer. Never overwrite a foreign hook.
    bool restored=ops.protect(ops.context,page,ops.pageSize,writable,&ignored,&result.error);
    if (restored) {
        for (unsigned i=0; i<count; ++i) {
            void* current{};
            if (!ReadCell(context,startup,rvas[i],ops.memory,&current,&result.error)) {
                restored=false; continue;
            }
            if (current==wrappers[i]) {
                void* observed{};
                if (!ops.compareExchange(ops.context,base+rvas[i],wrappers[i],originals[i],
                    &observed,&result.error) || observed!=wrappers[i]) restored=false;
            } else if (current!=originals[i]) restored=false;
        }
    }
    const bool protectionRestored=ops.protect(ops.context,page,ops.pageSize,protection,
        &ignored,&result.error);
    // Do not short-circuit the read-only proof behind failed protection calls.
    // After an attempted pointer write, retain the stricter recovery contract.
    const bool stateProven=ProtectedCells(context,startup,rvas,count,ops.memory,protection,
        originals,&result.error) && ops.stableIdentity(ops.context,&result.error);
    restored=stateProven && ((restored && protectionRestored) || !pointerWriteAttempted);
    InterlockedExchange(&state.gate,static_cast<LONG>(Gate::Disabled));
    if (!restored) return {false,true,Reason::RollbackFailed,result.error ? result.error : failureError};
    result.error=failureError;
    return result;
}

void ObserverUnavailable(Reason reason) noexcept { ScheduleObserverDisabledNotice(reason); }

InstallResult InstallObserverWithLeases(const BootstrapContextV3& context,
    const StartupProfile& startup, const Profile& profile, DispatchState& state,
    HostHashLease& host, HostHashLease& sdk, const ServerPumpCell* pump) noexcept {
    if (!host.valid() || !sdk.valid())
        return {false,false,Reason::InvalidContext,ERROR_INVALID_HANDLE};
    SYSTEM_INFO system{}; GetSystemInfo(&system);
    IdentityContext identities{&host,&sdk};
    const TransactionOps ops{ProductionMemoryOps(),&identities,system.dwPageSize,
        Protect,CompareExchange,Stable};
    return InstallObserver(context,startup,profile,state,ops,pump);
}
[[noreturn]] void FailFastObserverInstallation(const InstallResult& result) noexcept {
    FatalInstall(result);
}

void StartObserver(const BootstrapContextV3& context, const StartupProfile& startup,
    const Profile& profile, const Sha256Digest& hostDigest, HostHashLease& hostLease,
    const wchar_t* directory) noexcept {
    Config config{};
    Reason reason=ReadConfig(directory,&config);
    if (reason!=Reason::None) { ObserverUnavailable(reason); return; }
    if (hostDigest!=profile.hostDigest || !hostLease.valid()) {
        ObserverUnavailable(Reason::HostMismatch); return;
    }
    DWORD error{};
    reason=CheckColdProfile(context,startup,profile,ProductionMemoryOps(),&error);
    if (reason!=Reason::None) { ObserverUnavailable(reason); return; }
    HostHashLease sdkLease;
    DispatchConfig dispatch{};
    reason=QualifySdk(context,startup,profile,&sdkLease,&dispatch,&error);
    if (reason!=Reason::None) { ObserverUnavailable(reason); return; }
    auto* state=static_cast<DispatchState*>(VirtualAlloc(nullptr,sizeof(DispatchState),
        MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if (!state) { ObserverUnavailable(Reason::PreparationFailed); return; }
    // The writer may already own this address even on a partial preparation
    // failure; retain the bounded allocation rather than racing its shutdown.
    Writer* writer=PrepareWriter(directory,config.maxLogMiB,state,&reason,&error);
    if (!writer) { ObserverUnavailable(reason); return; }
    InitializeDispatch(*state,dispatch,GetWriterSink(writer));
    if (!PublishDispatch(*state)) {
        StopUnarmedWriter(writer); ObserverUnavailable(Reason::PreparationFailed); return;
    }
    SYSTEM_INFO system{}; GetSystemInfo(&system);
    IdentityContext identities{&hostLease,&sdkLease};
    const TransactionOps ops{ProductionMemoryOps(),&identities,system.dwPageSize,
        Protect,CompareExchange,Stable};
    const auto installed=InstallObserver(context,startup,profile,*state,ops);
    if (installed.armed) { ArmWriter(writer); return; }
    StopUnarmedWriter(writer);
    ObserverUnavailable(installed.reason);
    if (installed.fatal) FatalInstall(installed);
}
} // namespace rs2fix::observer
