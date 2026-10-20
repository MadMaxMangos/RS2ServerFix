#include "companion/steam_reporting.h"
#include "companion/steam_reporting_config.h"
#include "companion/steam_reporting_forward.h"
#include "companion/steam_reporting_console.h"
#include "companion/steam_reporting_profile.h"
#include "companion/steam_reporting_native_profile.h"
#include "companion/steam_reporting_transport.h"
#include "companion/leech_recovery.h"
#include "shared/selected_reporting_profile.h"
#include <bcrypt.h>
#include <cstring>
#include <new>

extern "C" {
// The only extra export of the reporting artifact. Storage survives absent or
// failed writer allocation and is never shared with the worker's lifetime.
rs2fix::reporting::StatusWireV3 RS2SteamReport_StatusV3{};
}

namespace rs2fix::reporting {
namespace {
struct Resident {
    Runtime runtime;
    LeechRecovery recovery;
    observer::DispatchState dispatch;
    ReportRingV3 ring;
};
struct ProfileCheck {
    std::uintptr_t base;
    const StartupProfile* startup;
    const ReportingProfile* profile;
};
bool Recheck(void* context, DWORD* error) noexcept {
    const auto& check=*static_cast<const ProfileCheck*>(context);
    std::uintptr_t pump{};
    // IAT ownership is checked by the enclosing transaction; this callback runs
    // both before and after publication and validates immutable native evidence.
    return ValidateReportingProfile(check.base,*check.startup,*check.profile,
        ProductionMemoryOps(),&pump,error)==ProfileResult::Ready &&
        ValidateNativeLoggingProfile(check.base,*check.startup,SelectedNativeLoggingProfile(),
            ProductionMemoryOps(),ProductionNativeImportOps(),error)==ProfileResult::Ready;
}
void Reject(Reason reason, Resident* resident=nullptr, NativeTransport* writer=nullptr) noexcept {
    auto& status=RS2SteamReport_StatusV3;
    RevokeStatus(status,reason);
    StatusPayload payload{};
    if (resident) payload=resident->runtime.counters;
    payload.phase=static_cast<std::uint64_t>(ReportPhaseV3::Rejected);
    payload.reason=static_cast<std::uint64_t>(reason);
    payload.ownerThreadId=GetCurrentThreadId();
    OwnerTransport transport{};
    if (resident) transport=resident->runtime.transport;
    transport.state=static_cast<std::uint64_t>(TransportState::Faulted);
    transport.generatedSequence=payload.reportSequence;
    PublishOwnerV3(status,payload,transport);
    if (writer) {
        // Startup rejection happens before the writer is armed. Its stop path
        // cannot service a hook-style notice request, so schedule this one here.
        ScheduleReportingDisabledNotice(status,reason);
        StopNativeTransport(writer);
    } else ScheduleReportingDisabledNotice(status,reason);
}
bool Header(const ConfigV3& config, bool configValid, const Sha256Digest& digest, bool hostValid) noexcept {
    StatusHeader header{};
    header.configuredMode=static_cast<std::uint32_t>(config.mode);
    header.pid=GetCurrentProcessId();
    FILETIME created{}, exited{}, kernel{}, user{};
    if (header.pid && GetProcessTimes(GetCurrentProcess(),&created,&exited,&kernel,&user)) {
        header.processCreation=(static_cast<std::uint64_t>(created.dwHighDateTime)<<32)|created.dwLowDateTime;
        if (header.processCreation) header.validity|=ProcessIdentityValid;
    }
    LARGE_INTEGER frequency{};
    if (QueryPerformanceFrequency(&frequency) && frequency.QuadPart>0 &&
        frequency.QuadPart<=INT64_MAX/kFreshnessSeconds) {
        header.qpcFrequency=frequency.QuadPart; header.validity|=ClockIdentityValid;
    }
    if (BCryptGenRandom(nullptr,header.runId,sizeof(header.runId),BCRYPT_USE_SYSTEM_PREFERRED_RNG)>=0) {
        bool nonzero=false;
        for (const auto byte: header.runId) nonzero|=byte!=0;
        if (nonzero) header.validity|=RunIdentityValid;
    }
    if (configValid) header.validity|=ConfigurationValid;
    if (hostValid) {
        static_assert(sizeof(header.hostDigest)==sizeof(digest));
        std::memcpy(header.hostDigest,digest.data(),sizeof(header.hostDigest));
        header.validity|=HostIdentityValid;
    }
    StatusPayload payload{};
    payload.phase=static_cast<std::uint64_t>(ReportPhaseV3::Initializing);
    payload.ownerThreadId=GetCurrentThreadId();
    return InitializeStatusV3(RS2SteamReport_StatusV3,header,payload);
}
} // namespace

void StartReporting(const BootstrapContextV3& context, const StartupProfile& startup,
    const observer::Profile& observerProfile, const Sha256Digest& hostDigest,
    HostHashLease& hostLease, const wchar_t* directory, bool reconEligible,const NativeStartupSummary& startupSummary) noexcept {
    ConfigV3 config{}; DWORD error{};
    const auto configured=ReadConfigV3(directory,&config,&error);
    const auto& identities=SelectedReportingIdentities();
    const bool hostValid=hostLease.valid() && hostDigest==identities.hostDigest &&
        hostDigest==observerProfile.hostDigest;
    if (!Header(config,configured==Reason::None || configured==Reason::ConfigDisabled,hostDigest,hostValid)) return;
    if (configured!=Reason::None) { Reject(configured); return; }
    if (!reconEligible) { Reject(Reason::ReconIneligible); return; }
    if (!hostValid) { Reject(Reason::HostMismatch); return; }
    if (RS2SteamReport_StatusV3.header.validity!=CompleteHeaderIdentity) {
        Reject(Reason::IdentityIncomplete); return;
    }
    if (observerProfile.sdkDigest!=identities.steamApiDigest ||
        observer::CheckColdProfile(context,startup,observerProfile,ProductionMemoryOps(),&error)!=observer::Reason::None) {
        Reject(Reason::ProfileMismatch); return;
    }
    const auto base=reinterpret_cast<std::uintptr_t>(context.hostModule);
    const auto& profile=SelectedReportingProfile();
    if (ValidateNativeLoggingProfile(base,startup,SelectedNativeLoggingProfile(),
        ProductionMemoryOps(),ProductionNativeImportOps(),&error)!=ProfileResult::Ready) {
        Reject(Reason::ProfileMismatch); return;
    }
    std::uintptr_t nativePump{};
    if (ValidateReportingProfile(base,startup,profile,ProductionMemoryOps(),&nativePump,&error)!=ProfileResult::Ready) {
        Reject(Reason::ProfileMismatch); return;
    }
    HostHashLease sdkLease;
    observer::DispatchConfig dispatch{};
    if (observer::QualifySdk(context,startup,observerProfile,&sdkLease,&dispatch,&error)!=observer::Reason::None) {
        Reject(Reason::SdkMismatch); return;
    }
    observer::ShutdownFn originalPump{};
    if (observer::QualifyServerPump(context,startup,observerProfile,dispatch,profile.pump.slotRva,
        &originalPump,&error)!=observer::Reason::None ||
        reinterpret_cast<std::uintptr_t>(originalPump)!=nativePump) { Reject(Reason::SdkMismatch); return; }

    void* storage=VirtualAlloc(nullptr,sizeof(Resident),MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    auto* resident=storage ? ::new(storage) Resident{} : nullptr;
    if (!resident) { Reject(Reason::PreparationFailed); return; }
    // A partially prepared writer may retain these addresses. This bounded
    // process-lifetime allocation is intentionally never raced by cleanup/free.
    if (!InitializeReportRing(resident->ring,RS2SteamReport_StatusV3,context.startupThreadId)) {
        Reject(Reason::PreparationFailed,resident); return;
    }
    auto* writer=PrepareNativeTransport(RS2SteamReport_StatusV3,resident->ring,config,
        identities,context.startupThreadId,&error);
    if (!writer) { Reject(Reason::PreparationFailed,resident); return; }
    if (!CompleteNativeTransportStartup(writer,startupSummary)) {
        Reject(Reason::PreparationFailed,resident,writer); return;
    }
    RuntimeConfig runtime{};
    runtime.mode=config.mode; runtime.diagnostics=config.diagnostics; runtime.nativeTransport=writer;
    runtime.ownerThreadId=context.startupThreadId;
    runtime.hostBase=base; runtime.hostSize=startup.imageSize;
    runtime.memory=ProductionMemoryOps(); runtime.dispatch=&resident->dispatch;
    runtime.status=&RS2SteamReport_StatusV3; runtime.sink=ReportRingSink(resident->ring);
    runtime.pumpOriginal=originalPump;
    runtime.task=SelectedTaskLayout();
    runtime.builderOriginal=reinterpret_cast<BuilderFn>(base+runtime.task.builderRva);
    runtime.builderWrapper=reinterpret_cast<std::uintptr_t>(&BuilderEntry);
    runtime.source=SelectedSourceLayout(); runtime.prepared=SelectedPreparedLayout();
    runtime.ancestry=SelectedAncestryProfile();
    runtime.qualifyClient=QualifyLoadedSteamClient;
    runtime.recovery=&resident->recovery;
    // P4 consumes coherent owner/worker DATA; no hook-side console formatting.
    const auto initialized=InitializeRuntime(resident->runtime,runtime,RS2SteamReport_StatusV3.header.qpcFrequency);
    if (initialized!=Reason::None) { Reject(initialized,resident,writer); return; }
    const NativeLogReadContext nativeLog{ProductionMemoryOps(),base,startup.imageSize,context.startupThreadId,&SelectedNativeLogLayout()};
    if (!InitializeNativeLogService(resident->runtime.nativeLog,RS2SteamReport_StatusV3,
        resident->runtime.transport,writer,nativeLog,kSelectedNativeLogEntry)) {
        Reject(Reason::PreparationFailed,resident,writer); return;
    }
    HMODULE companion{};
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&StartReporting),&companion) ||
        !PrepareRuntimeCapture(resident->runtime,companion)) {
        Reject(Reason::ProfileMismatch,resident,writer); return;
    }
    // This capability is optional and startup-disabled. A failed third profile
    // cannot alter publication of the two existing reporting capture profiles.
    PrepareLeechRecovery(resident->recovery,resident->runtime,startup,directory,companion);
    AttachNativeTransportRecovery(writer,&RS2LeechRecovery_StatusV1);
    dispatch.lifecycleSink=RuntimeLifecycleSink(resident->runtime);
    observer::InitializeDispatch(resident->dispatch,dispatch,{});
    if (!PublishRuntime(resident->runtime) || !observer::PublishDispatch(resident->dispatch)) {
        Reject(Reason::PreparationFailed,resident,writer); return;
    }
    ProfileCheck check{base,&startup,&profile}; // Synchronous transaction only.
    const observer::ServerPumpCell pump{profile.pump.slotRva,originalPump,PumpEntry,&check,Recheck};
    const auto installed=observer::InstallObserverWithLeases(context,startup,observerProfile,
        resident->dispatch,hostLease,sdkLease,&pump);
    if (!installed.armed) {
        Reject(Reason::InstallFailed,resident,writer);
        if (installed.fatal) observer::FailFastObserverInstallation(installed);
        return;
    }
    ArmNativeTransport(writer);
    if (!StatusRevoked(RS2SteamReport_StatusV3)) ArmLeechRecovery(resident->recovery);
}
} // namespace rs2fix::reporting
