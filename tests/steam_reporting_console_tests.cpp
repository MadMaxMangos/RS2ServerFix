#include "companion/steam_reporting_console.h"
#include "test_framework.h"
#include <cstring>
#include <thread>

namespace rs2fix::testcases {
namespace {
using namespace reporting;
struct Fixture {
    StatusWireV3 wire{};
    RecoveryStatusWireV1 recovery{};
    ReportingConsole console{};
    std::uint64_t ticks{},qpc=1000;
    unsigned starts{},writes{};
    bool missing{},fail{},shortWrite{},startFail{},clockFail{},pauseAtHandle{},stopAtHandle{},advancingClock{};
    bool inFlightEven{};
    HANDLE entered{},release{};
    char last[kConsoleLineCapacity]{};
    static ULONGLONG Ticks(void* p) noexcept { return static_cast<Fixture*>(p)->ticks; }
    static bool Clock(void* p,std::uint64_t* value) noexcept {
        auto& f=*static_cast<Fixture*>(p); *value=f.qpc;
        if(f.advancingClock) ++f.qpc;
        return !f.clockFail;
    }
    static void SleepFor(void*,DWORD) noexcept {}
    static HANDLE Output(void* p,DWORD* error) noexcept {
        auto& f=*static_cast<Fixture*>(p); *error=0;
        if(f.pauseAtHandle) {
            StoreStatusWord(f.wire.workerPauseReason,static_cast<std::uint64_t>(TransportReason::ReaderBehind));
            f.pauseAtHandle=false;
        }
        if(f.stopAtHandle) StopStatus(f.wire,f.qpc);
        return f.missing ? nullptr : reinterpret_cast<HANDLE>(1);
    }
    static bool Write(void* p,HANDLE,const void* line,DWORD bytes,DWORD* written,DWORD* error) noexcept {
        auto& f=*static_cast<Fixture*>(p); ++f.writes;
        f.inFlightEven=!(ReadStatusWord(f.wire.consoleSequence)&1) &&
            ReadStatusWord(f.wire.console.workerState)==2 && ReadStatusWord(f.wire.console.attempts)>0;
        std::memcpy(f.last,line,bytes); f.last[bytes]=0;
        if(f.entered) { SetEvent(f.entered); WaitForSingleObject(f.release,INFINITE); }
        *written=f.shortWrite ? bytes-1 : bytes;
        *error=f.fail ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
        return !f.fail;
    }
    static HANDLE Start(void* p,LPTHREAD_START_ROUTINE,void*,DWORD* error) noexcept {
        auto& f=*static_cast<Fixture*>(p); ++f.starts;
        *error=f.startFail ? ERROR_NOT_ENOUGH_MEMORY : 0;
        return f.startFail ? nullptr : reinterpret_cast<HANDLE>(2);
    }
    ConsoleStatusOps Ops() { return {this,Ticks,SleepFor,Output,Write,Start,nullptr}; }
    Fixture() {
        StatusHeader h{}; h.pid=17; h.processCreation=42; h.qpcFrequency=1000;
        h.configuredMode=static_cast<unsigned>(Mode::Repair); h.runId[0]=1; h.hostDigest[0]=2;
        h.validity=CompleteHeaderIdentity;
        StatusPayload owner{}; owner.ownerThreadId=7; owner.lastOwnerQpc=qpc;
        owner.phase=static_cast<unsigned>(ReportPhaseV3::WaitingLogger);
        RS2_CHECK(InitializeStatusV3(wire,h,owner));
    }
    void StartConsole(bool attachRecovery=false) {
        RS2_CHECK(StartReportingConsole(console,wire,Ops(),Clock).started);
        if (attachRecovery) RS2_CHECK(AttachReportingConsoleRecovery(console,&recovery));
        ArmReportingConsole(console);
    }
    void Recover(RecoveryPhase phase,RecoveryReason reason,std::uint64_t transition,bool terminal=false) {
        if (!recovery.headerReady) RS2_CHECK(InitializeRecoveryStatus(recovery,wire.header));
        ReportRecoveryPayload p{};
        p.phase=static_cast<std::uint64_t>(phase); p.event=static_cast<std::uint64_t>(RecoveryEvent::Transition);
        p.reason=static_cast<std::uint64_t>(reason); p.operationSequence=1; p.transitionSequence=transition;
        p.qpc=qpc; p.flags=RecoveryPermissionEnabled;
        if (terminal) p.flags|=RecoveryTerminal|RecoveryRestartRequired;
        RS2_CHECK(PublishRecoveryStatus(recovery,p));
    }
    bool Step(std::uint64_t ms=0) {
        ticks+=ms; qpc=1000+ticks;
        auto owner=wire.owner; owner.lastOwnerQpc=qpc;
        RS2_CHECK(PublishOwnerV3(wire,owner,wire.ownerTransport));
        return CycleReportingConsole(console);
    }
    void Ready(bool publishTrigger=true) {
        if(!ReadStatusWord(wire.logIdentityReady)) {
            LogIdentity log{}; constexpr char16_t path[]=u"E:\\logs\\Launch.log";
            std::memcpy(log.path,path,sizeof(path)); log.pathChars=std::size(path)-1;
            log.transportKind=1; log.utcFiletime=1; log.calibrationQpcBefore=log.calibrationQpcAfter=100;
            RS2_CHECK(PublishLogIdentityV3(wire,log));
        }
        auto owner=wire.owner; owner.sourceEpoch=owner.bindingEpoch=1; owner.builderBound=1;
        owner.phase=static_cast<unsigned>(ReportPhaseV3::Repairing); owner.readyQpc=publishTrigger ? qpc : 0;
        auto t=wire.ownerTransport; t.state=static_cast<unsigned>(TransportState::Running);
        t.reason=0; t.startupSubmitted=1; t.actualRepairAdmitted=1; t.qualifiedSinkEpoch=1;
        RS2_CHECK(PublishOwnerV3(wire,owner,t));
        auto w=wire.worker; w.startupObserved=1; w.pauseReason=0;
        RS2_CHECK(PublishWorkerV3(wire,w));
    }
    void WorkerPause(bool pause) {
        auto w=wire.worker; w.pauseReason=pause ? static_cast<unsigned>(TransportReason::ReaderBehind) : 0;
        ++w.pauseConditionSequence; w.pauseConditionQpc=qpc;
        RS2_CHECK(PublishWorkerV3(wire,w));
    }
    bool Has(const char* value) const { return std::strstr(last,value)!=nullptr; }
};
void StateAndCadence() {
    Fixture f; f.StartConsole();
    RS2_CHECK(f.Step() && f.Has("status=waiting-logger") && f.Has("event=initial"));
    RS2_CHECK(f.inFlightEven && f.console.diagnostics.written==1);
    f.Ready(false); RS2_CHECK(f.Step(1000));
    RS2_CHECK(!f.Has("status=ready")); // No ManagePump readyQpc, no initial ready claim.
    f.Ready(); RS2_CHECK(f.Step(1000) && f.Has("status=ready") && f.Has("event=initial"));
    const auto before=f.console.diagnostics.attempts;
    f.WorkerPause(true); RS2_CHECK(f.Step(100));
    f.WorkerPause(false); RS2_CHECK(f.Step(100));
    f.WorkerPause(true); RS2_CHECK(f.Step(100));
    RS2_CHECK(f.console.diagnostics.attempts==before && f.console.diagnostics.skippedTransitions==2);
    RS2_CHECK(f.Step(700) && f.Has("status=paused") && f.Has("reason=reader-behind"));
    RS2_CHECK(f.console.diagnostics.attempts==before+1 && f.Has("worker_condition=3"));
    f.WorkerPause(false); RS2_CHECK(f.Step(1000) && f.Has("status=ready") && f.Has("event=resumed"));
    RS2_CHECK(f.Step(1000) && f.console.diagnostics.attempts==before+2); // No heartbeat spam.
    RS2_CHECK(StartReportingConsole(f.console,f.wire,f.Ops(),Fixture::Clock).error==ERROR_ALREADY_EXISTS);
    RS2_CHECK(f.starts==1 && !StatusRevoked(f.wire));
}
void LatestStateAndFailure() {
    {
        Fixture f; f.Ready(); f.StartConsole();
        // A coherent owner publication one tick after the worker's first clock
        // is normal concurrency, not a request-floor or transport pause.
        auto owner=f.wire.owner; owner.lastOwnerQpc=f.qpc+1;
        owner.reason=static_cast<unsigned>(Reason::RequestFloor);
        RS2_CHECK(PublishOwnerV3(f.wire,owner,f.wire.ownerTransport));
        f.advancingClock=true;
        RS2_CHECK(CycleReportingConsole(f.console) && f.Has("status=ready") && !f.Has("status=paused"));
        RS2_CHECK(!StatusRevoked(f.wire));
    }
    {
        Fixture f; f.StartConsole(); StoreStatusWord(f.wire.ownerSequence,3);
        RS2_CHECK(CycleReportingConsole(f.console));
        RS2_CHECK(f.wire.console.workerState==1 && f.wire.console.lastError==ERROR_RETRY && !f.writes);
        RS2_CHECK(!StatusRevoked(f.wire));
        StoreStatusWord(f.wire.ownerSequence,2); RS2_CHECK(f.Step() && f.writes==1);
    }
    {
        Fixture f; f.Ready(); f.StartConsole(); f.pauseAtHandle=true;
        RS2_CHECK(f.Step() && f.writes==0 && f.console.diagnostics.attempts==0);
        RS2_CHECK(f.Step() && f.Has("status=paused") && !f.Has("status=ready"));
    }
    {
        Fixture f; f.Ready(); f.StartConsole(); f.fail=true;
        RS2_CHECK(f.Step() && f.console.diagnostics.failures==1 && f.inFlightEven);
        RS2_CHECK(f.Step(999) && f.writes==1);
        f.fail=false; RS2_CHECK(f.Step(1) && f.writes==2 && f.console.diagnostics.written==1);
        RS2_CHECK(f.console.diagnostics.lastError==0 && !StatusRevoked(f.wire));
        f.WorkerPause(true); f.shortWrite=true; RS2_CHECK(f.Step(1000));
        RS2_CHECK(f.console.diagnostics.failures==2 && f.console.diagnostics.lastError==ERROR_WRITE_FAULT);
    }
    {
        Fixture f; f.StartConsole(); f.missing=true;
        RS2_CHECK(f.Step() && f.writes==0 && f.console.diagnostics.failures==1);
        f.missing=false; RS2_CHECK(f.Step(1000) && f.writes==1);
        RS2_CHECK(!StatusRevoked(f.wire));
    }
    {
        Fixture f; f.StartConsole(); f.stopAtHandle=true;
        RS2_CHECK(!f.Step() && !f.writes && !f.console.diagnostics.attempts && f.console.diagnostics.workerState==3);
    }
    {
        Fixture f; f.Ready(); f.StartConsole(); LatchTransportFault(f.wire,TransportReason::NativeLogException);
        RS2_CHECK(f.Step() && f.Has("status=disabled") && f.Has("event=disabled"));
        RS2_CHECK(f.Has("reason_domain=transport") && f.Has("reason=native-log-exception"));
    }
    {
        Fixture f; f.Ready(); f.StartConsole(); RevokeStatus(f.wire,Reason::ForeignThread);
        RS2_CHECK(f.Step() && f.Has("reason_domain=runtime") && f.Has("reason=foreign-thread"));
    }
    {
        Fixture f; f.startFail=true;
        RS2_CHECK(!StartReportingConsole(f.console,f.wire,f.Ops(),Fixture::Clock).started);
        RS2_CHECK(f.wire.console.workerState==3 && f.wire.console.lastError==ERROR_NOT_ENOUGH_MEMORY);
        RS2_CHECK(!StatusRevoked(f.wire));
    }
    {
        Fixture f; f.StartConsole(); f.clockFail=true;
        RS2_CHECK(f.Step() && !f.writes && !StatusRevoked(f.wire));
        f.clockFail=false; RS2_CHECK(f.Step(1000) && f.writes==1);
        StopReportingConsole(f.console); RS2_CHECK(!f.Step() && f.writes==1);
    }
}
void BlockedOutput() {
    Fixture f; f.Ready(); f.StartConsole();
    f.entered=CreateEventW(nullptr,TRUE,FALSE,nullptr); f.release=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    RS2_CHECK(f.entered && f.release);
    std::thread worker([&]{ CycleReportingConsole(f.console); });
    RS2_CHECK(WaitForSingleObject(f.entered,5000)==WAIT_OBJECT_0);
    RS2_CHECK(ReadStatusWord(f.wire.console.workerState)==2 && !(ReadStatusWord(f.wire.consoleSequence)&1));
    // Main/receipt publication is still usable while stdout has not returned.
    f.WorkerPause(true);
    RS2_CHECK(ReadStatusWord(f.wire.workerPauseReason)==static_cast<unsigned>(TransportReason::ReaderBehind));
    RS2_CHECK(!StatusRevoked(f.wire));
    StopReportingConsole(f.console); SetEvent(f.release); worker.join();
    RS2_CHECK(f.writes==1 && f.inFlightEven && f.console.diagnostics.workerState==3);
    RS2_CHECK(!f.Step() && f.writes==1 && f.starts==1);
    CloseHandle(f.entered); CloseHandle(f.release);
}
void FormatBounds() {
    StatusHeader header{}; header.pid=UINT32_MAX; header.configuredMode=static_cast<unsigned>(Mode::Observe);
    std::memset(header.runId,0xff,sizeof(header.runId));
    for(unsigned domain=0;domain<2;++domain) {
        const auto count=domain ? static_cast<unsigned>(TransportReason::Count) : kReasonCount;
        for(std::uint64_t reason=0;reason<count;++reason) {
            ConsoleNoticeV3 n{ConsoleStateV3::WaitingLogger,domain!=0,reason,UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX};
            ConsoleReportContext report{};
            RS2_CHECK(FormatReportingConsoleNotice(header,n,"disabled",&report));
            RS2_CHECK(ValidConsoleReport(report) && report.bytes<kConsoleLineCapacity);
        }
    }
}
void RecoveryIndependenceAndCadence() {
    {
        Fixture f;
        f.Recover(RecoveryPhase::Failed,RecoveryReason::ClockFault,3,true);
        f.wire.owner.phase=UINT64_MAX; // Immutable header remains qualified; ordinary CORE is invalid.
        f.StartConsole(true);
        RS2_CHECK(f.Step() && f.Has("[RS2LeechRecovery] v0.7.1.0") && f.Has("phase=failed"));
        RS2_CHECK(f.Has("reason=clock-fault") && f.Has("transition=3") && f.Has("last_valid_qpc=1000"));
        RS2_CHECK(f.Has("restart_required=1") && f.Has("pid=17") && f.inFlightEven);
        RS2_CHECK(f.console.diagnostics.written==1 && f.console.diagnostics.lastNoticeEpoch==3);
        RS2_CHECK(f.Step(1000) && f.writes==1 && f.console.diagnostics.workerState==1); // No recovery heartbeat spam.
    }
    {
        Fixture f;
        f.Recover(RecoveryPhase::Failed,RecoveryReason::RecordingUnavailable,4,true);
        auto t=f.wire.ownerTransport; t.state=static_cast<std::uint64_t>(TransportState::Stopping);
        RS2_CHECK(PublishOwnerV3(f.wire,f.wire.owner,t)); // Normal selection refuses; no explicit stop gate is set.
        f.StartConsole(true);
        RS2_CHECK(f.Step() && f.Has("[RS2LeechRecovery]") && f.Has("reason=recording-unavailable"));
        RS2_CHECK(f.Step(1000) && f.console.diagnostics.workerState==1 && f.writes==1);
        StopReportingConsole(f.console); RS2_CHECK(!f.Step() && f.console.diagnostics.workerState==3);
    }
    {
        Fixture f; f.Ready(); f.Recover(RecoveryPhase::Failed,RecoveryReason::NativeException,5,true);
        f.StartConsole(true);
        RS2_CHECK(f.Step() && f.Has("[RS2LeechRecovery]")); // Recovery terminal has priority over ordinary ready.
        RS2_CHECK(f.Step(999) && f.writes==1);
        RS2_CHECK(f.Step(1) && f.writes==2 && f.Has("[RS2SteamReport] v0.7.1.0") && f.Has("status=ready"));
        f.Recover(RecoveryPhase::Failed,RecoveryReason::CreateFailed,6,true);
        RS2_CHECK(f.Step(100) && f.writes==2);
        f.Recover(RecoveryPhase::Failed,RecoveryReason::ClockFault,7,true);
        RS2_CHECK(f.Step(100) && f.writes==2 && f.console.diagnostics.skippedTransitions==1);
        RS2_CHECK(f.Step(800) && f.writes==3 && f.Has("transition=7") && f.Has("reason=clock-fault"));
        RS2_CHECK(f.console.diagnostics.attempts==3 && f.console.diagnostics.written==3);
    }
    {
        Fixture f;
        RS2_CHECK(InitializeRecoveryStatus(f.recovery,f.wire.header)); // Disabled all-zero payload remains silent.
        f.StartConsole(true);
        RS2_CHECK(f.Step() && f.Has("[RS2SteamReport]") && !f.Has("[RS2LeechRecovery]"));
        RS2_CHECK(f.Step(1000) && f.writes==1);
        RS2_CHECK(!AttachReportingConsoleRecovery(f.console,&f.recovery)); // Never attach/change after arm.
    }
    {
        Fixture f; f.Recover(RecoveryPhase::Failed,RecoveryReason::ClockFault,1,true);
        f.StartConsole(true); f.recovery.runId[0]=9;
        f.wire.owner.phase=UINT64_MAX;
        RS2_CHECK(f.Step() && !f.writes && f.console.diagnostics.workerState==1); // Wrong run never bypasses normal fault.
    }
    {
        Fixture f; f.Recover(RecoveryPhase::Failed,RecoveryReason::ClockFault,1,true); f.StartConsole(true);
        StoreStatusWord(f.wire.consoleSequence,3);
        RS2_CHECK(!f.Step() && !f.writes && f.console.diagnostics.workerState==3); // Publication failure is terminal.
    }
}
}
void ReportingConsoleTests() { StateAndCadence(); LatestStateAndFailure(); BlockedOutput(); FormatBounds(); RecoveryIndependenceAndCadence(); }
}
