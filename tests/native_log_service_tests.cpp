#include "companion/steam_reporting_native_log.h"
#include "test_framework.h"
#include <cstring>
#include <memory>
#include <thread>

namespace rs2fix::testcases {
namespace {
using namespace reporting;
constexpr DWORD kOutgoing=0x12348765;
constexpr DWORD kFixtureException=0xE1234567;
struct Fixture {
    StatusWireV3 status{};
    OwnerTransport owner{};
    NativeLogService service{};
    NativeReadyFrame frames[20]{};
    NativeLogSnapshot snapshot{};
    std::uint64_t now=1000,qualified{};
    std::uint32_t current{},calls{},reads{},requests{},returns{},clockCalls{};
    bool autoObserve=true,delayFirst{},changeDuringCall{},throwCpp{},throwSeh{},failEndClock{};
    TransportReason refuse=TransportReason::None;
    struct Exception {};
    static TransportReason Snapshot(void* ptr,NativeLogSnapshot* out) noexcept {
        auto& f=*static_cast<Fixture*>(ptr); ++f.reads;
        *out=f.snapshot; SetLastError(0xAABBCCDD); return f.refuse;
    }
    static bool Request(void* ptr,std::uint64_t epoch,const NativeLogSnapshot&) noexcept {
        auto& f=*static_cast<Fixture*>(ptr); ++f.requests; f.qualified=epoch; return true;
    }
    static std::uint64_t Qualified(void* ptr) noexcept { return static_cast<Fixture*>(ptr)->qualified; }
    static const NativeReadyFrame* Front(void* ptr,std::uint64_t) noexcept {
        auto& f=*static_cast<Fixture*>(ptr);
        return f.current<std::size(f.frames) ? &f.frames[f.current] : nullptr;
    }
    static bool Returned(void* ptr,std::uint64_t ticket) noexcept {
        auto& f=*static_cast<Fixture*>(ptr);
        if (ticket!=f.current+1) return false;
        if (!f.current && f.autoObserve) StoreStatusWord(f.status.worker.startupObserved,1);
        ++f.current; ++f.returns; return true;
    }
    static bool Clock(void* ptr,std::uint64_t* out) noexcept {
        auto& f=*static_cast<Fixture*>(ptr); ++f.clockCalls;
        if (f.failEndClock && f.calls) return false;
        *out=f.now; return true;
    }
    static void Log(void* ptr,const wchar_t*) {
        auto& f=*static_cast<Fixture*>(ptr);
        RS2_CHECK(GetLastError()==kOutgoing);
        ++f.calls; SetLastError(0xF0F0F0F0);
        if (f.throwCpp) throw Exception{};
        if (f.throwSeh) RaiseException(kFixtureException,0,0,nullptr);
        if (f.delayFirst && f.calls==1) f.now+=260;
        if (f.changeDuringCall) { f.changeDuringCall=false; ++f.snapshot.file; }
    }
    Fixture() {
        StatusHeader header{}; header.qpcFrequency=1000; header.validity=CompleteHeaderIdentity;
        header.configuredMode=2; header.pid=GetCurrentProcessId(); header.runId[0]=1;
        RS2_CHECK(InitializeStatusV3(status,header,{}));
        owner.generatedSequence=19;
        snapshot.redirector=reinterpret_cast<std::uintptr_t>(this);
        snapshot.file=100; snapshot.archive=200;
        snapshot.pathChars=1; snapshot.path[0]='E'; // Copied token only in this service seam.
        constexpr char message[]="[RS2ServerFix:event] {\"fixture\":true}";
        for (unsigned i=0;i<std::size(frames);++i) {
            frames[i].ticket=i+1; frames[i].sequence=i; frames[i].chars=sizeof(message)-1;
            RS2_CHECK(native_log::PrepareMessage(message,sizeof(message)-1,frames[i].message,std::size(frames[i].message)));
        }
        const NativeLogServiceOps ops{this,Snapshot,Request,Qualified,Front,Returned,Clock};
        RS2_CHECK(InitializeNativeLogServiceForTest(service,status,owner,GetCurrentThreadId(),ops,Log));
    }
    NativeServiceResult Run(CallerClass caller=CallerClass::NormalPump,bool top=true) {
        return ServiceNativeLog(service,caller,top,now,kOutgoing);
    }
};
void AdmissionAndBarrier() {
    auto f=std::make_unique<Fixture>();
    RS2_CHECK(f->Run(CallerClass::KnownSpin).submitted==0 && !f->reads && !StatusRevoked(f->status));
    RS2_CHECK(f->Run(CallerClass::NormalPump,false).submitted==0 && !f->reads);
    std::thread foreign([&] { RS2_CHECK(f->Run().submitted==0); }); foreign.join();
    RS2_CHECK(!f->reads && !f->calls);
    f->autoObserve=false;
    auto first=f->Run();
    RS2_CHECK(first.qualified && first.submitted==1 && f->owner.startupSubmitted==1);
    RS2_CHECK(f->calls==1 && f->returns==1 && GetLastError()==kOutgoing);
    f->now+=250;
    RS2_CHECK(f->Run().submitted==0 && f->calls==1); // Positive frame waits physical receipt.
    StoreStatusWord(f->status.worker.startupObserved,1); f->now+=250;
    RS2_CHECK(f->Run().submitted==2 && f->owner.submittedSequence==2);
    f->refuse=TransportReason::CategorySuppressed; f->now+=250;
    RS2_CHECK(f->Run().reason==TransportReason::CategorySuppressed && f->calls==3 && !StatusRevoked(f->status));
    f->refuse=TransportReason::None; f->now+=250;
    RS2_CHECK(f->Run().submitted==2 && !StatusRevoked(f->status));
}
void SlidingRate() {
    auto f=std::make_unique<Fixture>();
    f->delayFirst=true;
    RS2_CHECK(f->Run().submitted==2 && f->now==1260);
    RS2_CHECK(f->Run().submitted==2); // First native call delayed this opportunity.
    f->now=1510; RS2_CHECK(f->Run().submitted==2);
    f->now=1760; RS2_CHECK(f->Run().submitted==2);
    f->now=2010; RS2_CHECK(f->Run().submitted==1); // Only oldest single call expired.
    RS2_CHECK(f->calls==9 && f->owner.submitWindowCount==8);
    RS2_CHECK(f->owner.nativeSubmitCalls==9 && f->owner.nativeSubmitElapsedTicks==260);
    RS2_CHECK(f->owner.nativeSubmitMaximumTicks==260 && f->owner.nativeSubmitOverFiveMilliseconds==1);
    f->now=2100; RS2_CHECK(f->Run().submitted==0 && f->calls==9);
}
void ChangedSinkAndDamage() {
    auto f=std::make_unique<Fixture>(); f->changeDuringCall=true;
    const auto result=f->Run();
    RS2_CHECK(result.submitted==1 && !result.qualified && result.reason==TransportReason::SameFileRequalification);
    RS2_CHECK(f->requests==2 && !StatusRevoked(f->status));
    f->now+=250; RS2_CHECK(f->Run().submitted==2);
    auto damaged=std::make_unique<Fixture>();
    damaged->frames[0].message[30]=0x010A;
    RS2_CHECK(damaged->Run().submitted==0 && damaged->calls==0 && StatusRevoked(damaged->status));
    auto clock=std::make_unique<Fixture>(); clock->failEndClock=true;
    RS2_CHECK(clock->Run().submitted==1 && clock->owner.startupSubmitted==1 && clock->returns==1);
    RS2_CHECK(StatusRevoked(clock->status) && clock->owner.nativeSubmitCalls==1);
}
bool CatchSeh(Fixture* f) {
    __try { f->Run(); }
    __except(GetExceptionCode()==kFixtureException ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return true;
    }
    return false;
}
void Exceptions() {
    auto cpp=std::make_unique<Fixture>(); cpp->throwCpp=true;
    bool caught{};
    try { cpp->Run(); } catch (const Fixture::Exception&) { caught=true; }
    RS2_CHECK(caught && cpp->returns==0 && cpp->owner.startupSubmitted==0);
    RS2_CHECK(cpp->status.fatalTransportReason==static_cast<std::uint64_t>(TransportReason::NativeLogException));
    RS2_CHECK(GetLastError()==kOutgoing);
    auto seh=std::make_unique<Fixture>(); seh->throwSeh=true;
    RS2_CHECK(CatchSeh(seh.get()) && seh->returns==0 && seh->owner.startupSubmitted==0);
    RS2_CHECK(seh->status.fatalTransportReason==static_cast<std::uint64_t>(TransportReason::NativeLogException));
    RS2_CHECK(GetLastError()==kOutgoing);
}
}
void NativeLogServiceTests() { AdmissionAndBarrier(); SlidingRate(); ChangedSinkAndDamage(); Exceptions(); }
}

