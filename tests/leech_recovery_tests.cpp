#include "companion/leech_recovery.h"
#include "companion/steam_reporting_runtime.h"
#include "leech_recovery_native_fixture.h"
#include "test_framework.h"
#include <cstring>
#include <initializer_list>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace rs2fix::testcases {
namespace {
using namespace reporting;
volatile LONG nativeCalls{};
void NativeVoid() { InterlockedIncrement(&nativeCalls); }
void NativeHolder(std::uint32_t*) { InterlockedIncrement(&nativeCalls); }
void NativeSlot(void*,std::uint16_t) { InterlockedIncrement(&nativeCalls); }
std::uint64_t Now() {
    LARGE_INTEGER qpc{}; RS2_CHECK(QueryPerformanceCounter(&qpc) && qpc.QuadPart>0);
    return static_cast<std::uint64_t>(qpc.QuadPart);
}
struct Fixture {
    StatusWireV3 status{};
    RecoveryStatusWireV1 recoveryStatus{};
    ReportRingV3 ring{};
    observer::DispatchState dispatch{};
    Runtime runtime{};
    std::unique_ptr<LeechRecovery> recovery=std::make_unique<LeechRecovery>();
    unsigned char callbackByte{1};
    std::uint64_t memoryReads{},memoryQueries{};
    std::uint64_t frequency{};
    Fixture() {
        InterlockedExchange(&nativeCalls,0);
        LARGE_INTEGER clock{}; RS2_CHECK(QueryPerformanceFrequency(&clock) && clock.QuadPart>0);
        frequency=static_cast<std::uint64_t>(clock.QuadPart);
        StatusHeader header{};
        header.pid=GetCurrentProcessId();header.processCreation=1;header.runId[0]=1;header.hostDigest[0]=1;
        header.validity=CompleteHeaderIdentity;header.configuredMode=static_cast<std::uint32_t>(Mode::Repair);
        header.qpcFrequency=frequency;
        RS2_CHECK(InitializeStatusV3(status,header,{}));
        RS2_CHECK(InitializeRecoveryStatus(recoveryStatus,status.header));
        RS2_CHECK(InitializeReportRing(ring,status,GetCurrentThreadId()));
        observer::InitializeDispatch(dispatch,{},{});
        InterlockedExchange(&dispatch.gate,static_cast<LONG>(observer::Gate::Armed));
        InterlockedExchange64(&dispatch.lifecycle,static_cast<LONG64>(1ULL<<32));
        runtime.config.ownerThreadId=GetCurrentThreadId();runtime.config.status=&status;runtime.config.dispatch=&dispatch;
        runtime.config.sink=ReportRingSink(ring);runtime.config.mode=Mode::Repair;
        runtime.config.memory={this,Query,Read};runtime.config.hostBase=0x1000;runtime.config.hostSize=0x2000000;
        runtime.config.recovery=recovery.get();runtime.sdkReady=true;runtime.sourceReady=true;
        runtime.idleLifecycle=1ULL<<32;runtime.producer.frequency=static_cast<std::int64_t>(frequency);
        runtime.pumpDepth=1;runtime.timingDepth=1;runtime.counters.sourceEpoch=1;runtime.counters.bindingEpoch=1;
        runtime.transport.state=static_cast<std::uint64_t>(TransportState::Running);
        runtime.transport.startupSubmitted=1;runtime.transport.qualifiedSinkEpoch=1;
        StoreStatusWord(status.logIdentityReady,1);StoreStatusWord(status.worker.startupObserved,1);
        auto& r=*recovery;
        r.runtime=&runtime;r.status=&recoveryStatus;r.prepared=true;r.controlStarted=true;
        r.startup.imageSize=runtime.config.hostSize;r.startup.checksumCount=1;r.startup.checksums[0]=1;r.startup.timestamp=1;
        r.native={runtime.config.hostBase,runtime.config.hostSize,runtime.config.memory,
            &ProductionNativeImportOps(),&ProductionRecoveryNativeLayout()};
        r.calls.cleanup=NativeVoid;r.calls.start=NativeVoid;r.calls.create=NativeVoid;r.calls.cancel=NativeHolder;
        r.calls.releaseHolder=NativeHolder;r.calls.finishRelease=NativeSlot;
        r.value.ownerThreadId=GetCurrentThreadId();r.value.phase=static_cast<std::uint64_t>(RecoveryPhase::Armed);
        r.value.flags=RecoveryPermissionEnabled;r.value.transitionSequence=1;r.value.qpc=Now();
        r.value.sourceEpoch=1;r.value.sdkEpoch=runtime.idleLifecycle;
        r.control.result=static_cast<LONG>(rs2fix::recovery::ControlResult::Ready);
        r.control.identity.pid=header.pid;r.control.identity.runId[0]=1;
        r.control.scope=rs2fix::recovery::kTrainingControlScope;
        RS2_CHECK(PublishRecoveryStatus(recoveryStatus,r.value));
    }
    ~Fixture() { SetLeechRecoveryCurrentForTest(nullptr); }
    static bool Query(void* context,std::uintptr_t,MemoryRegion*,DWORD* error) noexcept {
        ++static_cast<Fixture*>(context)->memoryQueries;*error=ERROR_INVALID_ADDRESS;return false;
    }
    static bool Read(void* context,std::uintptr_t address,void* output,std::size_t bytes,DWORD* error) noexcept {
        auto& f=*static_cast<Fixture*>(context);++f.memoryReads;
        if(address==reinterpret_cast<std::uintptr_t>(&f.callbackByte) && bytes==1) {
            std::memcpy(output,&f.callbackByte,1);*error=ERROR_SUCCESS;return true;
        }
        *error=ERROR_PARTIAL_COPY;return false;
    }
    void FinishPhase(RecoveryPhase phase=RecoveryPhase::FinishSubmitted) {
        auto& r=*recovery;r.requested=true;r.cancelEntered=true;r.enqueueReturned=true;r.finishId=17;
        r.value.operationSequence=1;r.value.transitionSequence=4;r.value.requestId=17;
        r.value.phase=static_cast<std::uint64_t>(phase);
        r.value.flags|=RecoveryCancellationCompleted|RecoveryAttributionValid;
        r.value.qpc=Now();r.value.finishDeadlineQpc=r.value.qpc+frequency*60;r.value.overallDeadlineQpc=r.value.qpc+frequency*120;
        runtime.bindingSuspended=true;
    }
    std::vector<ReportRecordV3> Records() {
        std::vector<ReportRecordV3> records;ReportRecordV3 record{};
        while(DequeueReport(ring,&record)==ReportReadResult::Record) records.push_back(record);
        return records;
    }
    RecoveryStatusSnapshot Scalar() {
        RecoveryStatusSnapshot scalar{};
        const RecoveryReadOps reader{&recoveryStatus,[](void* context,std::size_t offset,void* output,std::size_t bytes) noexcept {
            if(offset>sizeof(RecoveryStatusWireV1) || bytes>sizeof(RecoveryStatusWireV1)-offset) return false;
            std::memcpy(output,static_cast<const unsigned char*>(context)+offset,bytes);return true;
        }};
        RS2_CHECK(ReadRecoveryStatusSnapshot(reader,status.header,&scalar)==RecoverySnapshotResult::Coherent);
        return scalar;
    }
    void Reserve() { RS2_CHECK(ReserveCapture(runtime,runtime.recoveryQuota,9)); }
    bool Service(std::uint64_t qpc) {
        return ServiceLeechRecovery(runtime,CallerClass::NormalPump,3,false,static_cast<std::int64_t>(qpc));
    }
};
// Console fixture calls ONLY these DLL-owned stubs. Byte/profile reads are
// synthetic data; the EXE's constructor, allocator and reply leaf never run.
struct ConsoleFixture : Fixture {
    leech_fixture::NativeFixture native{true};
    static ConsoleFixture* active;
    unsigned constructors{},replies{},pins{};
    bool failPin{},badPost{},throwConstruct{},throwReply{},reenter{};
    std::wstring lastReply;
    struct Exception {};
    ConsoleFixture() {
        ResetLeechConsoleForTest();active=this;native.LoadConsoleProfile();
        auto& r=*recovery;r.native=native.Context();r.startup=native.host;
        runtime.config.hostBase=native.base;runtime.config.hostSize=native.host.imageSize;
        runtime.config.memory=native.Memory();runtime.config.mode=Mode::Observe;
        r.control.enabled=true;r.control.started=1;r.control.consoleRequested=true;
        r.control.scope={2,L"E:\\servertwo"};
        PrepareLeechConsole(r.console,r,reinterpret_cast<HMODULE>(1));
        r.console.calls={Construct,Reply,Pin};
        native.Put(kLeechConsoleRegistryRva,native.heapBase+0x180000);
        native.Put<std::int32_t>(kLeechConsoleRegistryRva+8,2);
        native.Put<std::int32_t>(kLeechConsoleRegistryRva+12,8);
        native.HeapPut(0x180000,native.heapBase+0x180100);
        native.HeapPut(0x180008,native.heapBase+0x180108);
        Output();
    }
    ~ConsoleFixture() {ResetLeechConsoleForTest();active=nullptr;}
    void Output() {
        std::memset(native.heap.data()+0x101000,0,0x24);
        native.HeapPut(0x101000,native.base+kLeechConsoleReplyVtableRva);
        native.HeapPut<std::int32_t>(0x101008,1);native.HeapPut<std::int32_t>(0x101010,1);
    }
    void* OutputAddress() {return reinterpret_cast<void*>(native.heapBase+0x101000);}
    static bool Pin(HMODULE module) noexcept {++active->pins;return module==reinterpret_cast<HMODULE>(1) && !active->failPin;}
    static void* Construct(void* object) {
        auto& f=*active;++f.constructors;
        RS2_CHECK(recovery::ReadConsoleRegistration(f.recovery->control)==recovery::ConsoleRegistration::NotRegistered);
        if(f.throwConstruct) throw Exception{};
        static_cast<LeechConsoleObject*>(object)->vtable=reinterpret_cast<const std::uintptr_t*>(f.native.base+0xEA40A8);
        f.native.HeapPut(0x180010,reinterpret_cast<std::uintptr_t>(object));
        f.native.Put<std::int32_t>(kLeechConsoleRegistryRva+8,3);
        if(f.badPost) f.native.HeapPut(0x180000,f.native.heapBase+0x180118);
        return object;
    }
    static void Reply(void* output,const wchar_t* text,std::uint32_t category) {
        auto& f=*active;++f.replies;
        RS2_CHECK(output==f.OutputAddress() && category==0x2F8 && std::wcslen(text)<=kLeechConsoleReplyCharacters);
        if(f.throwReply) throw Exception{};
        f.lastReply=text;SetLastError(0x9876);
        if(f.reenter) {f.reenter=false;RS2_CHECK(f.Command(L"rs2leech status")==1);}
    }
    void Register() {RegisterLeechConsole(runtime,CallerClass::NormalPump,3,false);}
    std::int32_t Command(const wchar_t* text,std::uintptr_t returnRva=kLeechConsoleReturnRva) {
        const auto bytes=(std::wcslen(text)+1)*sizeof(wchar_t);RS2_CHECK(bytes<=512);
        std::memcpy(native.heap.data()+0x100000,text,bytes);
        return ExecuteLeechConsoleForTest(recovery->console,&recovery->console.object,native.base+returnRva,
            reinterpret_cast<const wchar_t*>(native.heapBase+0x100000),OutputAddress());
    }
};
ConsoleFixture* ConsoleFixture::active{};
void ConsoleRegistrationAndCommands() {
    using Registration=recovery::ConsoleRegistration;
#if defined(RS2_RECOVERY_GUARD_PROBE)
    auto owner=std::make_unique<ConsoleFixture>();auto& f=*owner;
    RS2_CHECK(!LeechConsoleRegistrationDue(f.runtime));f.Register();
    RS2_CHECK(!f.constructors && !f.replies && !f.pins &&
        recovery::ReadConsoleRegistration(f.recovery->control)==Registration::NotRegistered);
#else
    for(unsigned scenario=0;scenario<8;++scenario) {
        auto owner=std::make_unique<ConsoleFixture>();auto& f=*owner;auto& a=f.recovery->console;
        if(scenario==1) f.failPin=true;
        if(scenario==2) f.badPost=true;
        if(scenario==3) f.native.Put<std::int32_t>(kLeechConsoleRegistryRva+12,2); // No growth branch.
        if(scenario==4) f.native.image[0x4B710]^=1;
        if(scenario==5) f.native.Put<std::uintptr_t>(f.native.layout.gmalloc,0);
        if(scenario==6) f.throwConstruct=true;
        if(scenario==7) f.recovery->control.consoleRequested=false;
        SetLastError(0x1234);bool caught{};
        try {f.Register();}catch(const ConsoleFixture::Exception&) {caught=true;}
        RS2_CHECK(caught==(scenario==6) && GetLastError()==0x1234);
        const auto state=recovery::ReadConsoleRegistration(f.recovery->control);
        RS2_CHECK(state==(scenario==0 ? Registration::Available : scenario==7 ? Registration::NotRegistered : Registration::Unavailable));
        const auto calls=f.constructors;f.Register();RS2_CHECK(f.constructors==calls);
        RS2_CHECK(f.recovery->control.latched==0 && f.recovery->control.result==static_cast<LONG>(recovery::ControlResult::Ready));
        if(scenario!=0) continue;
        f.runtime.pumpDepth=0;f.runtime.timingDepth=0;
        RS2_CHECK(f.Command(L"unrelated command")==0 && f.replies==0);
        RS2_CHECK(f.Command(L"rs2leech status",kLeechConsoleReturnRva+1)==0 && f.replies==0);
        RS2_CHECK(f.Command(L"rs2leech status")==1 && f.replies==1 && GetLastError()==0x1234);
        RS2_CHECK(f.lastReply.find(L"phase=armed")!=std::wstring::npos && f.lastReply.find(L"confirm=0100000000000000")!=std::wstring::npos);
        RS2_CHECK(f.Command(L"rs2leech recover 0000000000000000")==1 && !f.recovery->control.latched);
        RS2_CHECK(f.Command(L"rs2leech recover")==1 && !f.recovery->control.latched);
        const auto previous=f.replies;f.reenter=true;
        RS2_CHECK(f.Command(L"rs2leech status")==1 && f.replies==previous+1);
        f.native.HeapPut(0x101000,f.native.base+0xF04478); // In-game reply class: do not claim.
        RS2_CHECK(f.Command(L"rs2leech recover 0100000000000000")==1 && !f.recovery->control.latched);
        f.Output();f.runtime.pumpDepth=1;
        RS2_CHECK(f.Command(L"rs2leech recover 0100000000000000")==1 && !f.recovery->control.latched);
        f.runtime.pumpDepth=0;
        RS2_CHECK(f.Command(L"rs2leech recover 0100000000000000")==1 && f.recovery->control.latched==2);
    RS2_CHECK(!f.recovery->requested && !f.recovery->cancelEntered && f.lastReply.find(L"request queued")!=std::wstring::npos);
        RS2_CHECK(f.Command(L"rs2leech recover 0100000000000000")==1 && f.lastReply.find(L"not queued")!=std::wstring::npos);
        const auto replies=f.replies;
        std::thread other([&] {RS2_CHECK(f.Command(L"rs2leech status")==0);});other.join();
        RS2_CHECK(f.replies==replies && a.foreignObserved==1);
        f.throwReply=true;caught=false;
        try{f.Command(L"rs2leech status");}catch(const ConsoleFixture::Exception&){caught=true;}
        RS2_CHECK(caught && recovery::ReadConsoleRegistration(f.recovery->control)==Registration::Unavailable && !a.replying);
    }
#endif
}
void ConsoleReadSelectors() {
    auto fixture=std::make_unique<ConsoleFixture>();auto& f=*fixture;DWORD error{};
#if !defined(RS2_RECOVERY_GUARD_PROBE)
    RS2_CHECK(LeechConsoleRegistrationDue(f.runtime));
    f.runtime.sourceReady=false;RS2_CHECK(!LeechConsoleRegistrationDue(f.runtime));f.runtime.sourceReady=true;
    f.runtime.sdkReady=false;RS2_CHECK(!LeechConsoleRegistrationDue(f.runtime));f.runtime.sdkReady=true;
    f.recovery->requested=true;RS2_CHECK(!LeechConsoleRegistrationDue(f.runtime));f.recovery->requested=false;
#endif
    RS2_CHECK(ValidateNativeLeechConsoleProfile(f.native.base,f.native.host,f.native.Memory(),f.native.imports,&error)==ProfileResult::Ready);
    const auto& profile=leech_fixture::kConsoleProduction;
    for(std::size_t i=0;i<profile.body.spanCount;++i) {
        const auto at=profile.body.spans[i].span.rva;f.native.image[at]^=1;
        RS2_CHECK(ValidateNativeLeechConsoleProfile(f.native.base,f.native.host,f.native.Memory(),f.native.imports,&error)==ProfileResult::BytesMismatch);
        f.native.image[at]^=1;
    }
    LeechConsoleRegistry registry{};
    RS2_CHECK(ReadLeechConsoleRegistry(f.native.Context(),&registry) && registry.count==2 && registry.capacity==8);
    f.native.Put<std::int32_t>(kLeechConsoleRegistryRva+8,-1);
    RS2_CHECK(!ReadLeechConsoleRegistry(f.native.Context(),&registry) && !registry.data);
    f.native.Put<std::int32_t>(kLeechConsoleRegistryRva+8,2);
    f.native.Put<std::int32_t>(kLeechConsoleRegistryRva+12,1025);
    RS2_CHECK(!ReadLeechConsoleRegistry(f.native.Context(),&registry));
    f.native.Put<std::int32_t>(kLeechConsoleRegistryRva+12,8);
    const auto output=reinterpret_cast<std::uintptr_t>(f.OutputAddress());
    RS2_CHECK(ReadLeechConsoleOutput(f.native.Context(),output));
    f.native.HeapPut<std::int32_t>(0x101020,8); // Positive capacity, null Data, Num0 is unsafe.
    RS2_CHECK(!ReadLeechConsoleOutput(f.native.Context(),output));
    f.native.HeapPut(0x101014,f.native.heapBase+0x101100);
    RS2_CHECK(ReadLeechConsoleOutput(f.native.Context(),output));
    f.native.HeapPut<std::int32_t>(0x10101C,2);f.native.HeapPut<std::uint16_t>(0x101102,1);
    RS2_CHECK(!ReadLeechConsoleOutput(f.native.Context(),output));
    f.native.HeapPut<std::uint16_t>(0x101102,0);RS2_CHECK(ReadLeechConsoleOutput(f.native.Context(),output));
    f.native.HeapPut<std::int32_t>(0x10101C,9);RS2_CHECK(!ReadLeechConsoleOutput(f.native.Context(),output));
    f.Output();f.native.HeapPut<std::int32_t>(0x101008,0);RS2_CHECK(!ReadLeechConsoleOutput(f.native.Context(),output));
}
// Reuse the qualified native byte/descriptor fixture with owned addresses.
// Only our counting stubs are executed. The PE bytes are never executable;
// source/log objects are bounded inert metadata read by the production gates.
struct SequenceFixture : Fixture {
    leech_fixture::NativeFixture native{true};
    std::vector<const char*> order;
    unsigned holderReleases{},slotReleases{},forwardCalls{},finishDrains{};
    unsigned metadataHeads{},metadataFills{},metadataUpdates{},metadataDestroys{},metadataRandomCalls{};
    bool throwMetadataHead{},throwMetadataFill{},throwMetadataUpdate{},throwMetadataDestroy{};
    bool metadataRandomFails{},metadataChangesCounts{},metadataLeavesMismatch{};
    bool throwCopy{},throwEnqueue{},throwForward{},changeOther{},twoCreates{},raceCas{},casRaced{},synchronousFinishError{};
    const bool* borrowedFinish{};
    RecoveryFinishSuccessFn finishSuccess{};
    RecoveryFinishErrorFn finishError{};
    std::uint16_t allocatedFinishSlot{0xffff};
    static SequenceFixture* active;
    struct Exception {};
    static constexpr std::uint32_t kBuilder=0xBF7430,kResult=0x14D8000;
    NativeLogLayout logLayout{0x1500100,0x1501000,0x149F020,0x149F030,0x149F040,0x149F050,0x149F060,0x149F070,
        0x149F080,0x1500108,0x149F090,0x1500110,0x1500114,0x1500118,0x150011C,0x1500120,0x1500128,
        0x1500130,0x1500134,0x1500138,0x150013C};
    static bool QueryOwned(void* context,std::uintptr_t address,MemoryRegion* output,DWORD* error) noexcept {
        auto& f=*static_cast<SequenceFixture*>(context);
        if(f.raceCas && !f.casRaced && address==f.native.base+f.native.layout.genericPool+0x48) {
            f.casRaced=true;f.native.Put(f.native.layout.genericPool+0x48,reinterpret_cast<std::uintptr_t>(&OtherSuccess));
        }
        return leech_fixture::NativeFixture::Query(&f.native,address,output,error);
    }
    static bool ReadOwned(void* context,std::uintptr_t address,void* output,std::size_t bytes,DWORD* error) noexcept {
        auto& f=*static_cast<SequenceFixture*>(context);
        if(f.borrowedFinish && address==reinterpret_cast<std::uintptr_t>(f.borrowedFinish) && bytes==1) {
            std::memcpy(output,f.borrowedFinish,1);return true;
        }
        return leech_fixture::NativeFixture::Read(&f.native,address,output,bytes,error);
    }
    static bool Owner(void* context) noexcept {return RuntimeOwner(static_cast<SequenceFixture*>(context)->runtime);}
    static bool Safe(void* context) noexcept {return RecoveryRuntimeSafeOwner(static_cast<SequenceFixture*>(context)->runtime);}
    static bool Admit(void* context) noexcept {
        auto& f=*static_cast<SequenceFixture*>(context);return f.runtime.sourceReady && RuntimeCaptureAdmission(f.runtime);
    }
    static bool Exchange(void* context,std::uintptr_t address,std::uintptr_t expected,std::uintptr_t desired,
        std::uintptr_t* observed,DWORD* error) noexcept {
        if(!Safe(context)) return false;
        *observed=reinterpret_cast<std::uintptr_t>(InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(address),reinterpret_cast<PVOID>(desired),reinterpret_cast<PVOID>(expected)));
        *error=ERROR_SUCCESS;return true;
    }
    TaskAccess Access() {return {runtime.config.memory,native.base,native.host.imageSize,this,Exchange,Admit,Safe,Owner};}
    static std::uint64_t Qualified(void*) noexcept {return 1;}
    static bool Builder(void*) {return true;}
    SequenceFixture() {
        active=this;auto& r=*recovery;
        native.LoadMetadataProfile();
        runtime.config.hostBase=native.base;runtime.config.hostSize=native.host.imageSize;
        runtime.config.memory={this,QueryOwned,ReadOwned};r.startup=native.host;
        r.native={native.base,native.host.imageSize,runtime.config.memory,&native.imports,&native.layout};
        // The ordinary task reader's admitted heartbeat metadata type is43.
        native.Put<std::uintptr_t>(native.layout.registry+42*8,0);
        native.Put(native.layout.registry+43*8,native.base+native.hbObject);
        native.Put<std::uint16_t>(native.hbObject+8,43);native.Put<std::uint16_t>(native.hbObject+10,3);
        native.Put(native.layout.genericPool+0x38,(43u<<16)|2u);
        native.Put(native.layout.genericPool+0x40,native.base+kBuilder);
        runtime.config.source={0x14F0000,0x14F0008,0x14F0010,0x14F0018};
        for(const auto offset : {0x100000u,0x101000u,0x103000u,0x104000u,0x105000u})
            native.HeapPut(offset,native.base+0x149F000);
        native.Put(0x149F000,native.base+0x1000);
        native.Put(runtime.config.source.world,native.heapBase+0x100000);
        native.Put(runtime.config.source.worldInfoClass,native.heapBase+0x105000);
        native.HeapPut(0x100080,native.heapBase+0x101000);
        native.HeapPut(0x101060,native.heapBase+0x102000);native.HeapPut<std::int32_t>(0x101068,1);native.HeapPut<std::int32_t>(0x10106C,1);
        native.HeapPut(0x102000,native.heapBase+0x103000);native.HeapPut(0x103050,native.heapBase+0x105000);
        native.HeapPut(0x1035CC,native.heapBase+0x104000);native.HeapPut<std::uint32_t>(0x103398,0x100);
        native.HeapPut<std::uint8_t>(0x103598,1);native.HeapPut(0x1034FC,1000.0F);
        native.HeapPut<std::int32_t>(0x1042E4,64);native.HeapPut<std::int32_t>(0x1042EC,2);
        native.Put(runtime.config.source.publicWrapper,native.heapBase+0x106000);
        native.Put(runtime.config.source.privateWrapper,native.heapBase+0x106000);
        native.HeapPut(0x106000,native.heapBase+0x107000);native.HeapPut<std::int32_t>(0x106098,2);
        native.HeapPut<std::int32_t>(0x10609C,64);native.HeapPut(0x1060A4,12.0F);
        dispatch.bindingCount=1;dispatch.bindings[0].accepted=true;
        dispatch.bindings[0].proxy.real=reinterpret_cast<void*>(native.heapBase+0x107000);
        dispatch.bindings[0].proxy.owner=&dispatch;dispatch.bindings[0].proxy.bindingId=1;dispatch.bindings[0].proxy.bindingSequence=1;
        runtime.config.task={native.layout.genericPool,native.layout.heartbeatId,native.layout.invalidId,native.layout.issuedId,
            native.layout.registry+43*8,native.layout.heartbeatVtable,kBuilder,native.layout.standalone};
        runtime.config.builderOriginal=reinterpret_cast<BuilderFn>(native.base+kBuilder);
        runtime.config.builderWrapper=reinterpret_cast<std::uintptr_t>(&Builder);
        RS2_CHECK(InitializeTaskBinding(runtime.task,native.base+kBuilder,reinterpret_cast<std::uintptr_t>(&Builder))==Reason::None);
        RS2_CHECK(RecoveryRuntimeSource(runtime,&r.source)==Reason::None);runtime.source=r.source;
        TaskSnapshot installed{};
        RS2_CHECK(InstallTaskBinding(runtime.task,Access(),runtime.config.task,{1,1},&installed)==Reason::None);
        RS2_CHECK(RecoveryRuntimeTask(runtime,&r.oldHeartbeat)==Reason::None);
        RS2_CHECK(native.Snapshot(r.before)==RecoveryNativeResult::Ready);r.current=r.before;
        const auto base=native.base;
        native.Put(logLayout.logSlot,base+logLayout.redirectorObject);native.Put(logLayout.redirectorObject,base+logLayout.redirectorVtable);
        native.Put<std::uint32_t>(0x1501044,GetCurrentThreadId());native.Put(0x1501034,base+0x1502000);
        native.Put<std::int32_t>(0x150103C,3);native.Put<std::int32_t>(0x1501040,3);
        native.Put(0x1502000,base+0x1503000);native.Put(0x1502008,base+0x1504000);native.Put(0x1502010,base+0x1506000);
        native.Put(0x1503000,base+logLayout.fileVtable);native.Put(0x1503014,base+0x1507000);
        native.Put<std::uint32_t>(0x1503010,1);native.Put<std::uint32_t>(0x150381C,1);
        constexpr char16_t logPath[]=u"E:\\logs\\Launch.log";std::memcpy(native.image.data()+0x150301C,logPath,sizeof(logPath));
        native.Put(0x1504000,base+logLayout.inheritedVtable);native.Put<std::uintptr_t>(0x1504014,UINTPTR_MAX);native.Put(0x1504020,base+0x1505000);
        native.Put(0x1505000,base+logLayout.consoleVtable);native.Put(0x1506000,base+logLayout.eventVtable);
        native.Put(0x1507000,base+logLayout.archiveVtable);native.Put<std::uintptr_t>(0x1507084,0x980);
        native.Put(logLayout.managerSlot,base+0x1509000);native.Put(0x1509000,base+logLayout.managerVtable);
        native.Put<std::uint32_t>(logLayout.forceFlush,1);native.Put<std::uint32_t>(logLayout.logTimes,1);
        native.Put<std::uint32_t>(logLayout.suppressionInitialized,1);native.Put(logLayout.nameTable,base+0x150B000);
        native.Put(0x150C7C0,base+0x150D000);
        runtime.nativeLog.read={runtime.config.memory,base,native.host.imageSize,GetCurrentThreadId(),&logLayout};
        RS2_CHECK(ReadNativeLogSnapshot(runtime.nativeLog.read,&runtime.nativeLog.snapshot)==TransportReason::None);
        runtime.nativeLog.haveSnapshot=true;runtime.nativeLog.epoch=1;runtime.nativeLog.ops={};
        runtime.nativeLog.ops.context=this;runtime.nativeLog.ops.qualified=Qualified;
        r.requested=true;r.value.operationSequence=1;r.value.phase=static_cast<std::uint64_t>(RecoveryPhase::Qualifying);
        r.value.transitionSequence=3;r.value.qpc=Now();r.value.finishDeadlineQpc=r.value.qpc+frequency*60;r.value.overallDeadlineQpc=r.value.qpc+frequency*120;
        r.calls.initHolder=Init;r.calls.finishType=Type;r.calls.finishAllocate=Allocate;r.calls.bindHolder=Bind;
        r.calls.resolveHolder=Resolve;r.calls.copyString=Copy;r.calls.cancel=Cancel;r.calls.enqueueFinish=Enqueue;
        r.calls.releaseHolder=Release;r.calls.finishRelease=ReleaseSlot;r.calls.cleanup=Cleanup;r.calls.start=Start;r.calls.create=Create;r.calls.createSuccess=Forward;
        runtime.config.prepared=ProductionPreparedLayout();
        native.Put<std::uint32_t>(0x1798A00,2);native.Put<std::uint32_t>(0x17989F8,0);native.Put<std::uint32_t>(0x17989FC,64);
        native.Put<std::uint32_t>(0x14AAD68,64);
        MetadataJson(2);
        r.metadataCalls={MetadataHead,MetadataFill,MetadataDestroy,MetadataUpdate};
        r.metadataRandom={this,MetadataRandom};
        SetLeechRecoveryCurrentForTest(&r);Reserve();
    }
    void MetadataJson(unsigned count) {
        const auto json=std::string("{\"ip\":\"192.0.2.123\",\"op\":[{\"k\":\"PI_COUNT\",\"v\":\"")+std::to_string(count)+
            "\"},{\"k\":\"BotPlayerCount\",\"v\":\""+std::to_string(Get<std::uint32_t>(0x17989F8))+"\"},{\"k\":\"MaxPlayerCount\",\"v\":\"64\"}]}";
        native.HeapString(0x14AAD48,0x1C0000,json.c_str(),4096);
    }
    void PilotScope() {
        recovery->control.scope={2,L"E:\\servertwo"};
        runtime.config.mode=Mode::Observe;status.header.configuredMode=static_cast<std::uint32_t>(Mode::Observe);
    }
    void Population(unsigned pi,unsigned humans=64) {
        native.HeapPut<std::int32_t>(0x1042EC,static_cast<std::int32_t>(humans));
        native.HeapPut<std::int32_t>(0x106098,static_cast<std::int32_t>(pi));
        native.Put<std::uint32_t>(0x1798A00,pi);MetadataJson(pi);
    }
    static bool MetadataRandom(void* context,std::uint8_t* bytes,std::size_t count) noexcept {
        auto& f=*static_cast<SequenceFixture*>(context);++f.metadataRandomCalls;
        if(f.metadataRandomFails) return false;
        for(std::size_t i=0;i<count;++i) bytes[i]=static_cast<std::uint8_t>(i);
        return true;
    }
    static void* MetadataHead() {
        auto& f=*active;++f.metadataHeads;
        if(f.throwMetadataHead) throw Exception{};
        return f.native.heap.data()+0x1D8000;
    }
    static void MetadataFill(void* properties) {
        auto& f=*active;++f.metadataFills;
        RS2_CHECK((reinterpret_cast<std::uintptr_t>(properties)&15)==0);
        const auto* bytes=static_cast<const std::uint8_t*>(properties);
        for(const auto offset:{0x18,0x58,0x78}) {std::uint64_t capacity{};std::memcpy(&capacity,bytes+offset,8);RS2_CHECK(capacity==15);}
        void* head{};std::memcpy(&head,bytes+0xA8,8);RS2_CHECK(head==f.native.heap.data()+0x1D8000);
        if(f.throwMetadataFill) throw Exception{};
        // Native fill reads cached PP into properties; it does not write that
        // global or the separate registration-changed byte at F0.
        if(f.metadataChangesCounts) f.native.Put<std::uint32_t>(0x1798A00,3);
    }
    static void MetadataUpdate(const void* properties,const RecoveryBorrowedVector* members) {
        auto& f=*active;++f.metadataUpdates;RS2_CHECK(properties && members);
        const auto count=static_cast<std::uint32_t>((members->end-members->begin)/sizeof(RecoveryBorrowedString));
        RS2_CHECK(count==f.recovery->metadataMembers.count && count==f.Get<std::uint32_t>(0x1798A00));
        if(f.throwMetadataUpdate) throw Exception{};
        if(f.metadataLeavesMismatch) return;
        // Test-owned deep copy: borrowed buffers remain live/unchanged and are
        // never freed. Production's BA9490 performs the qualified native copy.
        const auto* strings=reinterpret_cast<const RecoveryBorrowedString*>(members->begin);
        for(std::uint32_t i=0;i<count;++i) {
            const auto text=reinterpret_cast<const char*>(strings[i].data);
            RS2_CHECK(strings[i].size==36 && strings[i].capacity==36 && text[36]==0);
            f.native.HeapPut(0x60000+i*32,f.native.heapBase+0x80000+i*128);
            f.native.HeapPut<std::uint64_t>(0x60000+i*32+0x10,36);
            f.native.HeapPut<std::uint64_t>(0x60000+i*32+0x18,47);
            std::memcpy(f.native.heap.data()+0x80000+i*128,text,37);
        }
        f.native.Put(f.native.layout.kernelVector+8,f.native.heapBase+0x60000+count*32);
        const auto capacity=f.Get<std::uintptr_t>(f.native.layout.kernelVector+16);
        const auto end=f.native.heapBase+0x60000+count*32;
        if(capacity<end) f.native.Put(f.native.layout.kernelVector+16,end); // Fake native vector growth.
        f.native.Put<std::uint8_t>(0x14AAD88,1);f.MetadataJson(count);
    }
    static void MetadataDestroy(void* properties) {
        auto& f=*active;++f.metadataDestroys;RS2_CHECK(properties!=nullptr);
        if(f.throwMetadataDestroy) throw Exception{};
    }
    ~SequenceFixture() {SetLeechCreateCaptureForTest(nullptr,0,false,false);active=nullptr;}
    template<class T> T Get(std::uint32_t rva) {T value{};std::memcpy(&value,native.image.data()+rva,sizeof(value));return value;}
    char* StringData(std::uint32_t object) {
        return Get<std::uint64_t>(object+0x18)<16 ? reinterpret_cast<char*>(native.image.data()+object) :
            reinterpret_cast<char*>(Get<std::uintptr_t>(object));
    }
    std::string StringValue(std::uint32_t object) {
        const auto size=Get<std::uint64_t>(object+0x10);
        RS2_CHECK(size<kRecoverySessionBytes && size<=Get<std::uint64_t>(object+0x18));
        if(size>=kRecoverySessionBytes) return {};
        return {StringData(object),static_cast<std::size_t>(size)};
    }
    void AssignRetained(std::uint32_t object,const std::string& value) {
        RS2_CHECK(value.size()<=Get<std::uint64_t>(object+0x18));
        if(value.size()>Get<std::uint64_t>(object+0x18)) return;
        std::memcpy(StringData(object),value.c_str(),value.size()+1);
        native.Put<std::uint64_t>(object+0x10,value.size());
    }
    static std::uint16_t Type(void* descriptor) {
        auto& f=*active;f.order.push_back("type");
        RS2_CHECK(reinterpret_cast<std::uintptr_t>(descriptor)==f.native.base+f.native.finishObject);return 40;
    }
    static void* Init(std::uint32_t* holder) {
        active->order.push_back("init");RS2_CHECK(holder==&active->recovery->holder);*holder=0;return holder;
    }
    static std::uint16_t Allocate(void* descriptor) {
        auto& f=*active;f.order.push_back("allocate");
        RS2_CHECK(reinterpret_cast<std::uintptr_t>(descriptor)==f.native.base+f.native.finishObject);
        for(std::uint16_t slot=0;slot<16;++slot) {
            const auto reference=f.native.finishObject+0x20+slot*0x30;
            if(f.Get<std::int32_t>(reference)!=-1) continue;
            f.allocatedFinishSlot=slot;f.native.Put<std::int32_t>(reference,0);
            // Native BF0DB0 frees/reconstructs retained string storage. This
            // fixture owns its byte arrays, so reconstruction needs no host free.
            f.native.Inline(reference+8);return slot;
        }
        return 0xffff;
    }
    static void Bind(std::uint32_t* holder,std::uint16_t type,std::uint16_t slot) {
        auto& f=*active;f.order.push_back("bind");
        RS2_CHECK(holder==&f.recovery->holder && type==40 && slot==f.allocatedFinishSlot);
        *holder=(static_cast<std::uint32_t>(type)<<16)|slot;
        f.native.Put<std::int32_t>(f.native.finishObject+0x20+slot*0x30,1);
    }
    static void* Resolve(const std::uint32_t* holder) {
        auto& f=*active;f.order.push_back("resolve");
        RS2_CHECK(holder==&f.recovery->holder && (*holder>>16)==40 && (*holder&0xffff)==f.allocatedFinishSlot);
        return reinterpret_cast<void*>(f.native.base+f.native.finishObject+0x28+(*holder&0xffff)*0x30);
    }
    static void* Copy(void* destination,const void* source,std::size_t offset,std::size_t count) {
        auto& f=*active;f.order.push_back("copy");
        const auto payload=f.native.finishObject+0x28+f.allocatedFinishSlot*0x30;
        RS2_CHECK(reinterpret_cast<std::uintptr_t>(destination)==f.native.base+payload);
        RS2_CHECK(reinterpret_cast<std::uintptr_t>(source)==f.native.base+f.native.layout.sdkSession && !offset && count==SIZE_MAX);
        RS2_CHECK(f.Get<std::uint64_t>(payload+0x10)==0 && f.Get<std::uint64_t>(payload+0x18)==15);
        if(f.throwCopy) throw Exception{};
        const auto value=f.StringValue(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(source)-f.native.base));
        f.native.HeapString(payload,0x1B0000,value.c_str());return destination;
    }
    static void Cancel(std::uint32_t* id) {
        auto& f=*active;f.order.push_back("cancel");
        RS2_CHECK(ReadTaskPhase(f.runtime.task)==TaskPhase::Retired && f.runtime.bindingSuspended);
        RS2_CHECK(f.Get<std::uintptr_t>(f.native.layout.genericPool+0x40)==f.runtime.task.original);
        RS2_CHECK(reinterpret_cast<std::uintptr_t>(id)==f.native.base+f.native.layout.heartbeatId && *id==77);
        *id=0;std::memset(f.native.image.data()+f.native.layout.genericPool,0,0x78);
        f.native.Put<std::int32_t>(f.native.hbObject+0x20+2*0x78,-1);
    }
    static std::uint32_t Enqueue(const char* component,const std::uint32_t* holder,RecoveryFinishSuccessFn success,RecoveryFinishErrorFn error) {
        auto& f=*active;f.order.push_back("enqueue");f.native.Put(f.native.layout.issuedId,78u);
        RS2_CHECK(reinterpret_cast<std::uintptr_t>(component)==f.Get<std::uintptr_t>(f.native.layout.componentName));
        RS2_CHECK(holder==&f.recovery->holder && (*holder>>16)==40 && (*holder&0xffff)==f.allocatedFinishSlot && success && error);
        const auto reference=f.native.finishObject+0x20+(*holder&0xffff)*0x30;
        RS2_CHECK(f.Get<std::int32_t>(reference)==1);
        f.native.Put<std::int32_t>(reference,2); // Local holder plus native task.
        if(f.throwEnqueue) {
            f.native.Put(f.native.layout.genericPool,1u);
            throw Exception{};
        }
        f.finishSuccess=success;f.finishError=error;
        f.Task(0,78,*holder,reinterpret_cast<std::uintptr_t>(success));
        f.native.Put(f.native.layout.genericPool,4u); // Immediate dispatch, pending later completion.
        f.native.Put(f.native.layout.genericPool+0x50,reinterpret_cast<std::uintptr_t>(error));
        RS2_CHECK(!f.recovery->createInstalled && f.recovery->value.nativeStage==static_cast<std::uint64_t>(NativeStage::Enqueue));
        if(f.synchronousFinishError) {
            RS2_CHECK(error(-7,78));
            f.native.Put<std::int32_t>(reference,1);
            std::memset(f.native.image.data()+f.native.layout.genericPool,0,0x78);
            return 0; // Only the admitted error path completes during enqueue.
        }
        return 78;
    }
    static void Release(std::uint32_t* holder) {
        auto& f=*active;f.order.push_back("release");++f.holderReleases;
        RS2_CHECK(holder==&f.recovery->holder && (*holder>>16)==40 && (*holder&0xffff)==f.allocatedFinishSlot);
        const auto reference=f.native.finishObject+0x20+(*holder&0xffff)*0x30;
        const auto refs=f.Get<std::int32_t>(reference);RS2_CHECK(refs>=1);*holder=0;
        f.native.Put<std::int32_t>(reference,refs==1 ? -1 : refs-1);
    }
    static void ReleaseSlot(void* descriptor,std::uint16_t slot) {
        auto& f=*active;f.order.push_back("release-slot");++f.slotReleases;
        RS2_CHECK(reinterpret_cast<std::uintptr_t>(descriptor)==f.native.base+f.native.finishObject && slot==f.allocatedFinishSlot);
        const auto reference=f.native.finishObject+0x20+slot*0x30;
        RS2_CHECK(f.Get<std::int32_t>(reference)==0);f.native.Put<std::int32_t>(reference,-1);
    }
    void CompleteFinish() {
        RS2_CHECK(finishSuccess && finishError && !finishDrains);
        RS2_CHECK(Get<std::uint32_t>(native.layout.genericPool)==4 && Get<std::uint32_t>(native.layout.genericPool+4)==78);
        const auto reference=native.finishObject+0x20+allocatedFinishSlot*0x30;
        RS2_CHECK(Get<std::int32_t>(reference)==1);
        const auto phase=recovery->value.phase,callCount=order.size();
        const bool result=true;borrowedFinish=&result;finishSuccess(&result,78);borrowedFinish=nullptr;
        RS2_CHECK(recovery->value.phase==phase && order.size()==callCount && !recovery->createInstalled);
        // BF7400 callback and disposal are one native owner drain. There is no
        // artificial owner-service visit between these two operations.
        native.Put<std::int32_t>(reference,-1);
        std::memset(native.image.data()+native.layout.genericPool,0,0x78);++finishDrains;
    }
    static void Cleanup() {
        auto& f=*active;f.order.push_back("cleanup");f.native.Put(f.native.layout.standalone,0u);
        f.native.ClearString(f.native.layout.sdkSession);
        std::memset(f.native.heap.data()+0x60000,0,64*32);
        for(unsigned i=0;i<64;++i) f.native.HeapPut<std::uint64_t>(0x60000+i*32+0x18,15);
        f.native.Put(f.native.layout.kernelVector+8,f.native.heapBase+0x60000);
    }
    static void Start() {active->order.push_back("start");active->native.Put(active->native.layout.standalone,1u);}
    void Task(unsigned slot,std::uint32_t id,std::uint32_t holder,std::uintptr_t success,std::uintptr_t builder=0) {
        const auto rva=native.layout.genericPool+slot*0x78;std::memset(native.image.data()+rva,0,0x78);
        native.Put(rva,2u);native.Put(rva+4,id);native.Put(rva+8,native.base+0x1490000);native.Put(rva+0x38,holder);
        native.Put(rva+0x40,builder);native.Put(rva+0x48,success);
    }
    static void Create() {
        auto& f=*active;f.order.push_back("create");f.native.Put(f.native.layout.standalone,2u);f.native.Put(f.native.layout.issuedId,79u);
        f.native.ClearString(f.native.layout.cacheSession); // A53560 retains the allocation.
        f.native.Put<std::int32_t>(f.native.createObject+0x20,1);f.Task(0,79,41u<<16,reinterpret_cast<std::uintptr_t>(&Forward));
        if(f.changeOther) f.native.image[f.native.layout.genericPool+3*0x78+0x71]=1;
        if(f.twoCreates) {f.native.Put(f.native.layout.issuedId,80u);f.native.Put<std::int32_t>(f.native.createObject+0x20+0x90,1);f.Task(1,80,(41u<<16)|1,reinterpret_cast<std::uintptr_t>(&Forward));}
        f.native.HeapString(kResult,0x180000,"66666666-7777-8888-9999-aaaaaaaaaaaa",47);
    }
    static void OtherSuccess(const void*,std::uint32_t) {}
    static void Forward(const void* result,std::uint32_t id) {
        auto& f=*active;f.order.push_back("forward");++f.forwardCalls;
        RS2_CHECK(reinterpret_cast<std::uintptr_t>(result)==f.native.base+kResult && id==79);
        RS2_CHECK(f.Get<std::uint64_t>(f.native.layout.cacheSession+0x10)==0);
        if(f.throwForward) throw Exception{};
        const auto value=f.StringValue(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(result)-f.native.base));
        f.AssignRetained(f.native.layout.sdkSession,value);f.native.Put(f.native.layout.standalone,3u);
        f.native.Put(f.native.layout.issuedId,80u);f.native.Put(f.native.layout.heartbeatId,80u);f.native.Put<std::int32_t>(f.native.hbObject+0x20,1);
        f.Task(1,80,43u<<16,0,f.native.base+kBuilder);f.native.Put<std::uint64_t>(f.native.layout.genericPool+0x78+0x60,30000);
        // BAB120 does not publish the adapter cache; that is a later A550B0 tick.
    }
    void PublishCache() {AssignRetained(native.layout.cacheSession,StringValue(native.layout.sdkSession));}
    void RelocatePublicIp() {
        const auto count=Get<std::int32_t>(native.layout.publicIp+8);
        const auto data=Get<std::uintptr_t>(native.layout.publicIp);
        RS2_CHECK(count>1 && count<=32);
        std::memcpy(native.heap.data()+0x800,reinterpret_cast<const void*>(data),static_cast<std::size_t>(count)*2);
        native.Put(native.layout.publicIp,native.heapBase+0x800);native.Put<std::int32_t>(native.layout.publicIp+12,48);
    }
    void Callback(bool valid=true) {
        static constexpr std::uint32_t frames[]{0xBF746E,0xBD2CAC,0xBE853A,0xB9880D,0xBE8044,0xBD1AD9,
            0xBE874A,0xBC32FD,0xBE7E44,0xBD1999,0xBE874A,0xBC32FD,0xBE7E44,0xBD1999,0xBE874A,0xC02D42,0xA4B370,0xA341A7,0x5F48E6,0x585650};
        SetLeechCreateCaptureForTest(frames,std::size(frames),!valid,true);
        native.Put(native.layout.genericPool,4u);runtime.pumpDepth=0;runtime.timingDepth=0;
        InvokeLeechCreateSuccessForTest(*recovery,reinterpret_cast<const void*>(native.base+kResult),79);
        if(Get<std::uint32_t>(native.layout.genericPool+4)==79) {
            std::memset(native.image.data()+native.layout.genericPool,0,0x78);
            native.Put<std::int32_t>(native.createObject+0x20,-1);
        }
        runtime.pumpDepth=1;runtime.timingDepth=1;
    }
};
SequenceFixture* SequenceFixture::active{};
void NativeGuardReasons() {
    auto before=std::make_unique<RecoveryNativeSnapshot>();
    TaskSnapshot heartbeat{};
    before->core=1;before->httpManager=1;before->asyncManager=1;before->auth=7;before->role=1;
    before->previousReady=1;before->previousConnected=1;before->connected=1;
    before->authorizationToken.size=1;before->authorizationBytes[0]='a';
    before->coreGuid.size=36;
    std::memcpy(before->coreGuidBytes,leech_fixture::NativeFixture::kCoreGuid,sizeof(before->coreGuidBytes));
    before->publicIpData=1;before->publicIpCount=2;before->publicIpChars[0]='1';
    before->standalone=3;before->sdkSession.size=1;before->issuedId=1;before->genericFree=2;
    before->finish.firstFree=0;before->finish.slots[0].references=-1;
    before->create.firstFree=0;before->create.slots[0].references=-1;
    before->heartbeat.type=43;heartbeat.identity.slot=0;heartbeat.identity.id=42;
    heartbeat.identity.holder=(43u<<16)|2u;before->heartbeatId=42;
    before->generic[0].id=42;before->generic[0].holder=heartbeat.identity.holder;
    before->heartbeat.slots[2].references=1;
    const auto check=[&](RecoveryNativeResult result,RecoveryReason expected) {
        RS2_CHECK(NativeGuardReasonForTest(result,*before,heartbeat)==expected);
    };
    check(RecoveryNativeResult::Ready,RecoveryReason::SnapshotGuardPassed);
    check(RecoveryNativeResult::Unreadable,RecoveryReason::GuardSnapshotUnreadable);
    check(RecoveryNativeResult::Changed,RecoveryReason::GuardSnapshotChanged);
    check(RecoveryNativeResult::Descriptor,RecoveryReason::GuardSnapshotDescriptor);
    check(RecoveryNativeResult::Pool,RecoveryReason::GuardSnapshotPool);
    before->coreGuid.size=0;check(RecoveryNativeResult::Ready,RecoveryReason::GuardReadiness);before->coreGuid.size=36;
    std::memcpy(before->coreGuidBytes,"00000000-0000-0000-0000-000000000000",sizeof(before->coreGuidBytes));
    check(RecoveryNativeResult::Ready,RecoveryReason::GuardReadiness);
    std::memcpy(before->coreGuidBytes,leech_fixture::NativeFixture::kCoreGuid,sizeof(before->coreGuidBytes));
    before->core=0;check(RecoveryNativeResult::Ready,RecoveryReason::GuardReadiness);before->core=1;
    before->standalone=2;check(RecoveryNativeResult::Ready,RecoveryReason::GuardStandalone);before->standalone=3;
    before->finish.slots[0].references=1;check(RecoveryNativeResult::Ready,RecoveryReason::GuardFinishFree);
    before->finish.slots[0].references=-1;
    before->generic[0].holder=0;check(RecoveryNativeResult::Ready,RecoveryReason::GuardGenericHolder);
    before->generic[0].holder=heartbeat.identity.holder;
    before->heartbeat.slots[2].references=2;check(RecoveryNativeResult::Ready,RecoveryReason::GuardHeartbeatReferences);
}
#if defined(RS2_RECOVERY_GUARD_PROBE)
void ReadOnlyGuardProbe() {
    auto f=std::make_unique<SequenceFixture>();auto& r=*f->recovery;
    r.qualifyingRecordSequence=1;StoreStatusWord(f->status.worker.observedSequence,1);
    f->runtime.counters.reportSequence=1;
    f->runtime.transport.generatedSequence=1;
    f->runtime.transport.submittedSequence=1;
    ReleaseCapture(f->runtime,f->runtime.recoveryQuota);
    RS2_CHECK(f->Service(Now()));
    RS2_CHECK(!r.terminal && r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Qualifying));
    RS2_CHECK(nativeCalls==0 && f->order.empty());
    // The first guard pass is not a terminal result while native-log transport
    // has no quiescence witness. A later owner visit must evaluate it again.
    f->native.Put<std::uint32_t>(f->native.layout.issuedId,UINT32_MAX);
    RS2_CHECK(f->Service(Now()));
    RS2_CHECK(r.terminal && r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Rejected));
    RS2_CHECK(r.value.reason==static_cast<std::uint64_t>(RecoveryReason::GuardIssuedId) &&
        r.value.outcome==static_cast<std::uint64_t>(RecoveryOutcome::MechanicsFailed));
    RS2_CHECK((r.value.flags&RecoveryTerminal) && !(r.value.flags&RecoveryRestartRequired));
    RS2_CHECK(!r.cancelEntered && !r.createInstalled && !f->runtime.bindingSuspended);
    RS2_CHECK(nativeCalls==0 && f->order.empty());
    const auto scalar=f->Scalar();
    RS2_CHECK(scalar.wire.payload.phase==r.value.phase && scalar.wire.payload.reason==r.value.reason);
}
#else
void ActiveGuardReasonCompatibility() {
    auto f=std::make_unique<SequenceFixture>();auto& r=*f->recovery;
    r.qualifyingRecordSequence=1;StoreStatusWord(f->status.worker.observedSequence,1);
    f->runtime.counters.reportSequence=1;f->runtime.transport.generatedSequence=1;f->runtime.transport.submittedSequence=1;
    ReleaseCapture(f->runtime,f->runtime.recoveryQuota);
    RS2_CHECK(f->Service(Now()));
    RS2_CHECK(!r.terminal && r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Qualifying));
    RS2_CHECK(r.value.oldSdkFingerprint!=0 && r.value.oldCacheFingerprint==r.value.oldSdkFingerprint);
    RS2_CHECK(nativeCalls==0 && f->order.empty());
    f->native.Put<std::uint32_t>(f->native.layout.issuedId,UINT32_MAX);
    RS2_CHECK(f->Service(Now()));
    RS2_CHECK(r.terminal && r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Rejected));
    RS2_CHECK(r.value.reason==static_cast<std::uint64_t>(RecoveryReason::GuardIssuedId) &&
        r.value.outcome==static_cast<std::uint64_t>(RecoveryOutcome::MechanicsFailed));
    RS2_CHECK(nativeCalls==0 && f->order.empty());
}
#endif
void SequenceOrder(const SequenceFixture& f,std::initializer_list<const char*> expected) {
    RS2_CHECK(f.order.size()==expected.size());
    if(f.order.size()!=expected.size()) return;
    auto wanted=expected.begin();for(const auto* observed:f.order) RS2_CHECK(!std::strcmp(observed,*wanted++));
}
void FinishSequence(SequenceFixture& f,bool rotateAuthorization=false,bool relocateIp=false) {
    SubmitLeechFinishForTest(f.runtime,*f.recovery);
    SequenceOrder(f,{"type","init","allocate","bind","resolve","copy","cancel","enqueue","release"});
    const auto& r=*f.recovery;
    RS2_CHECK(!r.terminal && !r.finishObserved && !r.finishTrue && r.enqueueReturned && r.finishId==78);
    RS2_CHECK(r.value.apiReturnedId==78 && r.value.callbackId==0 && r.value.requestId==78);
    RS2_CHECK(r.value.resourcePhase==static_cast<std::uint64_t>(ResourcePhase::LocalReleased) && f.holderReleases==1 && !f.slotReleases);
    RS2_CHECK(r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::FinishSubmitted) && !r.createInstalled);
    RS2_CHECK(f.Get<std::uint32_t>(f.native.layout.genericPool)==4 &&
        f.Get<std::int32_t>(f.native.finishObject+0x20)==1);
    if(rotateAuthorization) f.StringData(f.native.layout.authorizationToken)[0]='S'; // Same header, changed bytes.
    if(relocateIp) f.RelocatePublicIp();
    RS2_CHECK(f.Service(Now()));
    RS2_CHECK(!r.terminal && r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::FinishSubmitted) && f.order.size()==9);
    f.CompleteFinish();
    RS2_CHECK(r.finishObserved && r.finishTrue && r.value.callbackId==78 && f.finishDrains==1);
    RS2_CHECK(r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::FinishSubmitted) && f.order.size()==9);
    RS2_CHECK(f.Get<std::uint32_t>(f.native.layout.genericPool)==0 &&
        f.Get<std::int32_t>(f.native.finishObject+0x20)==-1);
    // Callback/disposal completed in one native drain. Only later owner visits
    // first accept that result and then perform cleanup/start/create.
    RS2_CHECK(f.Service(Now()));
    RS2_CHECK(r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::FinishAccepted) && f.order.size()==9);
}
void IrreversibleSequenceSuccess() {
  for(unsigned scenario=0;scenario<8;++scenario) {
    auto f=std::make_unique<SequenceFixture>();auto& r=*f->recovery;
    if(scenario==5 || scenario==6) {
        f->PilotScope();
        const unsigned bots=scenario==5 ? 1u : 32u;
        f->Population(scenario==5 ? 2u : 65u,scenario==5 ? 1u : 33u);
        f->native.HeapPut<std::int32_t>(0x1042F0,static_cast<std::int32_t>(bots));
        f->native.HeapPut<std::int32_t>(0x106094,static_cast<std::int32_t>(bots));
        f->native.Put<std::uint32_t>(0x17989F8,bots);f->MetadataJson(scenario==5 ? 2u : 65u);
        RS2_CHECK(RecoveryRuntimeSource(f->runtime,&r.source)==Reason::None);
    }
    if(scenario==7) {
        f->PilotScope();
        f->native.Put<std::int32_t>(f->native.layout.genericPool+0x68,12);
        f->native.Put<std::int32_t>(f->native.layout.genericPool+0x6C,6);
        f->native.Put<std::uint8_t>(f->native.layout.genericPool+0x70,1);
        RS2_CHECK(RecoveryRuntimeTask(f->runtime,&r.oldHeartbeat)==Reason::None);
    }
    if(scenario==4) {
        f->native.HeapString(f->native.finishObject+0x28,0x190000,"retained-previous-finish-session");
        RS2_CHECK(f->native.Snapshot(r.before)==RecoveryNativeResult::Ready);
        RS2_CHECK(r.before.finish.firstFree==0 && RequireFinishFirstFree(r.before)==RecoveryNativeResult::Ready);
        r.current=r.before;
    }
    FinishSequence(*f,scenario==1,scenario==3);
    const auto originalBody=f->native.image[0xBAB120];
    const auto cacheData=f->Get<std::uintptr_t>(f->native.layout.cacheSession);
    const auto cacheCapacity=f->Get<std::uint64_t>(f->native.layout.cacheSession+0x18);
    RecreateLeechForTest(f->runtime,r);
    SequenceOrder(*f,{"type","init","allocate","bind","resolve","copy","cancel","enqueue","release","cleanup","start","create"});
    RS2_CHECK(!r.terminal && r.createInstalled && r.createId==79 && r.createSlot==0 && r.createHolder==(41u<<16));
    RS2_CHECK(ChangedOnlyLeechCreateForTest(r,true));
    RS2_CHECK(f->Get<std::uintptr_t>(f->native.layout.cacheSession)==cacheData &&
        f->Get<std::uint64_t>(f->native.layout.cacheSession+0x18)==cacheCapacity &&
        f->Get<std::uint64_t>(f->native.layout.cacheSession+0x10)==0);
    const auto guard=f->Get<std::uintptr_t>(f->native.layout.genericPool+0x48);
    RS2_CHECK(guard!=reinterpret_cast<std::uintptr_t>(&SequenceFixture::Forward) && f->native.image[0xBAB120]==originalBody);
    const auto credits=f->runtime.transport.reservedCredits,records=f->runtime.counters.reportSequence,publication=f->recoveryStatus.ownerSequence;
    if(scenario==2) f->native.HeapString(f->native.layout.authorizationToken,0x200,"synthetic-authorization-token-after-refresh-expanded");
    f->Callback();
    RS2_CHECK(!r.terminal && r.createReturned && f->forwardCalls==1 && (r.value.flags&RecoveryCreateForwardNormalCompleted));
    RS2_CHECK(r.callbackTiming.phase==PrimaryCallbackTimingPhase::CompleteValid && !r.callbackDepth);
    RS2_CHECK(f->runtime.transport.reservedCredits==credits && f->runtime.counters.reportSequence==records && f->recoveryStatus.ownerSequence==publication);
    const auto ticks=r.callbackTiming.ticks;
    // Stock success has not published the cache. A later publisher tick must
    // supply a matching narrow value before the owner accepts publication.
    RS2_CHECK(f->Get<std::uint64_t>(f->native.layout.cacheSession+0x10)==0);
    RS2_CHECK(f->Service(Now()));
    RS2_CHECK(r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Recreating) && !r.terminal);
    f->PublishCache();f->StringData(f->native.layout.cacheSession)[0]='X';RS2_CHECK(f->Service(Now()));
    RS2_CHECK(r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Recreating) && !r.terminal);
    f->PublishCache();RS2_CHECK(f->Service(Now()));
    RS2_CHECK(r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Published) && !f->runtime.bindingSuspended && !r.terminal);
    RS2_CHECK(r.value.newSdkFingerprint!=0 && r.value.newCacheFingerprint==r.value.newSdkFingerprint);
    TaskSnapshot newBinding{};
    RS2_CHECK(InstallTaskBinding(f->runtime.task,f->Access(),f->runtime.config.task,{1,2},&newBinding)==Reason::None);
    f->runtime.counters.bindingEpoch=2;
    RS2_CHECK(f->Service(Now()));
    RS2_CHECK(r.terminal && r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Observed) && !f->runtime.transport.reservedCredits);
    RS2_CHECK(f->metadataHeads==1 && f->metadataFills==1 && f->metadataUpdates==1 && f->metadataDestroys==1);
    RS2_CHECK((r.value.flags&(RecoveryPublishedLocally|RecoveryMetadataAttempted|RecoveryMetadataCoherent))==
        (RecoveryPublishedLocally|RecoveryMetadataAttempted|RecoveryMetadataCoherent));
    if(scenario==5 || scenario==6) RS2_CHECK(f->Get<std::uint32_t>(0x17989F8)==(scenario==5 ? 1u : 32u));
    RS2_CHECK(r.value.callbackOwnTicks==ticks && (r.value.flags&RecoveryCallbackOwnTimingValid));
    InvokeLeechCreateSuccessForTest(r,reinterpret_cast<const void*>(f->native.base+SequenceFixture::kResult),79);
    RS2_CHECK(f->forwardCalls==1 && r.callbackTiming.ticks==ticks && r.value.callbackOwnTicks==ticks);
    RS2_CHECK(f->holderReleases==1 && f->native.image[0xBAB120]==originalBody);
  }
}
void SynchronousFinishError() {
    auto f=std::make_unique<SequenceFixture>();f->synchronousFinishError=true;
    SubmitLeechFinishForTest(f->runtime,*f->recovery);const auto& r=*f->recovery;
    RS2_CHECK(r.terminal && r.finishObserved && !r.finishTrue &&
        r.value.reason==static_cast<std::uint64_t>(RecoveryReason::FinishRejected));
    RS2_CHECK((r.value.flags&RecoveryRestartRequired) && !r.createInstalled && f->holderReleases==1 && !f->slotReleases);
    RS2_CHECK(f->Get<std::uint32_t>(f->native.layout.genericPool)==0 &&
        f->Get<std::int32_t>(f->native.finishObject+0x20)==-1);
}
void PreparePublished(SequenceFixture& f) {
    FinishSequence(f);RecreateLeechForTest(f.runtime,*f.recovery);f.Callback();f.PublishCache();
    RS2_CHECK(f.Service(Now()) && f.recovery->value.phase==static_cast<std::uint64_t>(RecoveryPhase::Published));
    TaskSnapshot bound{};RS2_CHECK(InstallTaskBinding(f.runtime.task,f.Access(),f.runtime.config.task,{1,2},&bound)==Reason::None);
    f.runtime.counters.bindingEpoch=2;
}
void PreflightRetryAndNativeBoundary() {
    for(bool foreign:{false,true}) {
        auto fault=std::make_unique<SequenceFixture>();fault->PilotScope();auto& ended=*fault->recovery;
        ended.control.enabled=true;ended.control.started=1;ended.control.latched=1;
        ended.qualifyingRecordSequence=1;StoreStatusWord(fault->status.worker.observedSequence,1);
        fault->native.HeapPut<std::int32_t>(0x1042E0,1);
        RS2_CHECK(fault->Service(Now()) && (ended.value.flags&RecoveryPreflightRetryable));
        if(foreign) InterlockedExchange(&ended.foreignFault,1);
        else ended.control.result=static_cast<LONG>(recovery::ControlResult::WorkerFailure);
        RS2_CHECK(RecoveryServiceDue(fault->runtime) && fault->Service(Now()));
        RS2_CHECK(!(ended.value.flags&RecoveryPreflightRetryable) && ended.value.operationSequence==1 &&
            ended.value.reason==static_cast<std::uint64_t>(foreign ? RecoveryReason::CallbackInvalid : RecoveryReason::ControlWorkerUnavailable) &&
            !ended.recipeEntered && fault->order.empty() && !RecoveryServiceDue(fault->runtime));
        const auto exported=fault->Scalar();
        RS2_CHECK(exported.wire.payload.flags==ended.value.flags && exported.wire.payload.reason==ended.value.reason);
    }
    {
        auto idle=std::make_unique<SequenceFixture>();idle->PilotScope();idle->Population(65,33);
        idle->native.HeapPut<std::int32_t>(0x1042F0,32);idle->native.HeapPut<std::int32_t>(0x106094,32);
        idle->native.Put<std::int32_t>(idle->native.layout.genericPool+0x68,12);
        idle->native.Put<std::int32_t>(idle->native.layout.genericPool+0x6C,6);
        idle->native.Put<std::uint8_t>(idle->native.layout.genericPool+0x70,1);
        auto& admitted=*idle->recovery;admitted.qualifyingRecordSequence=1;StoreStatusWord(idle->status.worker.observedSequence,1);
        RS2_CHECK(idle->Service(Now()) && !admitted.terminal && admitted.oldHeartbeat.schedule.errors==12 &&
            admitted.oldHeartbeat.schedule.throttles==6 && admitted.source.outer.bots==32 && admitted.source.outer.pi==65 &&
            !admitted.recipeEntered && idle->order.empty()); // Still awaiting the real transport quiescence witness.
    }
    for(unsigned invalid=0;invalid<3;++invalid) {
        auto bad=std::make_unique<SequenceFixture>();bad->PilotScope();auto& q=*bad->recovery;
        if(invalid==0) bad->native.Put<std::int32_t>(bad->native.layout.genericPool+0x68,-1);
        if(invalid==1) bad->native.Put<std::int32_t>(bad->native.layout.genericPool+0x6C,-1);
        if(invalid==2) bad->native.Put<std::uint8_t>(bad->native.layout.genericPool+0x70,2);
        q.qualifyingRecordSequence=1;StoreStatusWord(bad->status.worker.observedSequence,1);
        RS2_CHECK(bad->Service(Now()) && q.terminal && q.value.reason==77+invalid && !q.recipeEntered && bad->order.empty());
    }
    auto f=std::make_unique<SequenceFixture>();f->PilotScope();auto& r=*f->recovery;
    r.control.enabled=true;r.control.started=1;r.control.latched=1;
    r.qualifyingRecordSequence=1;StoreStatusWord(f->status.worker.observedSequence,1);
    f->native.HeapPut<std::int32_t>(0x1042E0,1); // Qualified source reads real spectators.
    RS2_CHECK(f->Service(Now()) && r.terminal && r.value.reason==static_cast<std::uint64_t>(RecoveryReason::SpectatorsPresent));
    RS2_CHECK((r.value.flags&RecoveryPreflightRetryable) && !r.control.latched && !r.recipeEntered && f->order.empty());
    RS2_CHECK(!RecoveryServiceDue(f->runtime));
    const auto firstOperation=r.value.operationSequence,firstTransition=r.value.transitionSequence;
    const auto records=f->Records();bool finalFound=false;
    for(const auto& record:records) if(record.header.kind==static_cast<std::uint64_t>(RecordKindV3::Recovery) &&
        record.payload.recovery.event==static_cast<std::uint64_t>(RecoveryEvent::Final) &&
        record.payload.recovery.reason==static_cast<std::uint64_t>(RecoveryReason::SpectatorsPresent)) finalFound=true;
    RS2_CHECK(finalFound); // The incident's missing terminal log must regress.
    f->native.HeapPut<std::int32_t>(0x1042E0,0);
    RS2_CHECK(recovery::ClaimControlForTesting(r.control,recovery::RequestOrigin::Pipe));
    RS2_CHECK(RecoveryServiceDue(f->runtime) && f->Service(Now()));
    RS2_CHECK(!r.terminal && r.value.operationSequence==firstOperation+1 && r.value.transitionSequence>firstTransition &&
        r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Qualifying) && !(r.value.flags&RecoveryPreflightRetryable));
    RS2_CHECK(!recovery::ClaimControlForTesting(r.control,recovery::RequestOrigin::Pipe));
    // A changing read-only native snapshot is also safely retryable; the
    // eligibility policy must not be another hand-picked diagnostic whitelist.
    r.terminal=true;r.finalPending=true;r.value.reason=static_cast<std::uint64_t>(RecoveryReason::GuardSnapshotChanged);
    r.value.outcome=static_cast<std::uint64_t>(RecoveryOutcome::MechanicsFailed);
    FinishLeechTerminalForTest(f->runtime,r,Now());
    RS2_CHECK((r.value.flags&RecoveryPreflightRetryable) && !r.control.latched && !r.recipeEntered);
    r.control.consoleRequested=true;r.control.consoleRegistration=static_cast<LONG>(recovery::ConsoleRegistration::Available);
    RS2_CHECK(recovery::ClaimConsoleControlRequest(r.control) && f->Service(Now()) && !r.terminal && r.value.operationSequence==firstOperation+2);
    // A later refusal after ANY native entry must stay spent, even when Cancel
    // was never reached. Exercise the same terminal publication function.
    r.recipeEntered=true;r.value.nativeStage=static_cast<std::uint64_t>(NativeStage::Descriptor);
    r.terminal=true;r.finalPending=true;r.value.reason=static_cast<std::uint64_t>(RecoveryReason::HeartbeatUnavailable);
    FinishLeechTerminalForTest(f->runtime,r,Now());
    RS2_CHECK(!(r.value.flags&RecoveryPreflightRetryable) && r.control.latched==2 && !r.cancelEntered);
}
void RevokedPreflightDoesNotStarveCleanup() {
    for(const auto phase:{RecoveryPhase::Requested,RecoveryPhase::Qualifying}) {
        auto f=std::make_unique<SequenceFixture>();auto& r=*f->recovery;
        r.value.phase=static_cast<std::uint64_t>(phase);
        RevokeStatus(f->status,Reason::RecordLoss);
        RS2_CHECK(f->Service(Now()) && r.terminal && !r.pendingCount && !r.finalPending);
        RS2_CHECK(!RecoveryServiceDue(f->runtime) && !f->runtime.recoveryQuota.active && !f->runtime.transport.reservedCredits);
        CleanupRevokedRuntime(f->runtime,CallerClass::NormalPump);
        RS2_CHECK(f->runtime.task.inverseAttempted && !f->runtime.task.stranded && ReadTaskPhase(f->runtime.task)==TaskPhase::Inert &&
            f->Get<std::uintptr_t>(f->native.layout.genericPool+0x40)==f->runtime.task.original && !r.recipeEntered);
    }
    // No records/native work are allowed on an unsupported capture. A later
    // qualified normal owner may finish a pure preflight timeout instead of
    // leaving it permanently spent with no terminal explanation.
    auto f=std::make_unique<SequenceFixture>();f->PilotScope();auto& r=*f->recovery;
    r.control.enabled=true;r.control.started=1;r.control.latched=1;
    const auto now=Now();r.value.finishDeadlineQpc=now-1;
    RS2_CHECK(!ServiceLeechRecovery(f->runtime,CallerClass::Unknown,3,false,static_cast<std::int64_t>(now)));
    RS2_CHECK(r.terminal && r.finalPending && !r.recipeEntered && f->Records().empty());
    RS2_CHECK(RecoveryServiceDue(f->runtime) && f->Service(Now()));
    RS2_CHECK((r.value.flags&RecoveryPreflightRetryable) && !r.control.latched && !RecoveryServiceDue(f->runtime));
}
void PilotPopulationBounds() {
    // Exercise the real owner admission path, not only UUID-view construction.
    for(const auto pi:{0u,2u,65u,256u,257u}) {
        auto f=std::make_unique<SequenceFixture>();f->PilotScope();f->Population(pi);
        auto& r=*f->recovery;r.qualifyingRecordSequence=1;
        StoreStatusWord(f->status.worker.observedSequence,1);
        RS2_CHECK(f->Service(Now()));
        if(pi>kRecoveryMetadataMemberLimit) {
            RS2_CHECK(r.terminal && !r.cancelEntered && f->order.empty() &&
                r.value.reason==static_cast<std::uint64_t>(RecoveryReason::MetadataCountLimit));
        } else {
            // Population and native guards pass, but this fixture deliberately
            // has no native-log quiescence witness. Never bypass that separate
            // gate merely to make a successful admission test invoke Cancel.
            RS2_CHECK(!r.cancelEntered && !r.terminal && f->order.empty() && r.source.outer.pi==pi &&
                r.source.maximum==64 && r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Qualifying));
            RS2_CHECK(r.value.oldSdkFingerprint && r.value.oldSdkFingerprint==r.value.oldCacheFingerprint);
        }
    }
    for(unsigned scenario=0;scenario<4;++scenario) {
        auto f=std::make_unique<SequenceFixture>();f->PilotScope();f->Population(2);
        if(scenario==0) {f->recovery->control.scope=rs2fix::recovery::kTrainingControlScope;f->Population(2,1);}
        if(scenario==1) f->runtime.config.mode=Mode::Repair;
        if(scenario==2) {f->native.HeapPut<std::int32_t>(0x1042E4,65);f->native.HeapPut<std::int32_t>(0x10609C,65);}
        if(scenario==3) {f->recovery->control.scope=rs2fix::recovery::kTrainingControlScope;f->native.HeapPut<std::int32_t>(0x1042F0,1);}
        auto& r=*f->recovery;r.qualifyingRecordSequence=1;StoreStatusWord(f->status.worker.observedSequence,1);
        RS2_CHECK(f->Service(Now()) && r.terminal && !r.cancelEntered && f->order.empty());
    }
    // Population changes AFTER recreation must use the latest qualified native
    // PI, including values above human maximum, and refuse 257 without truncation.
    for(const auto pi:{0u,2u,65u,256u,257u}) {
        auto f=std::make_unique<SequenceFixture>();f->PilotScope();PreparePublished(*f);f->Population(pi);
        auto& r=*f->recovery;RS2_CHECK(f->Service(Now()));
        RS2_CHECK(r.terminal && r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Observed) &&
            !(r.value.flags&RecoveryRestartRequired));
        if(pi==0) RS2_CHECK(!f->metadataHeads && !f->metadataRandomCalls && (r.value.flags&RecoveryMetadataCoherent));
        else if(pi<=kRecoveryMetadataMemberLimit) {
            RS2_CHECK(f->metadataUpdates==1 && f->metadataDestroys==1 && r.metadataMembers.count==pi);
            RS2_CHECK(f->Get<std::uintptr_t>(f->native.layout.kernelVector+8)-f->Get<std::uintptr_t>(f->native.layout.kernelVector)==pi*32);
        } else RS2_CHECK(!f->metadataHeads && !f->metadataRandomCalls &&
            r.value.reason==static_cast<std::uint64_t>(RecoveryReason::MetadataCountLimit));
    }
}
void MetadataObservationWindow() {
    for(bool coherent : {false,true}) {
        auto f=std::make_unique<SequenceFixture>();f->PilotScope();
        auto& r=*f->recovery;
        f->Population(32,2);
        f->native.HeapPut<std::int32_t>(0x1042F0,30);f->native.HeapPut<std::int32_t>(0x106094,30);
        f->native.HeapPut<std::int32_t>(0x1042E4,32);f->native.HeapPut<std::int32_t>(0x10609C,32);
        f->native.Put<std::uint32_t>(0x17989F8,30);f->native.Put<std::uint32_t>(0x17989FC,32);
        f->native.Put<std::uint32_t>(0x14AAD68,32);
        f->native.HeapString(0x14AAD48,0x1C0000,
            R"({"ip":"192.0.2.123","op":[{"k":"PI_COUNT","v":"32"},{"k":"BotPlayerCount","v":"30"},{"k":"MaxPlayerCount","v":"32"}]})",4096);
        RS2_CHECK(RecoveryRuntimeSource(f->runtime,&r.source)==Reason::None);
        f->runtime.source=r.source;
        RS2_CHECK(f->native.Snapshot(r.before)==RecoveryNativeResult::Ready);r.current=r.before;
        PreparePublished(*f);
        f->native.Put<std::uint8_t>(0x17989F0,1); // Let the stock update finish; no explicit repair admitted.
        const auto publication=r.value.qpc;
        RS2_CHECK(r.metadataDeadlineQpc==publication+f->frequency*65 && r.metadataDeadlineQpc<r.value.overallDeadlineQpc);
        // Cover the observed ~60s cadence beyond the former 45s window without
        // sleeping or changing the real clock: consume 62s of both budgets.
        const auto elapsed=f->frequency*62;
        r.metadataDeadlineQpc=r.metadataDeadlineQpc>elapsed ? r.metadataDeadlineQpc-elapsed : 0;
        r.value.overallDeadlineQpc-=elapsed;
        if(coherent) {
            const auto end=f->Get<std::uintptr_t>(f->native.layout.kernelVector)+32*32;
            f->native.Put(f->native.layout.kernelVector+8,end);
            f->native.Put(f->native.layout.kernelVector+16,end);
        }
        const auto nativeOrder=f->order.size();
        RS2_CHECK(f->Service(Now())==coherent);
        RS2_CHECK(!f->metadataHeads && !f->metadataUpdates && f->order.size()==nativeOrder &&
            r.value.operationSequence==1 && !(r.value.flags&(RecoveryRestartRequired|RecoveryPreflightRetryable|RecoveryMetadataAttempted)));
        if(coherent) {
            RS2_CHECK(r.terminal && r.value.reason==0 && (r.value.flags&RecoveryMetadataCoherent));
            RS2_CHECK(r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Observed));
        } else {
            RS2_CHECK(!r.terminal && r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Published) &&
                r.value.reason==static_cast<std::uint64_t>(RecoveryReason::MetadataCountsNotReady));
            RS2_CHECK(f->Service(r.metadataDeadlineQpc));
            RS2_CHECK(r.terminal && r.value.reason==static_cast<std::uint64_t>(RecoveryReason::MetadataTimeout) &&
                (r.value.flags&RecoveryMetadataUnverified) && !(r.value.flags&RecoveryMetadataCoherent));
        }
        RS2_CHECK(r.value.outcome==static_cast<std::uint64_t>(RecoveryOutcome::PublishedNotDelivered) &&
            !f->metadataHeads && !f->metadataUpdates && !f->runtime.transport.reservedCredits);
    }
}
void MetadataRefusalsAndCleanup() {
    for(unsigned scenario=0;scenario<5;++scenario) {
        auto f=std::make_unique<SequenceFixture>();PreparePublished(*f);auto& r=*f->recovery;
        if(scenario==0) f->metadataRandomFails=true;
        if(scenario==1) f->native.Put<std::uint8_t>(0x17989F0,1); // Stock update pending.
        if(scenario==2) f->metadataChangesCounts=true; // Changes after fill, before update.
        if(scenario==3) f->metadataLeavesMismatch=true;
        if(scenario==4) f->native.Put(f->native.layout.kernelVector+8,f->native.heapBase+0x60000+2*32); // Already coherent.
        const auto completed=f->Service(Now());
        if(scenario==1 || scenario==2) {
            RS2_CHECK(!completed && !r.terminal && f->metadataUpdates==0 && !r.metadataHeadOwned);
            RS2_CHECK(f->metadataHeads==(scenario==2 ? 1u : 0u) && f->metadataDestroys==f->metadataHeads);
            r.metadataDeadlineQpc=Now()-1;RS2_CHECK(f->Service(Now()));
            RS2_CHECK(r.value.reason==static_cast<std::uint64_t>(RecoveryReason::MetadataTimeout));
        } else RS2_CHECK(completed && r.terminal);
        RS2_CHECK(r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Observed) && !(r.value.flags&RecoveryRestartRequired));
        RS2_CHECK(r.value.outcome==static_cast<std::uint64_t>(RecoveryOutcome::PublishedNotDelivered));
        if(scenario==0) RS2_CHECK(f->metadataHeads==0 && f->metadataRandomCalls==1 &&
            r.value.reason==static_cast<std::uint64_t>(RecoveryReason::MetadataRandomUnavailable));
        if(scenario==3) RS2_CHECK(f->metadataUpdates==1 && f->metadataDestroys==1 &&
            (r.value.flags&RecoveryMetadataAttempted) && !(r.value.flags&RecoveryMetadataCoherent));
        if(scenario==4) RS2_CHECK(f->metadataHeads==0 && f->metadataRandomCalls==0 &&
            (r.value.flags&RecoveryMetadataCoherent) && !(r.value.flags&RecoveryMetadataAttempted));
    }
    for(unsigned stage=0;stage<4;++stage) {
        auto f=std::make_unique<SequenceFixture>();PreparePublished(*f);auto& r=*f->recovery;
        f->throwMetadataHead=stage==0;f->throwMetadataFill=stage==1;
        f->throwMetadataUpdate=stage==2;f->throwMetadataDestroy=stage==3;
        bool propagated{};try {f->Service(Now());} catch(const SequenceFixture::Exception&) {propagated=true;}
        RS2_CHECK(propagated && r.terminal && (r.value.flags&RecoveryExceptionObserved) && (r.value.flags&RecoveryRestartRequired));
        RS2_CHECK(f->metadataHeads==1 && f->metadataDestroys==(stage==0 ? 0u : 1u));
        FinishLeechTerminalForTest(f->runtime,r,Now());
        RS2_CHECK(r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Failed));
        const auto destroys=f->metadataDestroys;
        FinishLeechTerminalForTest(f->runtime,r,Now());RS2_CHECK(f->metadataDestroys==destroys);
    }
    {
        auto f=std::make_unique<SequenceFixture>();PreparePublished(*f);auto& r=*f->recovery;
        const auto value=f->StringValue(f->native.layout.sdkSession);
        f->native.HeapString(f->native.layout.sdkSession,0x1B8000,value.c_str(),63); // Same ID, new owned buffer.
        RS2_CHECK(f->Service(Now()) && (r.value.flags&RecoveryMetadataCoherent) && !(r.value.flags&RecoveryRestartRequired));
    }
    {
        auto f=std::make_unique<SequenceFixture>();PreparePublished(*f);auto& r=*f->recovery;
        f->StringData(f->native.layout.sdkSession)[0]='X';f->StringData(f->native.layout.cacheSession)[0]='X';
        RS2_CHECK(f->Service(Now()) && r.terminal && (r.value.flags&RecoveryRestartRequired) && !f->metadataHeads);
        RS2_CHECK(r.value.reason==static_cast<std::uint64_t>(RecoveryReason::PublishedIdentityChanged));
    }
}
void PublishedObservationFaults() {
    for(unsigned scenario=0;scenario<5;++scenario) {
        Fixture f;f.FinishPhase(RecoveryPhase::Published);f.Reserve();auto& r=*f.recovery;
        r.value.flags|=RecoveryPublishedLocally;
        if(scenario<2) {
            r.value.overallDeadlineQpc=Now()-1;r.metadataDeadlineQpc=r.value.overallDeadlineQpc-1;
            if(!scenario) RS2_CHECK(f.Service(Now()));
            else RS2_CHECK(!ServiceLeechRecovery(f.runtime,CallerClass::Unknown,0,true,static_cast<std::int64_t>(Now())));
        } else if(scenario==2) {
            RecoveryOwnerClockFault(f.runtime);FinishLeechTerminalForTest(f.runtime,r,Now());
        } else if(scenario==3) {
            f.runtime.transport.state=static_cast<std::uint64_t>(TransportState::Paused);RS2_CHECK(f.Service(Now()));
        } else {
            r.metadataDeadlineQpc=Now()+f.frequency*30;++f.runtime.counters.sourceEpoch;RS2_CHECK(f.Service(Now()));
        }
        RS2_CHECK(r.terminal && r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Observed));
        RS2_CHECK(!(r.value.flags&RecoveryRestartRequired) && (r.value.flags&RecoveryMetadataUnverified));
        RS2_CHECK(r.value.outcome==static_cast<std::uint64_t>(RecoveryOutcome::PublishedNotDelivered));
        RS2_CHECK(f.memoryReads==0 && f.memoryQueries==0 && nativeCalls==0 && !f.runtime.transport.reservedCredits);
        if(scenario<2) RS2_CHECK(r.value.reason==static_cast<std::uint64_t>(RecoveryReason::MetadataTimeout));
        const auto scalar=f.Scalar();RS2_CHECK(scalar.wire.payload.phase==r.value.phase);
    }
}
void ActualLifetimeChangesRefuse() {
    {
        auto f=std::make_unique<SequenceFixture>();SubmitLeechFinishForTest(f->runtime,*f->recovery);
        RS2_CHECK(!f->recovery->terminal && f->order.size()==9);
        // While Finish is pending, Lifetime is the only GUID equality gate.
        // A callback-only test could be masked by RequireHeartbeatFirstFree.
        f->StringData(f->native.layout.coreGuid)[0]='b';
        RS2_CHECK(f->Service(Now()));const auto& r=*f->recovery;
        RS2_CHECK(r.terminal && (r.value.flags&RecoveryRestartRequired) &&
            r.value.reason==static_cast<std::uint64_t>(RecoveryReason::LifecycleChanged));
        RS2_CHECK(!r.createInstalled && !f->forwardCalls && f->order.size()==9);
    }
    for(unsigned scenario=0;scenario<3;++scenario) {
        auto f=std::make_unique<SequenceFixture>();FinishSequence(*f);RecreateLeechForTest(f->runtime,*f->recovery);
        RS2_CHECK(f->recovery->createInstalled && !f->recovery->terminal);
        if(scenario==0) f->StringData(f->native.layout.coreGuid)[0]='b'; // Same valid header and length.
        else if(scenario==1) f->native.ClearString(f->native.layout.authorizationToken);
        else {
            auto* ip=reinterpret_cast<std::uint16_t*>(f->Get<std::uintptr_t>(f->native.layout.publicIp));ip[0]='2';
        }
        f->Callback();const auto& r=*f->recovery;
        RS2_CHECK(r.terminal && (r.value.flags&RecoveryRestartRequired) && !r.createForwarded && !f->forwardCalls);
        RS2_CHECK(r.value.reason==static_cast<std::uint64_t>(RecoveryReason::CallbackInvalid));
    }
}
void IrreversibleOwnershipUnwind() {
    for(bool enqueue : {false,true}) {
        auto f=std::make_unique<SequenceFixture>();f->throwCopy=!enqueue;f->throwEnqueue=enqueue;
        bool caught=false;try {SubmitLeechFinishForTest(f->runtime,*f->recovery);} catch(const SequenceFixture::Exception&) {caught=true;}
        auto& r=*f->recovery;
        RS2_CHECK(caught && r.terminal && (r.value.flags&RecoveryExceptionObserved) && !r.recipeReturned);
        RS2_CHECK(f->holderReleases==1 && !f->slotReleases && r.value.resourcePhase==static_cast<std::uint64_t>(ResourcePhase::LocalReleased));
        RS2_CHECK(!f->runtime.recoveryQuota.active && !f->runtime.transport.reservedCredits);
        ReleaseLeechOwnedForTest(f->runtime,r);RS2_CHECK(f->holderReleases==1);
        if(enqueue) RS2_CHECK(f->Get<std::uint32_t>(f->native.layout.genericPool)==1 && f->Get<std::int32_t>(f->native.finishObject+0x20)==1);
        else RS2_CHECK(!r.cancelEntered && ReadTaskPhase(f->runtime.task)==TaskPhase::Armed);
    }
}
void InstanceGuardRefusals() {
    for(unsigned scenario=0;scenario<3;++scenario) {
        auto f=std::make_unique<SequenceFixture>();FinishSequence(*f);
        f->changeOther=scenario==0;f->twoCreates=scenario==1;f->raceCas=scenario==2;
        const auto body=f->native.image[0xBAB120];RecreateLeechForTest(f->runtime,*f->recovery);
        RS2_CHECK(f->recovery->terminal && !f->recovery->createInstalled && (f->recovery->value.flags&RecoveryRestartRequired));
        RS2_CHECK(f->native.image[0xBAB120]==body && f->forwardCalls==0);
        const auto success=f->Get<std::uintptr_t>(f->native.layout.genericPool+0x48);
        RS2_CHECK(success==reinterpret_cast<std::uintptr_t>(scenario==2 ? &SequenceFixture::OtherSuccess : &SequenceFixture::Forward));
        if(scenario==2) RS2_CHECK(f->casRaced); // Failed CAS must never restore the competing field.
    }
    auto disabled=std::make_unique<SequenceFixture>();disabled->recovery->prepared=false;
    RS2_CHECK(!disabled->Service(Now()) && !disabled->recovery->createInstalled && disabled->order.empty());
}
void GuardedCallbackRefusalAndUnwind() {
    for(unsigned scenario=0;scenario<3;++scenario) {
        auto f=std::make_unique<SequenceFixture>();FinishSequence(*f);RecreateLeechForTest(f->runtime,*f->recovery);
        RS2_CHECK(f->recovery->createInstalled && !f->recovery->terminal);
        const auto credits=f->runtime.transport.reservedCredits,publication=f->recoveryStatus.ownerSequence;
        f->throwForward=scenario==1;
        bool caught=false;try {f->Callback(scenario!=0);} catch(const SequenceFixture::Exception&) {caught=true;f->runtime.pumpDepth=1;f->runtime.timingDepth=1;}
        auto& r=*f->recovery;RS2_CHECK(caught==(scenario==1));
        RS2_CHECK(f->forwardCalls==(scenario==0 ? 0u : 1u));
        RS2_CHECK((r.value.flags&RecoveryCreateCallbackObserved)!=0 && !r.callbackDepth);
        RS2_CHECK(r.callbackTiming.phase==PrimaryCallbackTimingPhase::CompleteValid);
        RS2_CHECK(f->runtime.transport.reservedCredits==credits && f->recoveryStatus.ownerSequence==publication);
        const auto timing=r.callbackTiming;
        if(scenario==2) {f->Callback();RS2_CHECK(f->forwardCalls==1 && r.terminal);}
        RS2_CHECK(r.terminal);
        if(scenario==1) RS2_CHECK(!(r.value.flags&RecoveryCreateForwardNormalCompleted));
        RS2_CHECK(!std::memcmp(&timing,&r.callbackTiming,sizeof(timing)));
        RS2_CHECK(f->Service(Now()) && !f->runtime.transport.reservedCredits);
    }
}
void RequestAdmission() {
    Fixture f;auto& r=*f.recovery;
    RS2_CHECK(!RecoveryServiceDue(f.runtime));
    r.control.result=static_cast<LONG>(recovery::ControlResult::PendingWrite);
    RS2_CHECK(!RecoveryServiceDue(f.runtime));
    InterlockedExchange(&r.control.latched,1);
    RS2_CHECK(RecoveryServiceDue(f.runtime));
    RS2_CHECK(f.Service(Now()));
    RS2_CHECK(r.requested && r.value.operationSequence==1 && r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Qualifying));
    RS2_CHECK(r.qualifyingRecordSequence==2 && !f.runtime.recoveryQuota.active && !f.runtime.transport.reservedCredits);
    const auto records=f.Records();RS2_CHECK(records.size()==2);
    if(records.size()==2) {
        RS2_CHECK(records[0].payload.recovery.phase==static_cast<std::uint64_t>(RecoveryPhase::Requested));
        RS2_CHECK(records[1].payload.recovery.phase==static_cast<std::uint64_t>(RecoveryPhase::Qualifying));
    }
    // Seeing Requested alone cannot grant cancellation: Qualifying must also
    // have been observed by the existing receipt protocol.
    StoreStatusWord(f.status.worker.observedSequence,1);
    const auto transition=r.value.transitionSequence;
    RS2_CHECK(f.Service(Now()));
    RS2_CHECK(!r.cancelEntered && !r.terminal && r.value.operationSequence==1 && r.value.transitionSequence==transition);
    RS2_CHECK(f.memoryReads==0 && f.memoryQueries==0 && nativeCalls==0 && f.Records().empty());
    Fixture unavailable;auto& rejected=*unavailable.recovery;
    InterlockedExchange(&rejected.control.latched,1);
    unavailable.runtime.transport.reservedCredits=256; // Existing unrelated reservation.
    RS2_CHECK(unavailable.Service(Now()));
    RS2_CHECK(rejected.terminal && !rejected.cancelEntered &&
        rejected.value.reason==static_cast<std::uint64_t>(RecoveryReason::QuotaUnavailable));
    RS2_CHECK(unavailable.runtime.transport.reservedCredits==256 && !unavailable.runtime.recoveryQuota.active && nativeCalls==0);
    // Nonzero claims cannot become invisible to the owner: opted-in console
    // is accepted, but unsupported origin/opt-in state is consumed as a visible
    // clean refusal with no native mutation and no later retry in this process.
    for (unsigned scenario=0;scenario<3;++scenario) {
        Fixture claim;auto& selected=*claim.recovery;
        selected.control.consoleRequested=scenario==0;
        selected.control.consoleRegistration=static_cast<LONG>(recovery::ConsoleRegistration::Available);
        selected.control.scope.schema=2;
        InterlockedExchange(&selected.control.latched,scenario==2 ? 3 : 2);
        RS2_CHECK(RecoveryServiceDue(claim.runtime));
        RS2_CHECK(claim.Service(Now()) && selected.requested && !selected.cancelEntered && nativeCalls==0);
        if(scenario==0) RS2_CHECK(!selected.terminal && selected.value.operationSequence==1);
        else RS2_CHECK(selected.terminal && selected.value.reason==static_cast<std::uint64_t>(RecoveryReason::InvalidRequest) &&
            !(selected.value.flags&RecoveryRestartRequired) && !RecoveryServiceDue(claim.runtime));
    }
}
void FinishCallbacks() {
    for(unsigned scenario=0;scenario<5;++scenario) {
        Fixture f;f.FinishPhase();auto& r=*f.recovery;
        f.callbackByte=static_cast<unsigned char>(scenario);
        const auto* result=scenario==3 ? nullptr : scenario==4 ? reinterpret_cast<const bool*>(static_cast<std::uintptr_t>(0x1234)) :
            reinterpret_cast<const bool*>(&f.callbackByte);
        ObserveLeechFinishForTest(r,result,17,false,0);
        const auto expected=scenario==0 ? CallbackResult::False : scenario==1 ? CallbackResult::True :
            scenario==2 ? CallbackResult::Invalid : scenario==3 ? CallbackResult::Null : CallbackResult::Unreadable;
        RS2_CHECK(r.finishObserved && r.value.callbackId==17 && r.value.callbackResult==static_cast<std::uint64_t>(expected));
        RS2_CHECK(r.finishTrue==(scenario==1) && r.terminal==(scenario!=1) && nativeCalls==0);
    if(scenario!=1) RS2_CHECK(r.value.flags&RecoveryRestartRequired);
    }
    for(const auto id : {0U,18U}) {
        Fixture mismatch;mismatch.FinishPhase();
        ObserveLeechFinishForTest(*mismatch.recovery,reinterpret_cast<const bool*>(&mismatch.callbackByte),id,false,0);
        RS2_CHECK(mismatch.recovery->terminal && !mismatch.recovery->finishObserved &&
            mismatch.recovery->value.reason==static_cast<std::uint64_t>(RecoveryReason::CallbackInvalid));
        RS2_CHECK(!(mismatch.recovery->value.flags&RecoveryCallbackObserved) && mismatch.memoryReads==0 && nativeCalls==0);
    }
    Fixture overdue;overdue.FinishPhase();overdue.recovery->value.finishDeadlineQpc=1;
    ObserveLeechFinishForTest(*overdue.recovery,reinterpret_cast<const bool*>(&overdue.callbackByte),17,false,0);
    RS2_CHECK(overdue.recovery->terminal && overdue.recovery->value.reason==static_cast<std::uint64_t>(RecoveryReason::FinishTimeout));
    RS2_CHECK(!overdue.recovery->finishTrue && overdue.memoryReads==0 && !StatusRevoked(overdue.status));
    Fixture inlineCallback;inlineCallback.FinishPhase();auto& inlineState=*inlineCallback.recovery;
    inlineState.finishId=0;inlineState.enqueueReturned=false;inlineState.value.apiReturnedId=0;
    ObserveLeechFinishForTest(inlineState,reinterpret_cast<const bool*>(&inlineCallback.callbackByte),31,false,0);
    RS2_CHECK(inlineState.finishObserved && inlineState.finishTrue && inlineState.value.callbackId==31 && !inlineState.terminal);
    RS2_CHECK(!inlineState.createInstalled && !inlineState.createForwarded && nativeCalls==0);
    // Full BA8F10 returned-zero reconciliation remains in the native recipe;
    // this assertion covers the required pre-return scalar observation only.
    ObserveLeechFinishForTest(inlineState,reinterpret_cast<const bool*>(&inlineCallback.callbackByte),31,false,0);
    RS2_CHECK(inlineState.terminal && inlineState.value.reason==static_cast<std::uint64_t>(RecoveryReason::CallbackInvalid));
    Fixture error;error.FinishPhase();SetLastError(0x55AB);
    RS2_CHECK(FinishLeechErrorForTest(*error.recovery,-7,17));
    RS2_CHECK(GetLastError()==0x55AB && error.recovery->terminal &&
        error.recovery->value.reason==static_cast<std::uint64_t>(RecoveryReason::FinishRejected));
    Fixture foreign;foreign.FinishPhase();const auto unchanged=foreign.recovery->value;
    std::thread callback([&foreign]{ObserveLeechFinishForTest(*foreign.recovery,reinterpret_cast<const bool*>(&foreign.callbackByte),17,false,0);});
    callback.join();
    RS2_CHECK(foreign.recovery->foreignFault==1 && !std::memcmp(&unchanged,&foreign.recovery->value,sizeof(unchanged)));
    RS2_CHECK(!foreign.recovery->finishObserved && foreign.memoryReads==0 && nativeCalls==0);
    Fixture late;late.FinishPhase();late.recovery->terminal=true;
    late.recovery->value.phase=static_cast<std::uint64_t>(RecoveryPhase::Failed);
    const auto terminal=late.recovery->value;
    ObserveLeechFinishForTest(*late.recovery,reinterpret_cast<const bool*>(&late.callbackByte),17,false,0);
    RS2_CHECK(!std::memcmp(&terminal,&late.recovery->value,sizeof(terminal)) && !late.recovery->finishObserved && nativeCalls==0);
}
void DeadlinesAndUnknownInverse() {
    Fixture f;f.FinishPhase(RecoveryPhase::FinishAccepted);auto& r=*f.recovery;
    const auto now=Now();r.value.finishDeadlineQpc=now-1;r.finishObserved=true;r.finishTrue=true;r.value.callbackId=r.finishId;
    RS2_CHECK(f.Service(now));
    RS2_CHECK(r.terminal && r.value.reason==static_cast<std::uint64_t>(RecoveryReason::FinishTimeout));
    RS2_CHECK(!r.createInstalled && !r.createForwarded && f.memoryQueries==0 && f.memoryReads==0 && nativeCalls==0);
    // A lost fresh logger/native lease while public transport still says Running
    // cannot be treated as ordinary waiting or an already-observed replacement.
    for(const auto phase : {RecoveryPhase::FinishSubmitted,RecoveryPhase::Published}) {
        Fixture crossing;crossing.FinishPhase(phase);
        InterlockedExchange(&crossing.runtime.task.phase,static_cast<LONG>(TaskPhase::Armed));
        RS2_CHECK(crossing.Service(Now()));
        RS2_CHECK(crossing.recovery->terminal && crossing.recovery->value.phase==static_cast<std::uint64_t>(RecoveryPhase::Failed));
        RS2_CHECK(crossing.recovery->value.flags&RecoveryRestartRequired);
        RS2_CHECK(!crossing.recovery->createInstalled && !crossing.recovery->createForwarded && nativeCalls==0);
    }
    Fixture clock;clock.FinishPhase();clock.Reserve();const auto oldQpc=clock.recovery->value.qpc;
    FailRuntimeTiming(clock.runtime,Reason::ClockFailed);
    RecoveryOwnerClockFault(clock.runtime);
    RS2_CHECK(clock.recovery->terminal && clock.recovery->value.reason==static_cast<std::uint64_t>(RecoveryReason::ClockFault));
    RS2_CHECK(StatusRevoked(clock.status) && clock.runtime.timingGap);
    RS2_CHECK(clock.recovery->value.qpc==oldQpc && !clock.runtime.recoveryQuota.active && !clock.runtime.transport.reservedCredits && nativeCalls==0);
    Fixture callbackClock;callbackClock.FinishPhase();callbackClock.Reserve();callbackClock.recovery->callbackDepth=1;
    const auto callbackQpc=callbackClock.recovery->value.qpc;
    // Admission-clock failure has already revoked normal reporting before the
    // recovery hook runs. Retaining callback credits does not permit ring I/O.
    FailRuntimeTiming(callbackClock.runtime,Reason::ClockFailed);
    RecoveryOwnerClockFault(callbackClock.runtime);
    RS2_CHECK(StatusRevoked(callbackClock.status) && callbackClock.runtime.timingGap);
    RS2_CHECK(callbackClock.recovery->terminal && callbackClock.runtime.recoveryQuota.active && callbackClock.runtime.transport.reservedCredits==9);
    RS2_CHECK(callbackClock.runtime.counters.reportSequence==0 && callbackClock.ring.reportWriteSequence==0);
    callbackClock.recovery->callbackDepth=0;
    RS2_CHECK(callbackClock.Service(Now()));
    RS2_CHECK(!callbackClock.runtime.recoveryQuota.active && !callbackClock.runtime.transport.reservedCredits && nativeCalls==0);
    const auto scalar=callbackClock.Scalar();
    RS2_CHECK(scalar.wire.payload.phase==static_cast<std::uint64_t>(RecoveryPhase::Failed) &&
        scalar.wire.payload.reason==static_cast<std::uint64_t>(RecoveryReason::ClockFault) && scalar.wire.payload.qpc==callbackQpc);
    RS2_CHECK((scalar.wire.payload.flags&(RecoveryTerminal|RecoveryRestartRequired))==(RecoveryTerminal|RecoveryRestartRequired));
    RS2_CHECK(callbackClock.runtime.counters.reportSequence==0 && callbackClock.ring.reportWriteSequence==0 && callbackClock.Records().empty());
    RS2_CHECK(callbackClock.Service(Now()));
    RS2_CHECK(!callbackClock.runtime.recoveryQuota.active && !callbackClock.runtime.transport.reservedCredits &&
        callbackClock.runtime.counters.reportSequence==0 && callbackClock.ring.reportWriteSequence==0 && nativeCalls==0);
    Fixture unknown;unknown.FinishPhase();auto& resource=*unknown.recovery;
    resource.value.resourcePhase=static_cast<std::uint64_t>(ResourcePhase::AllocatedUnbound);
    resource.bindEntered=true;resource.bindCompleted=false;
    ReleaseLeechOwnedForTest(unknown.runtime,resource);
    RS2_CHECK(resource.terminal && resource.value.reason==static_cast<std::uint64_t>(RecoveryReason::InverseUnavailable));
    RS2_CHECK(resource.value.flags&RecoveryRestartRequired);
    RS2_CHECK(!resource.resourceReleaseAttempted && resource.value.resourcePhase==static_cast<std::uint64_t>(ResourcePhase::AllocatedUnbound));
    RS2_CHECK(unknown.memoryQueries==0 && unknown.memoryReads==0 && nativeCalls==0);
}
void UnsupportedServicePreservesManagement() {
    Fixture f;InterlockedExchange(&f.recovery->control.latched,1);
    RS2_CHECK(!ServiceLeechRecovery(f.runtime,CallerClass::Unknown,3,false,static_cast<std::int64_t>(Now())));
    RS2_CHECK(!f.recovery->requested && !f.recovery->terminal && nativeCalls==0);
    CaptureReservation ordinary{};
    ManagePump(f.runtime,CallerClass::Unknown,static_cast<std::int64_t>(Now()),ordinary);
    RS2_CHECK(StatusRevoked(f.status) && !ordinary.active);
    for(const auto caller : {CallerClass::Unknown,CallerClass::Truncated}) for(bool overall : {false,true}) {
        Fixture pending;pending.FinishPhase();pending.Reserve();auto& r=*pending.recovery;
        InterlockedExchange(&pending.runtime.task.phase,static_cast<LONG>(TaskPhase::Retired));
        const auto now=Now();r.value.finishDeadlineQpc=now-1;
        if(overall) r.value.overallDeadlineQpc=now-1;
        r.pendingRecords[0]=r.value;r.pendingRecords[0].event=static_cast<std::uint64_t>(RecoveryEvent::Transition);r.pendingCount=1;
        const bool truncated=caller==CallerClass::Truncated;
        const auto count=truncated ? kCaptureFrames : std::size_t{3};
        SetLastError(0x5678);
        RS2_CHECK(!ServiceLeechRecovery(pending.runtime,caller,count,truncated,static_cast<std::int64_t>(now)));
        RS2_CHECK(GetLastError()==0x5678);
        RS2_CHECK(r.terminal && r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Failed) &&
            r.value.reason==static_cast<std::uint64_t>(overall ? RecoveryReason::AttemptTimeout : RecoveryReason::FinishTimeout));
        RS2_CHECK((r.value.flags&(RecoveryTerminal|RecoveryRestartRequired))==(RecoveryTerminal|RecoveryRestartRequired));
        RS2_CHECK(pending.runtime.bindingSuspended && !pending.runtime.recoveryQuota.active && !pending.runtime.transport.reservedCredits);
        RS2_CHECK(!r.pendingCount && !r.finalPending && !r.createInstalled && !r.createForwarded &&
            pending.memoryReads==0 && pending.memoryQueries==0 && nativeCalls==0);
        const auto failed=pending.Scalar();
        RS2_CHECK(failed.wire.payload.phase==r.value.phase && failed.wire.payload.reason==r.value.reason && failed.wire.payload.flags==r.value.flags);
        RS2_CHECK(pending.runtime.counters.reportSequence==0 && pending.ring.reportWriteSequence==0 && pending.Records().empty());
        const auto transition=r.value.transitionSequence;
        RS2_CHECK(!ServiceLeechRecovery(pending.runtime,caller,count,truncated,static_cast<std::int64_t>(now)));
        RS2_CHECK(r.value.transitionSequence==transition && !pending.runtime.transport.reservedCredits &&
            pending.runtime.counters.reportSequence==0 && pending.ring.reportWriteSequence==0 && nativeCalls==0);
        CaptureReservation fallthrough{};
        ManagePump(pending.runtime,caller,static_cast<std::int64_t>(now),fallthrough);
        RS2_CHECK(StatusRevoked(pending.status) && !fallthrough.active && pending.runtime.bindingSuspended &&
            !pending.runtime.recoveryQuota.active && !pending.runtime.transport.reservedCredits);
    }
    Fixture foreign;foreign.FinishPhase();foreign.Reserve();foreign.recovery->foreignFault=1;
    RS2_CHECK(!ServiceLeechRecovery(foreign.runtime,CallerClass::Unknown,3,false,static_cast<std::int64_t>(Now())));
    RS2_CHECK(foreign.recovery->terminal && foreign.recovery->value.reason==static_cast<std::uint64_t>(RecoveryReason::CallbackInvalid));
    RS2_CHECK(!foreign.runtime.transport.reservedCredits && foreign.runtime.bindingSuspended && foreign.Records().empty() && nativeCalls==0);
}
void UnsupportedTerminalKeepsSuspension() {
    for(const auto caller : {CallerClass::Unknown,CallerClass::Truncated}) {
        Fixture f;f.FinishPhase(RecoveryPhase::Recreating);f.Reserve();auto& r=*f.recovery;
        InterlockedExchange(&f.runtime.task.phase,static_cast<LONG>(TaskPhase::Retired));
        const auto now=static_cast<std::int64_t>(Now());
        const auto interval=f.runtime.producer.frequency/kManagementHz;
        f.runtime.haveManagement=true;f.runtime.lastManagement=now;
        r.value.overallDeadlineQpc=static_cast<std::uint64_t>(now)-1;
        const bool truncated=caller==CallerClass::Truncated;
        const auto count=truncated ? kCaptureFrames : std::size_t{3};
        RS2_CHECK(!ServiceLeechRecovery(f.runtime,caller,count,truncated,now));
        RS2_CHECK(r.terminal && r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Failed) &&
            r.value.reason==static_cast<std::uint64_t>(RecoveryReason::AttemptTimeout));
        RS2_CHECK((r.value.flags&(RecoveryTerminal|RecoveryRestartRequired))==(RecoveryTerminal|RecoveryRestartRequired));
        // AfterPump defers management while the preceding management visit is
        // this recent. Terminal publication does not imply same-visit revocation.
        RS2_CHECK(interval>0 && f.runtime.haveManagement && now-f.runtime.lastManagement<interval);
        RS2_CHECK(!StatusRevoked(f.status) && RuntimeCaptureAdmission(f.runtime) && !RecoveryServiceDue(f.runtime));
        RS2_CHECK(f.runtime.bindingSuspended && !f.runtime.recoveryQuota.active && !f.runtime.transport.reservedCredits);
        const auto failed=f.Scalar();
        RS2_CHECK(failed.wire.payload.phase==r.value.phase && failed.wire.payload.reason==r.value.reason &&
            failed.wire.payload.flags==r.value.flags);
        // The next due visit can have normal ancestry. It still cannot rebind,
        // reserve credits or read a potentially newly selected heartbeat.
        CaptureReservation ordinary{};
        ManagePump(f.runtime,CallerClass::NormalPump,now+interval,ordinary);
        RS2_CHECK(!ordinary.active && !StatusRevoked(f.status) && f.runtime.bindingSuspended &&
            ReadTaskPhase(f.runtime.task)==TaskPhase::Retired && f.runtime.sourceReady);
        RS2_CHECK(f.runtime.lastManagement==now && f.runtime.counters.managementCalls==0 &&
            f.memoryReads==0 && f.memoryQueries==0 && nativeCalls==0);
        // A qualified logger also cannot lift an existing transport pause.
        f.runtime.transport.state=static_cast<std::uint64_t>(TransportState::Paused);
        const auto transportTransition=f.runtime.transport.transitionSequence;
        const NativeServiceResult qualified{TransportReason::None,true,0};
        RefreshRuntimeTransport(f.runtime,qualified,now+interval);
        RS2_CHECK(f.runtime.transport.state==static_cast<std::uint64_t>(TransportState::Paused) &&
            f.runtime.transport.transitionSequence==transportTransition && !StatusRevoked(f.status));
        RS2_CHECK(f.runtime.bindingSuspended && !f.runtime.transport.reservedCredits &&
            f.memoryReads==0 && f.memoryQueries==0 && nativeCalls==0);
        // With capture admission restored, unsupported management must revoke
        // even though irreversible recovery still holds the suspension.
        f.runtime.transport.state=static_cast<std::uint64_t>(TransportState::Running);
        ManagePump(f.runtime,caller,now+interval,ordinary);
        RS2_CHECK(StatusRevoked(f.status) && f.runtime.bindingSuspended && !ordinary.active &&
            f.runtime.counters.reason==static_cast<std::uint64_t>(truncated ? Reason::TruncatedStack : Reason::UnknownAncestry));
        const auto transition=r.value.transitionSequence;
        RS2_CHECK(!ServiceLeechRecovery(f.runtime,caller,count,truncated,now+interval));
        RS2_CHECK(r.value.transitionSequence==transition && f.runtime.bindingSuspended &&
            !f.runtime.recoveryQuota.active && !f.runtime.transport.reservedCredits);
        RS2_CHECK(f.runtime.counters.reportSequence==0 && f.ring.reportWriteSequence==0 && f.Records().empty() &&
            f.memoryReads==0 && f.memoryQueries==0 && nativeCalls==0);
    }
}
void TerminalQuotaAndEvidence() {
    for(bool sticky : {false,true}) {
        Fixture f;f.FinishPhase();f.Reserve();auto& r=*f.recovery;
        r.value.qpc=1; // Earlier native fault/last-valid-clock observation.
        r.terminal=true;r.finalPending=true;
        r.value.reason=static_cast<std::uint64_t>(RecoveryReason::RecordingUnavailable);
        r.value.outcome=static_cast<std::uint64_t>(RecoveryOutcome::RecordingUnavailable);
        r.value.flags|=RecoveryRestartRequired;
        f.runtime.transport.state=static_cast<std::uint64_t>(TransportState::Paused);
        if(sticky) LoseStatus(f.status,Reason::RecordLoss);
        FinishLeechTerminalForTest(f.runtime,r,Now());
        const auto records=f.Records();RS2_CHECK(records.size()==(sticky ? 0u : 2u));
        RS2_CHECK(!f.runtime.recoveryQuota.active && f.runtime.transport.reservedCredits==0 && f.runtime.bindingSuspended);
        std::uint64_t previous{};
        for(const auto& record : records) {
            const auto& p=record.payload.recovery;
            RS2_CHECK(record.header.kind==static_cast<std::uint32_t>(RecordKindV3::Recovery));
            RS2_CHECK(p.phase==static_cast<std::uint64_t>(RecoveryPhase::Failed) &&
                (p.flags&RecoveryRestartRequired) && (p.flags&RecoveryTerminal));
            RS2_CHECK(p.event==static_cast<std::uint64_t>(RecoveryEvent::Transition) || p.event==static_cast<std::uint64_t>(RecoveryEvent::Final));
            RS2_CHECK(p.qpc==1 && record.header.qpc>p.qpc && record.header.qpc>=previous && p.recordSequence==0);
            previous=record.header.qpc;
        }
        RS2_CHECK(!sticky || StatusRevoked(f.status));
        RS2_CHECK(sticky || !StatusRevoked(f.status));
        RecoveryStatusSnapshot scalar{};
        const RecoveryReadOps reader{&f.recoveryStatus,[](void* context,std::size_t offset,void* output,std::size_t bytes) noexcept {
            if(offset>sizeof(RecoveryStatusWireV1) || bytes>sizeof(RecoveryStatusWireV1)-offset) return false;
            std::memcpy(output,static_cast<const unsigned char*>(context)+offset,bytes);return true;
        }};
        RS2_CHECK(ReadRecoveryStatusSnapshot(reader,f.status.header,&scalar)==RecoverySnapshotResult::Coherent);
        RS2_CHECK(scalar.wire.payload.phase==static_cast<std::uint64_t>(RecoveryPhase::Failed) && scalar.wire.payload.qpc==1);
        const auto sequence=f.runtime.counters.reportSequence;
        FinishLeechTerminalForTest(f.runtime,r,Now());
        RS2_CHECK(f.runtime.counters.reportSequence==sequence && !f.runtime.transport.reservedCredits && f.Records().empty() && nativeCalls==0);
    }
    Fixture rejected;auto& r=*rejected.recovery;r.requested=true;r.terminal=true;r.finalPending=true;
    r.value.reason=static_cast<std::uint64_t>(RecoveryReason::SourceUnavailable);rejected.runtime.bindingSuspended=true;
    rejected.Reserve();
    FinishLeechTerminalForTest(rejected.runtime,r,Now());
    RS2_CHECK(r.value.phase==static_cast<std::uint64_t>(RecoveryPhase::Rejected) && !(r.value.flags&RecoveryRestartRequired));
    RS2_CHECK(!rejected.runtime.bindingSuspended && !rejected.runtime.transport.reservedCredits && nativeCalls==0);
}
} // namespace
void LeechRecoveryTests() {
    ConsoleReadSelectors();ConsoleRegistrationAndCommands();
#if defined(RS2_RECOVERY_GUARD_PROBE)
    NativeGuardReasons();ReadOnlyGuardProbe();
#else
    NativeGuardReasons();ActiveGuardReasonCompatibility();
    RequestAdmission();FinishCallbacks();DeadlinesAndUnknownInverse();UnsupportedServicePreservesManagement();UnsupportedTerminalKeepsSuspension();TerminalQuotaAndEvidence();
    IrreversibleSequenceSuccess();MetadataObservationWindow();MetadataRefusalsAndCleanup();PilotPopulationBounds();PreflightRetryAndNativeBoundary();RevokedPreflightDoesNotStarveCleanup();PublishedObservationFaults();SynchronousFinishError();ActualLifetimeChangesRefuse();
    IrreversibleOwnershipUnwind();InstanceGuardRefusals();GuardedCallbackRefusalAndUnwind();
#endif
}
} // namespace rs2fix::testcases
