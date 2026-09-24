#include "companion/steam_reporting_log.h"
#include "companion/steam_reporting_profile.h"
#include "test_framework.h"
#include <aclapi.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <initializer_list>
#include <string>

namespace rs2fix::testcases {
namespace {
using namespace reporting;
namespace obs=observer;
volatile LONG directoryNumber{};
std::string ReadText(const std::wstring& path) {
    const HANDLE file=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,
        nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    RS2_CHECK(file!=INVALID_HANDLE_VALUE);
    if (file==INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file,&size) || size.QuadPart<0 || size.QuadPart>2*1024*1024) {
        RS2_CHECK(false); CloseHandle(file); return {};
    }
    std::string text(static_cast<std::size_t>(size.QuadPart),'\0');
    DWORD read{};
    RS2_CHECK(text.empty() || (ReadFile(file,text.data(),static_cast<DWORD>(text.size()),&read,nullptr) &&
        read==text.size()));
    CloseHandle(file); return text;
}
bool PrivateAcl(const std::wstring& path) {
    PSECURITY_DESCRIPTOR descriptor{}; PACL acl{}; PSID owner{};
    const auto result=GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()),SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&descriptor);
    if (result!=ERROR_SUCCESS) return false;
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision{};
    const bool ok=owner && acl && acl->AceCount==3 &&
        GetSecurityDescriptorControl(descriptor,&control,&revision) && (control&SE_DACL_PROTECTED);
    LocalFree(descriptor); return ok;
}
bool Loss(const StatusWire& status,Reason reason) {
    const auto mask=std::uint64_t{1}<<static_cast<unsigned>(reason);
    return (ReadStatusWord(status.lossReasons)&mask)!=0 && (ReadStatusWord(status.revokeReasons)&mask)!=0;
}
ReportRecord Record(RecordKind kind=RecordKind::State) {
    ReportRecord record{};
    record.header.kind=static_cast<std::uint32_t>(kind);
    record.header.qpc=12345; record.header.sourceEpoch=3; record.header.bindingEpoch=8;
    record.payload.state.pi=65; record.payload.state.bots=24; record.payload.state.maximum=64;
    return record;
}
struct Fixture {
    StatusWire status{};
    ReportRing ring{};
    obs::DispatchState dispatch{};
    obs::Writer* writer{};
    wchar_t root[obs::kWriterPathCapacity]{};
    explicit Fixture(const obs::WriterTestOptions& options={},bool create=true,bool blockedKey=false) {
        wchar_t temporary[obs::kWriterPathCapacity]{};
        RS2_CHECK(GetTempPathW(_countof(temporary),temporary)!=0);
        const auto count=_snwprintf_s(root,_countof(root),_TRUNCATE,
            L"%sRS2SteamReport-Writer-Test-%lu-%llu-%ld",temporary,GetCurrentProcessId(),
            GetTickCount64(),InterlockedIncrement(&directoryNumber));
        RS2_CHECK(count>0 && CreateDirectoryW(root,nullptr));
        if (blockedKey) {
            const auto path=std::wstring(root)+L"\\RS2SteamObserveKeys";
            const HANDLE file=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,0,nullptr);
            DWORD written{}; const char marker[]="reporting never opens this legacy key path";
            RS2_CHECK(file!=INVALID_HANDLE_VALUE && WriteFile(file,marker,sizeof(marker),&written,nullptr));
            if (file!=INVALID_HANDLE_VALUE) CloseHandle(file);
        }
        FILETIME creation{},exit{},kernel{},user{}; LARGE_INTEGER frequency{};
        RS2_CHECK(GetProcessTimes(GetCurrentProcess(),&creation,&exit,&kernel,&user));
        RS2_CHECK(QueryPerformanceFrequency(&frequency) && frequency.QuadPart>0);
        StatusHeader header{};
        header.configuredMode=static_cast<unsigned>(Mode::Repair);
        header.validity=CompleteHeaderIdentity; header.pid=GetCurrentProcessId();
        header.processCreation=(static_cast<std::uint64_t>(creation.dwHighDateTime)<<32)|creation.dwLowDateTime;
        header.qpcFrequency=static_cast<std::uint64_t>(frequency.QuadPart);
        for (unsigned i=0;i<16;++i) header.runId[i]=static_cast<std::uint8_t>(i);
        std::memcpy(header.hostDigest,ProductionReportingIdentities().hostDigest.data(),sizeof(header.hostDigest));
        RS2_CHECK(InitializeStatus(status,header,{}));
        RS2_CHECK(InitializeReportRing(ring,status,GetCurrentThreadId()));
        obs::InitializeDispatch(dispatch,{},{});
        if (create) Prepare(options);
    }
    void Prepare(const obs::WriterTestOptions& options={}) {
        Reason reason{}; DWORD error{};
        writer=PrepareReportingWriterForTest(root,status,ring,dispatch,options,&reason,&error);
        RS2_CHECK(writer && reason==Reason::None && error==ERROR_SUCCESS);
    }
    void Arm() {
        InterlockedExchange(&dispatch.gate,static_cast<LONG>(obs::Gate::Armed));
        ArmReportingWriter(writer);
    }
    void Send(const ReportRecord& record) {
        const auto sink=GetReportingWriterSink(writer); std::uint64_t sequence{};
        RS2_CHECK(sink.publish && sink.publish(sink.context,record,&sequence) && sequence!=0);
    }
    std::wstring Events() const { return std::wstring(obs::GetWriterDirectory(writer))+L"\\events.jsonl"; }
    ~Fixture() { obs::FinishWriterForTest(writer); }
};
void IdentityPrivacyAndKinds() {
    Fixture f({},true,true);
    if (!f.writer) return;
    RS2_CHECK(ReadText(f.Events()).empty());
    obs::PumpWriterForTest(f.writer);
    RS2_CHECK(ReadText(f.Events()).empty());
    RS2_CHECK(!obs::GetWriterSink(f.writer).publish && !f.dispatch.sink.publish);
    const std::wstring directory=obs::GetWriterDirectory(f.writer);
    RS2_CHECK(directory.find(L"\\RS2SteamReport\\")!=std::wstring::npos);
    RS2_CHECK(directory.substr(directory.size()-32)==L"000102030405060708090a0b0c0d0e0f");
    RS2_CHECK(GetFileAttributesW((std::wstring(f.root)+L"\\RS2SteamObserve").c_str())==INVALID_FILE_ATTRIBUTES);
    RS2_CHECK(ReadText(std::wstring(f.root)+L"\\RS2SteamObserveKeys").find("never opens")!=std::string::npos);
    RS2_CHECK(PrivateAcl(f.Events()) && PrivateAcl(directory));
    const HANDLE write=CreateFileW(f.Events().c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
        nullptr,OPEN_EXISTING,0,nullptr);
    RS2_CHECK(write==INVALID_HANDLE_VALUE && GetLastError()==ERROR_SHARING_VIOLATION);
    if (write!=INVALID_HANDLE_VALUE) CloseHandle(write);
    f.Arm();
    auto state=Record(); state.payload.state.clientQualificationMs=237;
    state.payload.state.nativeTaskState=3; state.payload.state.nativeScheduleValid=1;
    state.payload.state.nativeScheduleAnchorBits=0x8000000000000000ULL;
    state.payload.state.nativeErrorsBits=0x80000000ULL; state.payload.state.nativeThrottlesBits=UINT32_MAX;
    state.payload.state.nativeExpedite=255; state.payload.state.nativeRetryLimit=3;
    state.payload.state.nativeIntervalUnits=30000;
    state.payload.state.nativeIntervalOverrideBits=UINT64_MAX;
    state.payload.state.nativeRetryOverrideBits=0x8000000000000000ULL;
    // Stable raw unsupported values stay observable, but no nominal tier/due
    // result is invented from their sign bits.
    state.payload.state.nativeDelayUnits=0; state.payload.state.nativeTier=0;
    for (auto& word:state.payload.state.reserved) word=UINT64_MAX;
    f.Send(state);
    auto unavailable=state; unavailable.payload.state.nativeScheduleValid=0;
    unavailable.payload.state.nativeTaskState=2;
    f.Send(unavailable); // Prior raw scalars must be cleared in emitted evidence.
    for (const auto kind:{RecordKind::Request,RecordKind::Witness}) {
        auto record=Record(kind); record.payload.request={};
        record.payload.request.requestSequence=9; record.payload.request.witnessSequence=7;
        record.payload.request.worldBots=24; record.payload.request.freshSinceQpc=456;
        f.Send(record);
    }
    for (const auto kind:{RecordKind::BuilderEnter,RecordKind::BuilderReturn,RecordKind::BuilderUnwind}) {
        auto record=Record(kind); record.payload.builder={};
        record.payload.builder.buildSequence=10; record.payload.builder.probeElapsedTicks=100;
        record.payload.builder.classificationElapsedTicks=25; record.payload.builder.originalElapsedTicks=200;
        f.Send(record);
    }
    auto anchor=Record(RecordKind::Anchor); anchor.payload.anchor={};
    anchor.payload.anchor.normalAttempts=17; anchor.payload.anchor.selectedTrue=9;
    anchor.payload.anchor.durations[3]={19,UINT64_MAX,UINT64_MAX,3};
    f.Send(anchor);
    StatusPayload changed{}; changed.normalAttempts=7654321;
    RS2_CHECK(PublishStatus(f.status,changed));
    obs::PumpWriterForTest(f.writer);
    const auto text=ReadText(f.Events());
    RS2_CHECK(text.find("\"schema\":2")!=std::string::npos && text.find("\"version\":\"0.4.2.0\"")!=std::string::npos);
    RS2_CHECK(text.find("\"run_id\":\"000102030405060708090a0b0c0d0e0f\"")!=std::string::npos);
    RS2_CHECK(text.find("\"mode\":\"repair\"")!=std::string::npos && text.find("\"qualified_steam_api_sha256\":")!=std::string::npos);
    for (const auto type:{"state","request","witness","builder-enter","builder-return","builder-unwind","anchor"})
        RS2_CHECK(text.find(std::string("\"type\":\"")+type+"\"")!=std::string::npos);
    RS2_CHECK(text.find("\"normal_attempts\":17")!=std::string::npos && text.find("7654321")==std::string::npos);
    RS2_CHECK(text.find("\"probe_elapsed_ticks\":100")!=std::string::npos &&
        text.find("\"classification_elapsed_ticks\":25")!=std::string::npos);
    RS2_CHECK(text.find("\"client_qualification_ms\":237")!=std::string::npos);
    RS2_CHECK(text.find("\"native_task_state\":3")!=std::string::npos);
    RS2_CHECK(text.find("\"native_schedule_valid\":1,\"native_schedule_anchor_bits\":9223372036854775808")!=std::string::npos);
    RS2_CHECK(text.find("\"native_errors_bits\":2147483648,\"native_throttles_bits\":4294967295")!=std::string::npos);
    RS2_CHECK(text.find("\"native_expedite\":255,\"native_retry_limit\":3,\"native_interval_units\":30000")!=std::string::npos);
    RS2_CHECK(text.find("\"native_interval_override_bits\":18446744073709551615,\"native_retry_override_bits\":9223372036854775808")!=std::string::npos);
    RS2_CHECK(text.find("\"native_delay_units\":0,\"native_tier\":0")!=std::string::npos);
    RS2_CHECK(text.find("\"native_task_state\":2")!=std::string::npos);
    RS2_CHECK(text.find("\"native_schedule_valid\":0,\"native_schedule_anchor_bits\":0,"
        "\"native_errors_bits\":0,\"native_throttles_bits\":0,\"native_expedite\":0,"
        "\"native_retry_limit\":0,\"native_interval_units\":0,\"native_interval_override_bits\":0,"
        "\"native_retry_override_bits\":0,\"native_delay_units\":0,\"native_tier\":0")!=std::string::npos);
    RS2_CHECK(text.find("native_due")==std::string::npos && text.find("next_eligibility")==std::string::npos);
    RS2_CHECK(text.find("18446744073709551615")!=std::string::npos);
    RS2_CHECK(text.find("steam_token")==std::string::npos && text.find(".key")==std::string::npos &&
        text.find("caller_rva")==std::string::npos && text.find("reserved")==std::string::npos);
    RS2_CHECK(ReadStatusWord(f.status.recordsWritten)==8 && ReadStatusWord(f.status.lossReasons)==0);
    StopReportingWriter(f.writer); obs::PumpWriterForTest(f.writer);
    RS2_CHECK(ReadStatusWord(f.status.lastFlushedSequence)==8 && ReadStatusWord(f.status.lossReasons)==0);
    RS2_CHECK(obs::SnapshotWriter(f.writer).status==obs::WriterStatus::Stopped);
    RS2_CHECK(ReadText(f.Events()).find("\"complete\":true")==std::string::npos);
}
struct Fault {
    enum class Kind { None,Partial,Disk,BadCount } kind{};
    unsigned calls{};
    unsigned failCall{3};
    bool failFlush{};
    unsigned flushes{};
};
bool FaultWrite(void* context,HANDLE file,const void* data,DWORD length,DWORD* written,DWORD* error) noexcept {
    auto& fault=*static_cast<Fault*>(context); ++fault.calls;
    if (fault.calls==fault.failCall) {
        if (fault.kind==Fault::Kind::Disk) { *written=0; *error=ERROR_DISK_FULL; return false; }
        if (fault.kind==Fault::Kind::BadCount) { *written=length+1; *error=0; return true; }
        if (fault.kind==Fault::Kind::Partial) length=8;
    }
    const bool ok=WriteFile(file,data,length,written,nullptr)!=FALSE;
    *error=ok ? 0 : GetLastError(); return ok;
}
bool FaultFlush(void* context,HANDLE file,DWORD* error) noexcept {
    auto& fault=*static_cast<Fault*>(context); ++fault.flushes;
    if (fault.failFlush) { *error=ERROR_WRITE_FAULT; return false; }
    const bool ok=FlushFileBuffers(file)!=FALSE; *error=ok ? 0 : GetLastError(); return ok;
}
void WriteAndFlushFaults() {
    for (const auto kind:{Fault::Kind::Partial,Fault::Kind::Disk,Fault::Kind::BadCount}) {
        Fault fault{}; fault.kind=kind;
        Fixture f({0,&fault,FaultWrite,FaultFlush}); if (!f.writer) continue;
        f.Arm(); f.Send(Record()); f.Send(Record()); f.Send(Record());
        obs::PumpWriterForTest(f.writer);
        RS2_CHECK(Loss(f.status,Reason::WriterFailed));
        RS2_CHECK(ReadStatusWord(f.status.recordsWritten)==1 && ReadStatusWord(f.status.lastFlushedSequence)==0);
        RS2_CHECK(obs::SnapshotWriter(f.writer).status==obs::WriterStatus::Failed);
        const auto text=ReadText(f.Events());
        RS2_CHECK(text.find("\"sequence\":1,")!=std::string::npos && text.find("\"sequence\":2,")==std::string::npos);
        if (kind==Fault::Kind::Partial) RS2_CHECK(!text.empty() && text.back()!='\n');
        const auto calls=fault.calls;
        obs::PumpWriterForTest(f.writer); StopReportingWriter(f.writer); obs::PumpWriterForTest(f.writer);
        RS2_CHECK(fault.calls==calls && ReadText(f.Events())==text && Loss(f.status,Reason::WriterFailed));
    }
    Fault fault{}; fault.failFlush=true;
    Fixture f({0,&fault,FaultWrite,FaultFlush}); if (!f.writer) return;
    f.Arm(); f.Send(Record()); obs::PumpWriterForTest(f.writer);
    StopReportingWriter(f.writer); obs::PumpWriterForTest(f.writer);
    RS2_CHECK(fault.flushes==1 && Loss(f.status,Reason::WriterFailed));
    RS2_CHECK(ReadStatusWord(f.status.stopping)==1 && ReadStatusWord(f.status.recordsWritten)==1 &&
        ReadStatusWord(f.status.lastFlushedSequence)==0);
}
void QuotaBatchesAndStop() {
    {
        Fixture f; if (!f.writer) return;
        f.Arm();
        for (unsigned i=0;i<70;++i) f.Send(Record());
        obs::PumpWriterForTest(f.writer);
        RS2_CHECK(ReadStatusWord(f.status.recordsWritten)==32 && obs::SnapshotWriter(f.writer).queueDepth==38);
        StopReportingWriter(f.writer);
        std::uint64_t accepted=99;
        RS2_CHECK(EnqueueReport(f.ring,Record(),&accepted)==ReportWriteResult::Stopping && accepted==0);
        obs::PumpWriterForTest(f.writer); obs::PumpWriterForTest(f.writer);
        RS2_CHECK(ReadStatusWord(f.status.recordsWritten)==70 && ReadStatusWord(f.status.lastFlushedSequence)==70);
        RS2_CHECK(ReadStatusWord(f.status.lossReasons)==0 && obs::SnapshotWriter(f.writer).status==obs::WriterStatus::Stopped);
    }
    {
        Fixture f({16*1024,nullptr,nullptr,nullptr}); if (!f.writer) return;
        f.Arm(); for (unsigned i=0;i<100;++i) f.Send(Record());
        for (unsigned i=0;i<4;++i) obs::PumpWriterForTest(f.writer);
        RS2_CHECK(Loss(f.status,Reason::LogLimit));
        const auto snapshot=obs::SnapshotWriter(f.writer);
        RS2_CHECK(snapshot.status==obs::WriterStatus::Truncated && snapshot.bytesWritten<=16*1024);
        const auto text=ReadText(f.Events());
        RS2_CHECK(!text.empty() && text.back()=='\n' && text.size()==snapshot.bytesWritten);
        RS2_CHECK(text.find("\"complete\":true")==std::string::npos);
    }
}
void RejectIdentityAndSequenceGap() {
    {
        Fixture f({},false);
        // Immutable construction is deliberately invalidated only in this owned,
        // unpublished fixture; production never changes a published header.
        std::memset(f.status.header.runId,0,sizeof(f.status.header.runId));
        Reason reason{}; DWORD error{};
        auto* rejected=PrepareReportingWriterForTest(f.root,f.status,f.ring,f.dispatch,{},&reason,&error);
        RS2_CHECK(!rejected && reason==Reason::IdentityIncomplete && error!=0);
        RS2_CHECK(GetFileAttributesW((std::wstring(f.root)+L"\\RS2SteamReport").c_str())==INVALID_FILE_ATTRIBUTES);
    }
    {
        Fixture f; if (!f.writer) return;
        f.Arm(); f.Send(Record()); obs::PumpWriterForTest(f.writer);
        // Model an impossible dropped sequence between the ring's two valid
        // monotonic positions, not malformed JSON or a fabricated replacement.
        StoreStatusWord(f.ring.reportWriteSequence,2); StoreStatusWord(f.ring.reportReadSequence,2);
        f.Send(Record()); obs::PumpWriterForTest(f.writer);
        RS2_CHECK(Loss(f.status,Reason::RecordLoss) && ReadStatusWord(f.status.recordsWritten)==1);
        RS2_CHECK(ReadText(f.Events()).find("\"sequence\":3,")==std::string::npos);
    }
}
} // namespace
void ReportingLogTests() {
    IdentityPrivacyAndKinds(); WriteAndFlushFaults(); QuotaBatchesAndStop(); RejectIdentityAndSequenceGap();
}
} // namespace rs2fix::testcases
