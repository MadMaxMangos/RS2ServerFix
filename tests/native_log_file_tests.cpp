#include "companion/steam_reporting_log_file.h"
#include "companion/steam_reporting_worker.h"
#include "companion/steam_reporting_hash.h"
#include "companion/steam_reporting_transport.h"
#include "companion/leech_recovery_wire.h"
#include "test_framework.h"
#include <string>
#include <cstring>
#include <cwchar>
#include <memory>

namespace rs2fix::testcases {
namespace {
using namespace reporting;
const std::uint16_t* Units(const std::wstring& path) {
    static_assert(sizeof(wchar_t)==sizeof(std::uint16_t));
    return reinterpret_cast<const std::uint16_t*>(path.c_str());
}
struct Fixture {
    std::wstring directory,path,moved;
    HANDLE writer=INVALID_HANDLE_VALUE;
    NativeLogFile reader{};
    Fixture() {
        wchar_t temp[MAX_PATH]{},unique[MAX_PATH]{};
        RS2_CHECK(GetTempPathW(MAX_PATH,temp)!=0);
        RS2_CHECK(GetTempFileNameW(temp,L"RNL",0,unique)!=0);
        RS2_CHECK(DeleteFileW(unique)!=FALSE);
        directory=unique;
        RS2_CHECK(CreateDirectoryW(directory.c_str(),nullptr)!=FALSE);
        path=directory+L"\\Launch.log"; moved=directory+L"\\Archived.log";
        writer=CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,
            CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
        RS2_CHECK(writer!=INVALID_HANDLE_VALUE);
    }
    ~Fixture() {
        CloseNativeLogFile(reader);
        if (writer!=INVALID_HANDLE_VALUE) CloseHandle(writer);
        DeleteFileW(path.c_str()); DeleteFileW(moved.c_str()); RemoveDirectoryW(directory.c_str());
    }
    void Write(const char* text) {
        DWORD count{},size=static_cast<DWORD>(std::strlen(text));
        RS2_CHECK(WriteFile(writer,text,size,&count,nullptr) && count==size);
        RS2_CHECK(FlushFileBuffers(writer));
    }
    TransportReason Open() { return OpenNativeLogFile(reader,Units(path),path.size()); }
};
void Syntax() {
    wchar_t out[kNativeLogPathChars]{};
    for (const std::wstring good : {L"E:\\Launch.log",L"E:\\Server_Logs\\Server1Voting\\Launch\\Launch.log",
        L"c:\\a b\\x'.log",L"D:\\\u4e2d\u6587\\Launch.log"}) {
        RS2_CHECK(NativeLogPathSyntax(Units(good),good.size(),out));
        RS2_CHECK(good==out);
    }
    for (const std::wstring bad : {L"relative.log",L"E:Launch.log",L"E:\\",L"\\\\server\\share\\file",
        L"\\\\?\\E:\\file",L"E:/a.log",L"E:\\a\\..\\file",L"E:\\a\\.\\file",L"E:\\a.\\file",
        L"E:\\a \\file",L"E:\\a\\\\file",L"E:\\a:stream",L"E:\\NUL.txt",L"E:\\CONIN$",
        L"E:\\com1.log",L"E:\\LPT\u00B2\\file",L"E:\\a\\file*",L"E:\\a\tb\\file"}) {
        RS2_CHECK(!NativeLogPathSyntax(Units(bad),bad.size(),out) && out[0]==0);
    }
    std::wstring nul=L"E:\\foo"; nul.push_back(0); nul+=L"bar";
    RS2_CHECK(!NativeLogPathSyntax(Units(nul),nul.size(),out));
}
void GrowthAndTruncation() {
    Fixture f;
    f.Write("existing\n");
    RS2_CHECK(f.Open()==TransportReason::None);
    RS2_CHECK(f.reader.initialEOF==9 && f.reader.initialAtLineBoundary && f.reader.identity.valid);
    const auto identity=f.reader.identity;
    char bytes[64]{}; DWORD got=99;
    RS2_CHECK(ReadNativeLogFile(f.reader,9,bytes,sizeof(bytes),&got)==TransportReason::None && got==0);
    f.Write("new\r\n");
    RS2_CHECK(ReadNativeLogFile(f.reader,9,bytes,sizeof(bytes),&got)==TransportReason::None && got==5);
    RS2_CHECK(std::memcmp(bytes,"new\r\n",5)==0);
    RS2_CHECK(RequalifyNativeLogFile(f.reader,Units(f.path),f.path.size())==TransportReason::None);
    RS2_CHECK(f.reader.initialEOF==9 && SameFileIdentity128(identity,f.reader.identity));
    RS2_CHECK(OpenNativeLogFile(f.reader,Units(f.path),f.path.size())==TransportReason::ReceiptUnavailable);
    // The writer can still append with the reader present; our access is read-only.
    DWORD written{};
    RS2_CHECK(!WriteFile(f.reader.handle,"x",1,&written,nullptr));
    LARGE_INTEGER at{}; at.QuadPart=1;
    RS2_CHECK(SetFilePointerEx(f.writer,at,nullptr,FILE_BEGIN));
    RS2_CHECK(SetEndOfFile(f.writer));
    RS2_CHECK(FlushFileBuffers(f.writer));
    std::uint64_t size{};
    RS2_CHECK(CheckNativeLogFile(f.reader,&size)==TransportReason::FileTruncated && size==0);
}
void BoundaryAndReplacement() {
    Fixture f; f.Write("partial");
    RS2_CHECK(f.Open()==TransportReason::None);
    RS2_CHECK(f.reader.initialEOF==7 && !f.reader.initialAtLineBoundary);
    CloseHandle(f.writer); f.writer=INVALID_HANDLE_VALUE;
    // Native writer is closed. Receipt sharing must not prevent normal archival.
    RS2_CHECK(MoveFileW(f.path.c_str(),f.moved.c_str()));
    f.writer=CreateFileW(f.path.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,
        CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    RS2_CHECK(f.writer!=INVALID_HANDLE_VALUE);
    f.Write("replacement\n");
    RS2_CHECK(RequalifyNativeLogFile(f.reader,Units(f.path),f.path.size())==TransportReason::FileIdentityChanged);
    RS2_CHECK(f.reader.initialEOF==7); // Never adopt the replacement baseline.
    CloseNativeLogFile(f.reader);
    RS2_CHECK(f.Open()==TransportReason::ReceiptUnavailable); // No generation reset.
}
void MissingAndEmpty() {
    Fixture f;
    NativeLogFile missing{}; const auto absent=f.directory+L"\\absent.log";
    RS2_CHECK(OpenNativeLogFile(missing,Units(absent),absent.size())==TransportReason::ReceiptUnavailable);
    RS2_CHECK(GetFileAttributesW(absent.c_str())==INVALID_FILE_ATTRIBUTES);
    RS2_CHECK(f.Open()==TransportReason::None && f.reader.initialEOF==0 && f.reader.initialAtLineBoundary);
    DWORD got{};
    RS2_CHECK(ReadNativeLogFile(f.reader,1,nullptr,0,&got)==TransportReason::FileTruncated);
}

struct WorkerFixture:Fixture {
    StatusWireV3 status{};
    ReportRingV3 ring{};
    NativeReceiptWorker worker{};
    PreparedNativeHash hash{};
    NativeFormatContext context{};
    OwnerSnapshotV3 owner{};
    std::uint64_t tick=1000;
    bool failClock{};
    static bool Clock(void* ptr,std::uint64_t* out) noexcept {
        auto& f=*static_cast<WorkerFixture*>(ptr);
        if (f.failClock) return false;
        *out=++f.tick; return true;
    }
    explicit WorkerFixture(const char* initial="") {
        if (*initial) Write(initial);
        StatusHeader header{}; header.configuredMode=3; header.pid=100;
        header.processCreation=100; header.qpcFrequency=1000;
        header.validity=CompleteHeaderIdentity; header.runId[0]=0xaa;
        StatusPayload payload{}; payload.ownerThreadId=GetCurrentThreadId();
        RS2_CHECK(InitializeStatusV3(status,header,payload));
        RS2_CHECK(InitializeReportRing(ring,status,GetCurrentThreadId()));
        context.header=status.header; context.config={Mode::Repair,Diagnostics::Normal};
        context.log.utcFiletime=134100000000000000;
        context.log.calibrationQpcBefore=100; context.log.calibrationQpcAfter=102;
        RS2_CHECK(PrepareNativeHash(hash));
        RS2_CHECK(InitializeNativeReceiptWorker(worker,status,ring,context,NativeHashOperations(hash),
            {this,Clock}));
        const auto length=std::strlen(initial);
        const bool boundary=!length || initial[length-1]=='\n';
        RS2_CHECK(QualifyNativeReceiptFile(worker,Units(path),path.size(),0,1)==
            (boundary ? TransportReason::None : TransportReason::AwaitingLogger));
        RS2_CHECK(ReadOwnerV3(status,&owner));
        RS2_CHECK(ReadStatusWord(status.logIdentityReady)==(boundary ? 1U : 0U));
        if (boundary) RS2_CHECK(status.log.initialEOF==length);
    }
    ~WorkerFixture() { CloseNativeReceipts(worker); CloseNativeHash(hash); }
    std::string Front() {
        const auto* front=PeekNativeFrame(worker.pipeline);
        RS2_CHECK(front!=nullptr);
        if (!front) return {};
        std::string text="Log: ";
        for (std::size_t i=0;i<front->chars;++i) text.push_back(static_cast<char>(front->message[i]));
        return text+"\r\n";
    }
    void Returned() {
        const auto* front=PeekNativeFrame(worker.pipeline);
        RS2_CHECK(front!=nullptr);
        if (!front) return;
        if (front->sequence) owner.transport.submittedSequence=front->sequence;
        else owner.transport.startupSubmitted=1;
        RS2_CHECK(ReleaseNativeFrame(worker.pipeline,front->ticket));
        RS2_CHECK(PublishOwnerV3(status,owner.owner,owner.transport));
        RS2_CHECK(ReadOwnerV3(status,&owner));
    }
    void Step() { tick+=250; CycleNativeReceipts(worker); }
    void Enqueue() {
        ReportRecordV3 event{}; event.header.kind=1; event.header.qpc=tick;
        std::uint64_t sequence{};
        RS2_CHECK(EnqueueReport(ring,event,&sequence)==ReportWriteResult::Accepted);
        owner.owner.reportSequence=sequence; owner.transport.generatedSequence=sequence;
        RS2_CHECK(PublishOwnerV3(status,owner.owner,owner.transport));
        RS2_CHECK(ReadOwnerV3(status,&owner));
    }
};
void WorkerReceiptOrdering() {
    auto f=std::make_unique<WorkerFixture>();
    const auto bootstrap=f->Front();
    f->Write(bootstrap.c_str());
    f->Step();
    RS2_CHECK(!StatusRevoked(f->status));
    RS2_CHECK(f->worker.scanner.awaitingSubmission && f->worker.pipeline.heldMatch);
    RS2_CHECK(!f->status.worker.startupObserved && f->status.worker.observedSequence==0);
    const auto matchedAt=f->worker.scanner.offset;
    f->Returned(); f->Step();
    RS2_CHECK(f->status.worker.startupObserved==1 && !f->worker.pipeline.heldMatch);
    RS2_CHECK(f->worker.scanner.offset==matchedAt);
    f->Enqueue(); f->Step();
    const auto frame=f->Front();
    f->Write(frame.substr(0,frame.size()/2).c_str()); f->Returned(); f->Step();
    RS2_CHECK(!f->status.worker.observedSequence && f->worker.scanner.carry>0 && !StatusRevoked(f->status));
    f->Write(frame.substr(frame.size()/2).c_str()); f->Step();
    RS2_CHECK(f->status.worker.observedSequence==1 && !f->worker.scanner.carry);
    const auto cursor=f->worker.scanner.offset;
    RS2_CHECK(QualifyNativeReceiptFile(f->worker,Units(f->path),f->path.size(),0,2)==TransportReason::None);
    RS2_CHECK(f->worker.qualifiedEpoch==2 && f->worker.scanner.offset==cursor && f->status.log.initialEOF==0);
    const auto cycles=f->status.worker.readCycles;
    CycleNativeReceipts(f->worker); // Too early: must not spin EOF or exceed4Hz.
    RS2_CHECK(f->status.worker.readCycles==cycles);
}
void WorkerBudgetAndLateReceipt() {
    auto f=std::make_unique<WorkerFixture>();
    const auto bootstrap=f->Front();
    f->Write((std::string(600*1024,'x')+"\n").c_str());
    f->Write(bootstrap.c_str()); f->Returned();
    f->Step();
    RS2_CHECK(f->status.worker.readBytes==kNativeReadCycleBytes);
    RS2_CHECK(f->status.workerPauseReason==static_cast<std::uint64_t>(TransportReason::ReaderBehind));
    RS2_CHECK(!f->status.worker.startupObserved && !StatusRevoked(f->status));
    f->Step();
    RS2_CHECK(f->status.worker.readBytes==2ULL*kNativeReadCycleBytes);
    f->Step();
    RS2_CHECK(f->status.worker.startupObserved && !f->status.workerPauseReason && !StatusRevoked(f->status));

    auto late=std::make_unique<WorkerFixture>();
    const auto pending=late->Front(); late->Returned();
    late->tick+=31000; late->Step();
    RS2_CHECK(late->status.workerPauseReason==0 && !StatusRevoked(late->status));
    late->tick+=31000; late->Step();
    RS2_CHECK(late->status.workerPauseReason==static_cast<std::uint64_t>(TransportReason::ReceiptOverdue));
    RS2_CHECK(!StatusRevoked(late->status));
    late->Write(pending.c_str()); late->Step();
    RS2_CHECK(late->status.worker.startupObserved && !late->status.workerPauseReason && !StatusRevoked(late->status));
}
void WorkerFaultsAndStop() {
    auto f=std::make_unique<WorkerFixture>();
    f->Write(f->Front().c_str()); f->Returned(); f->Step();
    LARGE_INTEGER at{}; RS2_CHECK(SetFilePointerEx(f->writer,at,nullptr,FILE_BEGIN));
    RS2_CHECK(SetEndOfFile(f->writer)); RS2_CHECK(FlushFileBuffers(f->writer));
    f->Step();
    RS2_CHECK(f->status.fatalTransportReason==static_cast<std::uint64_t>(TransportReason::FileTruncated));
    RS2_CHECK(StatusRevoked(f->status) && f->status.lossReasons!=0);

    auto stopped=std::make_unique<WorkerFixture>();
    stopped->Write(stopped->Front().c_str()); stopped->Returned();
    StopStatus(stopped->status,stopped->tick);
    stopped->Step(); // Already submitted tail can be verified without new output.
    RS2_CHECK(stopped->status.worker.startupObserved && stopped->status.stopping);
    CloseNativeReceipts(stopped->worker);
    RS2_CHECK(!stopped->worker.file.handle && stopped->status.logIdentityReady==1);

    auto clock=std::make_unique<WorkerFixture>();
    clock->failClock=true; clock->Step();
    RS2_CHECK(StatusRevoked(clock->status) && clock->worker.clockFailed);
}
void WorkerInitialPartialLine() {
    auto f=std::make_unique<WorkerFixture>("unfinished");
    const auto initial=f->worker.file.initialEOF;
    RS2_CHECK(initial==10 && !f->worker.qualifiedEpoch && !ReadStatusWord(f->status.logIdentityReady));
    RS2_CHECK(!PeekNativeFrame(f->worker.pipeline) && !StatusRevoked(f->status));
    f->tick+=31000;
    RS2_CHECK(QualifyNativeReceiptFile(f->worker,Units(f->path),f->path.size(),0,1)==TransportReason::AwaitingLogger);
    RS2_CHECK(!f->status.worker.startupObserved && !StatusRevoked(f->status));
    const auto before=f->worker.counters.readBytes;
    f->Write((std::string(300*1024,'x')+"\r\n").c_str());
    f->tick+=250;
    RS2_CHECK(QualifyNativeReceiptFile(f->worker,Units(f->path),f->path.size(),0,1)==TransportReason::AwaitingLogger);
    RS2_CHECK(f->worker.counters.readBytes-before==kNativeReadCycleBytes);
    RS2_CHECK(!PeekNativeFrame(f->worker.pipeline));
    f->tick+=250;
    RS2_CHECK(QualifyNativeReceiptFile(f->worker,Units(f->path),f->path.size(),0,1)==TransportReason::None);
    RS2_CHECK(f->status.log.initialEOF==initial && f->status.log.initialAtLineBoundary==0);
    const auto cursor=f->worker.scanner.offset;
    RS2_CHECK(cursor>initial && !f->worker.scanner.skipInitialSuffix);
    f->Write(f->Front().c_str()); f->Returned(); f->Step();
    RS2_CHECK(f->status.worker.startupObserved && f->worker.scanner.offset>cursor && !StatusRevoked(f->status));
}
void WorkerUnpublishedFileChange() {
    for(bool replace:{false,true}) {
        auto f=std::make_unique<WorkerFixture>("unfinished");
        RS2_CHECK(!f->status.logIdentityReady && !PeekNativeFrame(f->worker.pipeline));
        if(replace) {
            CloseHandle(f->writer); f->writer=INVALID_HANDLE_VALUE;
            RS2_CHECK(MoveFileW(f->path.c_str(),f->moved.c_str()));
            f->writer=CreateFileW(f->path.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,
                CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
            RS2_CHECK(f->writer!=INVALID_HANDLE_VALUE);
        } else {
            LARGE_INTEGER at{}; RS2_CHECK(SetFilePointerEx(f->writer,at,nullptr,FILE_BEGIN));
            RS2_CHECK(SetEndOfFile(f->writer) && FlushFileBuffers(f->writer));
        }
        f->tick+=250;
        RS2_CHECK(QualifyNativeReceiptFile(f->worker,Units(f->path),f->path.size(),0,1)==TransportReason::ReceiptUnavailable);
        RS2_CHECK(!f->worker.file.handle && !StatusRevoked(f->status) && !f->status.lossReasons && !f->status.logIdentityReady);
        RS2_CHECK(!PeekNativeFrame(f->worker.pipeline));
        f->Write("new candidate\n"); f->tick+=250;
        RS2_CHECK(QualifyNativeReceiptFile(f->worker,Units(f->path),f->path.size(),0,1)==TransportReason::None);
        RS2_CHECK(f->status.log.initialEOF==14 && f->status.log.initialAtLineBoundary==1);
        f->Write(f->Front().c_str()); f->Returned(); f->Step();
        RS2_CHECK(f->status.worker.startupObserved && !StatusRevoked(f->status));
    }
}


template<class Predicate> bool Await(Predicate predicate) {
    const auto started=GetTickCount64();
    do {
        if (predicate()) return true;
        Sleep(10);
    } while (GetTickCount64()-started<5000);
    return false;
}
void ThreadedTransport() {
    Fixture f;
    StatusWireV3 status{}; ReportRingV3 ring{};
    StatusHeader header{}; header.pid=GetCurrentProcessId(); header.processCreation=100;
    LARGE_INTEGER frequency{}; RS2_CHECK(QueryPerformanceFrequency(&frequency));
    header.qpcFrequency=static_cast<std::uint64_t>(frequency.QuadPart);
    header.validity=CompleteHeaderIdentity; header.configuredMode=3; header.runId[0]=0xbb;
    header.hostDigest[0]=0x66;
    StatusPayload owner{}; owner.ownerThreadId=GetCurrentThreadId();
    RS2_CHECK(InitializeStatusV3(status,header,owner));
    RS2_CHECK(InitializeReportRing(ring,status,GetCurrentThreadId()));
    DWORD error{}; ReportingIdentities identities{}; identities.hostDigest[0]=0x66;
    auto* transport=PrepareNativeTransport(status,ring,{Mode::Repair,Diagnostics::Normal},
        identities,GetCurrentThreadId(),&error);
    RS2_CHECK(transport!=nullptr && error==ERROR_SUCCESS);
    if (!transport) return;
    RecoveryStatusWireV1 recovery{};
    RS2_CHECK(InitializeRecoveryStatus(recovery,status.header));
    RS2_CHECK(AttachNativeTransportRecovery(transport,&recovery));
    RS2_CHECK(!AttachNativeTransportRecovery(transport,&recovery));
    RS2_CHECK(!NativeTransportQuiescent(transport,0,1));
    ArmNativeTransport(transport);
    RS2_CHECK(!AttachNativeTransportRecovery(transport,&recovery));
    RS2_CHECK(RequestNativeLogFile(transport,1,0,Units(f.path),f.path.size()));
    Sleep(300);
    // The marker/startup outcome is not available yet: no file identity or
    // bootstrap may be published, despite the ready thread and path request.
    RS2_CHECK(ReadStatusWord(status.logIdentityReady)==0 && NativeTransportQualifiedEpoch(transport)==0);
    NativeStartupSummary startup{}; startup.markerComplete=1; startup.startupAccepted=1;
    RS2_CHECK(CompleteNativeTransportStartup(transport,startup));
    RS2_CHECK(!CompleteNativeTransportStartup(transport,startup));
    const bool qualified=Await([&] { return NativeTransportQualifiedEpoch(transport)==1; });
    RS2_CHECK(qualified);
    OwnerSnapshotV3 publication{}; RS2_CHECK(ReadOwnerV3(status,&publication));
    if (qualified) {
        RS2_CHECK(!NativeTransportQuiescent(transport,0,1)); // Bootstrap ready/ledger work has not been observed.
        LARGE_INTEGER now{}; RS2_CHECK(QueryPerformanceCounter(&now));
        ReportRecordV3 event{}; event.header.kind=1; event.header.qpc=static_cast<std::uint64_t>(now.QuadPart);
        std::uint64_t accepted{};
        RS2_CHECK(EnqueueReport(ring,event,&accepted)==ReportWriteResult::Accepted);
        publication.owner.reportSequence=accepted; publication.transport.generatedSequence=accepted;
        RS2_CHECK(PublishOwnerV3(status,publication.owner,publication.transport));
        RS2_CHECK(!NativeTransportQuiescent(transport,accepted,1));
        const auto submit=[&](std::uint64_t expected,bool publish=true) {
            const auto* frame=NativeTransportFrame(transport,1);
            RS2_CHECK(frame && frame->sequence==expected);
            if (!frame) return false;
            std::string text="Log: ";
            for (std::size_t i=0;i<frame->chars;++i) text.push_back(static_cast<char>(frame->message[i]));
            text+="\r\n";
            if (!expected) RS2_CHECK(text.find("\"marker_complete\":1")!=std::string::npos);
            const auto ticket=frame->ticket;
            f.Write(text.c_str()); // Own fake engine, not a native game call.
            if (expected) publication.transport.submittedSequence=expected;
            else publication.transport.startupSubmitted=1;
            RS2_CHECK(NativeTransportReturned(transport,ticket));
            if (publish) RS2_CHECK(PublishOwnerV3(status,publication.owner,publication.transport));
            return true;
        };
        if (submit(0,false)) {
            RS2_CHECK(Await([&] { return ReadStatusWord(status.worker.preparedSequence)>=1; }));
            RS2_CHECK(ReadStatusWord(status.worker.startupObserved)==0);
            RS2_CHECK(NativeTransportFrame(transport,1)==nullptr); // Positive is prepared but must not be offered.
            RS2_CHECK(PublishOwnerV3(status,publication.owner,publication.transport));
            RS2_CHECK(Await([&] { return ReadStatusWord(status.worker.startupObserved)==1; }));
            RS2_CHECK(Await([&] { return NativeTransportFrame(transport,1)!=nullptr; }));
            if (submit(1)) {
                RS2_CHECK(Await([&] { return ReadStatusWord(status.worker.observedSequence)==1; }));
                RS2_CHECK(Await([&] { return NativeTransportQuiescent(transport,1,1); }));
                RS2_CHECK(!NativeTransportQuiescent(transport,0,1) && !NativeTransportQuiescent(transport,1,2));
                // An old coherent empty-ledger witness cannot authorize after a
                // new owner record, even before the receipt worker sees it.
                RS2_CHECK(QueryPerformanceCounter(&now)); event.header.qpc=static_cast<std::uint64_t>(now.QuadPart);
                RS2_CHECK(EnqueueReport(ring,event,&accepted)==ReportWriteResult::Accepted && accepted==2);
                RS2_CHECK(!NativeTransportQuiescent(transport,1,1));
                publication.owner.reportSequence=accepted; publication.transport.generatedSequence=accepted;
                RS2_CHECK(PublishOwnerV3(status,publication.owner,publication.transport));
                RS2_CHECK(!NativeTransportQuiescent(transport,2,1));
                RS2_CHECK(Await([&] { return NativeTransportFrame(transport,1)!=nullptr; }));
                if (submit(2)) RS2_CHECK(Await([&] { return NativeTransportQuiescent(transport,2,1); }));
            }
        }
        const auto initial=ReadStatusWord(status.log.initialEOF);
        RS2_CHECK(RequestNativeLogFile(transport,2,0,Units(f.path),f.path.size()));
        RS2_CHECK(Await([&] { return NativeTransportQualifiedEpoch(transport)==2; }));
        RS2_CHECK(Await([&] { return NativeTransportQuiescent(transport,publication.owner.reportSequence,2); }));
        RS2_CHECK(!NativeTransportQuiescent(transport,publication.owner.reportSequence,1));
        RS2_CHECK(status.log.initialEOF==initial && !StatusRevoked(status));
    }
    StopStatus(status,1);
    StopNativeTransport(transport);
    RS2_CHECK(WaitNativeTransportForTest(transport,5000));
    RS2_CHECK(NativeTransportQualifiedEpoch(transport)==0);
    RS2_CHECK(!NativeTransportQuiescent(transport,publication.owner.reportSequence,2));
    RS2_CHECK(!NativeTransportFrame(transport,2));
    RS2_CHECK(!RequestNativeLogFile(transport,3,0,Units(f.path),f.path.size()));

    // A callback can revoke after installation but before transport arming.
    // Receipts must remain unarmed, while diagnostics can still announce it.
    StatusWireV3 revoked{}; ReportRingV3 revokedRing{};
    RS2_CHECK(InitializeStatusV3(revoked,header,owner));
    RS2_CHECK(InitializeReportRing(revokedRing,revoked,GetCurrentThreadId()));
    auto* rejected=PrepareNativeTransport(revoked,revokedRing,{Mode::Repair,Diagnostics::Normal},
        identities,GetCurrentThreadId(),&error);
    RS2_CHECK(rejected!=nullptr);
    if(rejected) {
        RevokeStatus(revoked,Reason::ForeignThread); ArmNativeTransport(rejected);
        RS2_CHECK(Await([&]{return ReadStatusWord(revoked.console.attempts)!=0;}));
        RS2_CHECK(!NativeTransportQualifiedEpoch(rejected));
        StopNativeTransport(rejected); RS2_CHECK(WaitNativeTransportForTest(rejected,5000));
    }
}

}
void NativeLogFileTests() {
    Syntax(); GrowthAndTruncation(); BoundaryAndReplacement(); MissingAndEmpty();
    WorkerReceiptOrdering(); WorkerBudgetAndLateReceipt(); WorkerFaultsAndStop();
    WorkerInitialPartialLine(); WorkerUnpublishedFileChange();
    ThreadedTransport();
}
}
