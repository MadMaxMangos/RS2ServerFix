#include "companion/steam_reporting_pipeline.h"
#include "companion/steam_reporting_hash.h"
#include "companion/sha256.h"
#include "test_framework.h"
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace rs2fix::testcases {
namespace {
using namespace reporting;
struct Fixture {
    StatusWireV3 status{};
    ReportRingV3 ring{};
    NativePipeline pipe{};
    NativeFormatContext context{};
    OwnerSnapshotV3 owner{};
    PreparedNativeHash hash{};
    bool failHash{};
    static bool Hash(void* ptr,const void* bytes,std::size_t size,Sha256Digest* out) noexcept {
        auto& f=*static_cast<Fixture*>(ptr);
        const auto ops=NativeHashOperations(f.hash);
        return !f.failHash && ops.digest(ops.context,bytes,size,out);
    }
    Fixture() {
        RS2_CHECK(PrepareNativeHash(hash));
        StatusHeader header{}; header.pid=123; header.processCreation=99;
        header.qpcFrequency=10000000; header.validity=CompleteHeaderIdentity;
        header.configuredMode=3; header.runId[0]=1;
        StatusPayload payload{}; payload.ownerThreadId=GetCurrentThreadId();
        RS2_CHECK(InitializeStatusV3(status,header,payload));
        RS2_CHECK(InitializeReportRing(ring,status,GetCurrentThreadId()));
        context.header=status.header; context.config={Mode::Repair,Diagnostics::Normal};
        constexpr char16_t path[]=u"E:\\logs\\Launch.log";
        std::memcpy(context.log.path,path,sizeof(path)); context.log.pathChars=std::size(path)-1;
        context.log.transportKind=1; context.log.utcFiletime=134100000000000000;
        context.log.calibrationQpcBefore=100; context.log.calibrationQpcAfter=102;
        context.log.initialAtLineBoundary=1;
        RS2_CHECK(InitializeNativePipeline(pipe,status,ring,context,{this,Hash},101)==TransportReason::None);
        RS2_CHECK(ReadOwnerV3(status,&owner));
    }
    ~Fixture() { CloseNativeHash(hash); }
    void Enqueue(unsigned count) {
        for (unsigned i=0;i<count;++i) {
            ReportRecordV3 record{}; record.header.kind=static_cast<std::uint32_t>(RecordKindV3::State);
            record.header.qpc=102+i;
            std::uint64_t accepted{};
            RS2_CHECK(EnqueueReport(ring,record,&accepted)==ReportWriteResult::Accepted);
            owner.owner.reportSequence=accepted; owner.transport.generatedSequence=accepted;
        }
        RS2_CHECK(PublishOwnerV3(status,owner.owner,owner.transport));
        RS2_CHECK(ReadOwnerV3(status,&owner));
    }
    std::string Message() {
        const auto* front=PeekNativeFrame(pipe);
        RS2_CHECK(front!=nullptr);
        if (!front) return {};
        std::string result(front->chars,'\0');
        for (std::size_t i=0;i<front->chars;++i) result[i]=static_cast<char>(front->message[i]);
        return result;
    }
    void Submit() {
        const auto* front=PeekNativeFrame(pipe);
        RS2_CHECK(front!=nullptr);
        if (!front) return;
        if (front->sequence) owner.transport.submittedSequence=front->sequence;
        else owner.transport.startupSubmitted=1;
        RS2_CHECK(ReleaseNativeFrame(pipe,front->ticket));
        RS2_CHECK(PublishOwnerV3(status,owner.owner,owner.transport));
        RS2_CHECK(ReadOwnerV3(status,&owner));
    }
    void Ack(const std::string& message) {
        RS2_CHECK(MatchNativeReceipt(&pipe,message.data(),message.size())==ReceiptDisposition::AwaitingSubmission);
        RS2_CHECK(AcknowledgeNativeReceipt(pipe,owner));
    }
};
void ReceiptBeforePublication() {
    auto f=std::make_unique<Fixture>();
    const auto bootstrap=f->Message();
    RS2_CHECK(MatchNativeReceipt(&f->pipe,bootstrap.data(),bootstrap.size())==ReceiptDisposition::AwaitingSubmission);
    RS2_CHECK(!AcknowledgeNativeReceipt(f->pipe,f->owner));
    RS2_CHECK(f->pipe.ledgerRead==0 && f->pipe.startupObserved==0 && f->pipe.heldMatch==1);
    f->Submit();
    RS2_CHECK(AcknowledgeNativeReceipt(f->pipe,f->owner));
    RS2_CHECK(f->pipe.ledgerRead==1 && f->pipe.startupObserved==1);
    f->Enqueue(1); RS2_CHECK(PrepareNativeFrames(f->pipe,200));
    const auto positive=f->Message();
    RS2_CHECK(MatchNativeReceipt(&f->pipe,positive.data(),positive.size())==ReceiptDisposition::AwaitingSubmission);
    RS2_CHECK(!AcknowledgeNativeReceipt(f->pipe,f->owner) && f->pipe.observedSequence==0);
    f->Submit(); RS2_CHECK(AcknowledgeNativeReceipt(f->pipe,f->owner));
    RS2_CHECK(f->pipe.observedSequence==1 && !StatusRevoked(f->status));
}
void BoundedBacklog() {
    auto f=std::make_unique<Fixture>();
    auto bootstrap=f->Message(); f->Submit(); f->Ack(bootstrap);
    f->Enqueue(256);
    for (unsigned i=0;i<8;++i) RS2_CHECK(PrepareNativeFrames(f->pipe,200+i));
    RS2_CHECK(f->pipe.ledgerWrite-f->pipe.ledgerRead==256);
    RS2_CHECK(f->pipe.readyWrite-f->pipe.readyRead==8);
    RS2_CHECK(f->ring.reportReadSequence==256 && f->pipe.preparedSequence==8);
    // Native submission frees only a ready slot, never unreceipted ledger credit.
    std::vector<std::string> written;
    for (unsigned i=0;i<8;++i) { written.push_back(f->Message()); f->Submit(); }
    RS2_CHECK(f->pipe.ledgerWrite-f->pipe.ledgerRead==256 && f->pipe.observedSequence==0);
    RS2_CHECK(PrepareNativeFrames(f->pipe,220));
    RS2_CHECK(f->pipe.preparedSequence==16 && f->pipe.ledgerWrite-f->pipe.ledgerRead==256);
    for (const auto& message:written) f->Ack(message);
    RS2_CHECK(f->pipe.observedSequence==8 && f->pipe.ledgerWrite-f->pipe.ledgerRead==248);
    // Storage wraps without changing source record/receipt sequence identities.
    for (unsigned i=9;i<=256;++i) {
        RS2_CHECK(PrepareNativeFrames(f->pipe,300+i));
        const auto message=f->Message(); f->Submit(); f->Ack(message);
    }
    RS2_CHECK(f->pipe.observedSequence==256 && f->pipe.ledgerWrite==f->pipe.ledgerRead);
    f->Enqueue(20);
    for (unsigned i=257;i<=276;++i) {
        RS2_CHECK(PrepareNativeFrames(f->pipe,600+i));
        const auto message=f->Message(); f->Submit(); f->Ack(message);
    }
    RS2_CHECK(f->pipe.observedSequence==276 && !StatusRevoked(f->status));
}
void DamageAndGap() {
    auto f=std::make_unique<Fixture>();
    auto bootstrap=f->Message(); f->Submit(); f->Ack(bootstrap);
    f->Enqueue(2); RS2_CHECK(PrepareNativeFrames(f->pipe,200));
    const auto first=f->Message(); f->Submit();
    auto second=f->Message(); f->Submit();
    RS2_CHECK(MatchNativeReceipt(&f->pipe,second.data(),second.size())==ReceiptDisposition::Gap);
    RS2_CHECK(f->pipe.observedSequence==0 && f->pipe.heldMatch==0);
    second.back()='x';
    RS2_CHECK(MatchNativeReceipt(&f->pipe,second.data(),second.size())==ReceiptDisposition::Corrupt);
    f->Ack(first);
    RS2_CHECK(!AcknowledgeNativeReceipt(f->pipe,f->owner)); // No fabricated match.
    auto hashFail=std::make_unique<Fixture>(); hashFail->Enqueue(1); hashFail->failHash=true;
    RS2_CHECK(!PrepareNativeFrames(hashFail->pipe,200) && StatusRevoked(hashFail->status));
    auto damaged=std::make_unique<Fixture>();
    damaged->pipe.ready[0].message[50]=0x010A;
    RS2_CHECK(!PeekNativeFrame(damaged->pipe) && StatusRevoked(damaged->status));
    // Startup size refusal never consumes an accepted scalar or latches loss.
    wchar_t tiny[1]{}; char ascii[10]{}; std::size_t bytes{};
    RS2_CHECK(PrepareNativeBootstrap(damaged->context,ascii,sizeof(ascii),tiny,std::size(tiny),&bytes)==
        TransportReason::FramingUnsupported);
}
void ReusableHashes() {
    PreparedNativeHash hash{};
    RS2_CHECK(PrepareNativeHash(hash));
    auto ops=NativeHashOperations(hash);
    for (const auto& text: {std::string("abc"),std::string(""),std::string(8192,'x'),std::string("abc")}) {
        Sha256Digest actual{},expected{};
        RS2_CHECK(HashBytesSha256(text.data(),text.size(),&expected));
        RS2_CHECK(ops.digest(ops.context,text.data(),text.size(),&actual) && actual==expected);
    }
    Sha256Digest invalid{}; invalid.fill(0xff);
    RS2_CHECK(!ops.digest(ops.context,"x",8193,&invalid) && invalid==Sha256Digest{} && hash.failed);
    RS2_CHECK(!ops.digest(ops.context,"abc",3,&invalid));
    CloseNativeHash(hash);
}
}
void NativeLogPipelineTests() { ReceiptBeforePublication(); BoundedBacklog(); DamageAndGap(); ReusableHashes(); }
}
