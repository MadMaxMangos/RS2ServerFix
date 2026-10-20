#include "companion/steam_reporting_receipts.h"
#include "test_framework.h"
#include <string>

namespace rs2fix::testcases {
namespace {
using namespace reporting;
struct Match {
    unsigned calls{};
    ReceiptDisposition result=ReceiptDisposition::Accepted;
    std::string last;
    static ReceiptDisposition Run(void* context,const char* bytes,std::size_t count) noexcept {
        auto& self=*static_cast<Match*>(context);
        ++self.calls; self.last.assign(bytes,count); return self.result;
    }
    ReceiptMatchOps Ops() { return {this,Run}; }
};
constexpr std::uint8_t runId[16]{0xab,0xcd};
const std::string message=std::string(native_log::kMarker)+
    "{\"schema\":3,\"type\":\"startup\",\"run_id\":\"abcd0000000000000000000000000000\","
    "\"pid\":123,\"sequence\":0}";
const std::string line="Log: "+message+"\r\n";
ReceiptScanner Scanner(bool boundary=true) {
    ReceiptScanner s{};
    RS2_CHECK(InitializeReceiptScanner(s,123,boundary,native_log::PrefixMode::LogOnly,runId));
    return s;
}
ReceiptScanResult Feed(ReceiptScanner& s,Match& m,const std::string& data) {
    return ScanReceiptChunk(s,m.Ops(),data.data(),data.size());
}
void Boundaries() {
    for (std::size_t split=0;split<line.size();++split) {
        auto s=Scanner(); Match m;
        RS2_CHECK(Feed(s,m,line.substr(0,split)).consumed==split);
        RS2_CHECK(!s.failed && m.calls==0 && s.offset==123+split);
        RS2_CHECK(Feed(s,m,line.substr(split)).disposition==ReceiptDisposition::Accepted);
        RS2_CHECK(m.calls==1 && m.last==message && s.carry==0 && s.offset==123+line.size());
    }
    auto s=Scanner(false); Match m;
    const auto bytes=std::string("remaining old line\n")+line;
    RS2_CHECK(Feed(s,m,bytes).consumed==bytes.size() && m.calls==1);
    s=Scanner(); m={};
    const auto unrelated=std::string(300000,'x')+message+"\n";
    RS2_CHECK(Feed(s,m,unrelated).consumed==unrelated.size());
    RS2_CHECK(!s.failed && m.calls==0 && s.carry==0);
    RS2_CHECK(Feed(s,m,line).disposition==ReceiptDisposition::Accepted && m.calls==1);
}
void SubmissionRace() {
    auto s=Scanner(); Match m; m.result=ReceiptDisposition::AwaitingSubmission;
    const auto chunk=line+line;
    const auto read=Feed(s,m,chunk);
    RS2_CHECK(read.disposition==ReceiptDisposition::AwaitingSubmission);
    RS2_CHECK(read.consumed==line.size() && s.offset==123+line.size() && m.calls==1);
    RS2_CHECK(Feed(s,m,chunk.substr(read.consumed)).consumed==0 && m.calls==1);
    // In production the ledger must first confirm the held match against the
    // owner's submitted watermark. Resume itself deliberately performs no I/O.
    RS2_CHECK(ResumeReceiptScanner(s));
    m.result=ReceiptDisposition::Accepted;
    RS2_CHECK(Feed(s,m,chunk.substr(read.consumed)).consumed==line.size());
    RS2_CHECK(m.calls==2 && s.offset==123+chunk.size());
    RS2_CHECK(!ResumeReceiptScanner(s));
}
void ElapsedPrefix() {
    ReceiptScanner s{}; Match m;
    RS2_CHECK(InitializeReceiptScanner(s,0,true,native_log::PrefixMode::ElapsedTime,runId));
    const auto text=std::string("[100000.00] Log: ")+message+"\r\n";
    for (std::size_t offset=0;offset<text.size();offset+=13) {
        const auto chunk=text.substr(offset,13);
        RS2_CHECK(Feed(s,m,chunk).consumed==chunk.size());
    }
    RS2_CHECK(m.calls==1 && m.last==message && !s.carry && !s.failed && s.offset==text.size());
}
void ScopeAndFaults() {
    RS2_CHECK(native_log::BelongsToRun(message.data(),message.size(),runId));
    for (const auto& text : {
        std::string("Log: ")+native_log::kMarker+"junk\n",
        std::string("Log: ")+native_log::kMarker+std::string(20000,'x')+"\n",
        std::string("Log: {\"chat\":\"")+message+"\"}\r\n",
        std::string("ScriptLog: ")+message+"\r\n",
        std::string("Log: player ")+message+"\r\n"}) {
        auto s=Scanner(); Match m;
        RS2_CHECK(Feed(s,m,text).consumed==text.size() && !s.failed && m.calls==0);
    }
    auto other=line;
    other.replace(other.find("abcd"),4,"1234");
    other.insert(other.size()-2,20000,'x');
    auto s=Scanner(); Match m;
    RS2_CHECK(Feed(s,m,other).consumed==other.size() && !s.failed && m.calls==0);
    // A run-scoped bad line is corruption only when complete, not at EOF.
    auto oversized="Log: "+message+std::string(20000,'x');
    RS2_CHECK(Feed(s,m,oversized).consumed==oversized.size() && !s.failed);
    RS2_CHECK(Feed(s,m,"\r\n").disposition==ReceiptDisposition::Corrupt && s.failed);
    RS2_CHECK(Feed(s,m,line).consumed==0 && !ResumeReceiptScanner(s));
    s=Scanner(); m={};
    auto bad="Log: "+message+"\t\r\n";
    RS2_CHECK(Feed(s,m,bad).disposition==ReceiptDisposition::Corrupt && m.calls==0);
    s=Scanner(); m.result=ReceiptDisposition::Gap;
    RS2_CHECK(Feed(s,m,line+line).consumed==line.size() && s.failed && m.calls==1);
    s=Scanner(); m={}; s.offset=UINT64_MAX;
    RS2_CHECK(Feed(s,m,line).consumed==0 && s.failed);
}
}
void NativeLogReceiptTests() { Boundaries(); SubmissionRace(); ElapsedPrefix(); ScopeAndFaults(); }
}
