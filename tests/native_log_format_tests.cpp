#include "companion/steam_reporting_format_v3.h"
#include "companion/steam_reporting_json.h"
#include "shared/native_log_framing.h"
#include "test_framework.h"
#include <cstring>
#include <string>
#include <algorithm>

namespace rs2fix::testcases {
namespace {
using namespace reporting;
NativeFormatContext Context() {
    NativeFormatContext c{};
    c.header.magic=kStatusMagic; c.header.schema=3; c.header.bytes=sizeof(StatusWireV3);
    c.header.artifactVersion=kReportingArtifactVersionV3;
    c.header.configuredMode=3; c.header.validity=CompleteHeaderIdentity;
    c.header.pid=123; c.header.processCreation=134000000000000000;
    c.header.qpcFrequency=10000000;
    c.header.runId[0]=0xAB; c.header.runId[15]=0xEF;
    c.config={Mode::Repair,Diagnostics::Normal};
    c.log.utcFiletime=134100000000000000;
    c.log.calibrationQpcBefore=100; c.log.calibrationQpcAfter=102;
    c.log.transportKind=1; c.log.initialAtLineBoundary=1;
    constexpr char path[]="E:\\Logs\\Launch.log";
    c.log.pathChars=sizeof(path)-1;
    for (std::size_t i=0;i<c.log.pathChars;++i) c.log.path[i]=path[i];
    return c;
}
void CheckJson(const char* message,std::size_t bytes,const NativeFormatContext& context) {
    RS2_CHECK(native_log::BelongsToRun(message,bytes,context.header.runId));
    // Reuse the existing full JSON validator by appending its required count
    // tuple to the root. This checks our actual serialized document, not a
    // separate test serializer; no Steam/backend message is sent.
    RS2_CHECK(bytes>sizeof(native_log::kMarker));
    std::string json(message+sizeof(native_log::kMarker)-1,
        bytes-(sizeof(native_log::kMarker)-1));
    RS2_CHECK(json.back()=='}'); json.pop_back();
    json+=",\"op\":[{\"k\":\"PI_COUNT\",\"v\":\"1\"},"
        "{\"k\":\"BotPlayerCount\",\"v\":\"0\"},{\"k\":\"MaxPlayerCount\",\"v\":\"64\"}]}";
    RS2_CHECK(ValidatePreparedJson(json.data(),json.size(),{1,0,64})==Reason::None);
    wchar_t wide[native_log::kMessageLimit+1]{};
    RS2_CHECK(native_log::PrepareMessage(message,bytes,wide,std::size(wide)));
    RS2_CHECK(native_log::ValidMessage(wide,bytes));
}
void Formatting() {
    auto c=Context();
    char output[native_log::kMessageLimit+1]{};
    std::size_t bytes{};
    RS2_CHECK(FormatNativeBootstrap(c,output,sizeof(output),&bytes));
    CheckJson(output,bytes,c);
    RS2_CHECK(std::strstr(output,"\"sequence\":0")!=nullptr);
    RS2_CHECK(std::strstr(output,"\"log_path\":\"E:\\\\Logs\\\\Launch.log\"")!=nullptr);
    RS2_CHECK(std::strstr(output,"\"run_id\":\"ab0000000000000000000000000000ef\"")!=nullptr);
    // Every schema kind, including worst scalar widths, must remain bounded.
    for (std::uint32_t kind=1;kind<static_cast<std::uint32_t>(RecordKindV3::Count);++kind) {
        ReportRecordV3 record{};
        record.header.kind=kind; record.header.sequence=UINT64_MAX;
        record.header.qpc=100;
        std::memset(&record.payload,0xff,sizeof(record.payload));
        if (kind == static_cast<std::uint32_t>(RecordKindV3::Recovery)) {
            record.payload.recovery = {};
            record.payload.recovery.phase = static_cast<std::uint64_t>(RecoveryPhase::Failed);
            record.payload.recovery.event = static_cast<std::uint64_t>(RecoveryEvent::Final);
            record.payload.recovery.reason = static_cast<std::uint64_t>(RecoveryReason::ClockFault);
            record.payload.recovery.flags = RecoveryRestartRequired | RecoveryTerminal;
            record.payload.recovery.oldSdkFingerprint = UINT64_MAX;
            record.payload.recovery.newSdkFingerprint = UINT64_MAX;
            record.payload.recovery.oldCacheFingerprint = UINT64_MAX;
            record.payload.recovery.newCacheFingerprint = UINT64_MAX;
        }
        RS2_CHECK(FormatNativeRecord(c,record,output,sizeof(output),&bytes));
        CheckJson(output,bytes,c);
        RS2_CHECK(bytes<native_log::kMessageLimit);
        RS2_CHECK(std::strstr(output,"\"sequence\":18446744073709551615")!=nullptr);
        char tiny[8]; std::memset(tiny,'x',sizeof(tiny)); bytes=99;
        RS2_CHECK(!FormatNativeRecord(c,record,tiny,sizeof(tiny),&bytes));
        RS2_CHECK(bytes==0 && tiny[0]==0);
    }
    // Six ASCII bytes per Unicode code unit: worst legal path expansion.
    c.log.pathChars=1023;
    std::fill(std::begin(c.log.path),std::end(c.log.path),std::uint16_t{0x010A});
    c.log.path[1023]=0;
    RS2_CHECK(FormatNativeBootstrap(c,output,sizeof(output),&bytes));
    CheckJson(output,bytes,c);
    RS2_CHECK(std::strstr(output,"\\u010a")!=nullptr && std::strchr(output,'\n')==nullptr);
    const auto expected=bytes;
    wchar_t prepared[native_log::kMessageLimit+1]{};
    RS2_CHECK(PrepareNativeBootstrap(c,output,sizeof(output),prepared,std::size(prepared),&bytes)==TransportReason::None);
    RS2_CHECK(native_log::ValidMessage(prepared,bytes));
    RS2_CHECK(PrepareNativeBootstrap(c,output,expected,prepared,std::size(prepared),&bytes)==TransportReason::FramingUnsupported);
    RS2_CHECK(bytes==0 && output[0]==0 && prepared[0]==0);
    RS2_CHECK(!FormatNativeBootstrap(c,output,expected,&bytes));
    RS2_CHECK(bytes==0 && output[0]==0);
    RS2_CHECK(FormatNativeBootstrap(c,output,expected+1,&bytes));
    c.log.path[0]='"'; c.log.path[1]='\\'; c.log.path[2]=0xD83D; c.log.path[3]=0xDE80;
    RS2_CHECK(FormatNativeBootstrap(c,output,sizeof(output),&bytes)); CheckJson(output,bytes,c);
    c.header.schema=2;
    RS2_CHECK(!FormatNativeBootstrap(c,output,sizeof(output),&bytes));
    RS2_CHECK(bytes==0 && output[0]==0);
    c=Context(); c.config.mode=Mode::Observe; // Mismatch must not mislabel identity.
    RS2_CHECK(!FormatNativeBootstrap(c,output,sizeof(output),&bytes));
    c=Context(); ReportRecordV3 invalid{}; invalid.header.kind=1; invalid.header.qpc=101;
    RS2_CHECK(!FormatNativeRecord(c,invalid,output,sizeof(output),&bytes));
    invalid.header.sequence=1; invalid.header.kind=static_cast<std::uint32_t>(RecordKindV3::Count);
    RS2_CHECK(!FormatNativeRecord(c,invalid,output,sizeof(output),&bytes));
}
void RecoveryFormatting() {
    auto c = Context();
    ReportRecordV3 record{};
    record.header.kind = static_cast<std::uint32_t>(RecordKindV3::Recovery);
    record.header.sequence = 42; record.header.qpc = 200;
    auto& p = record.payload.recovery;
    p.phase = static_cast<std::uint64_t>(RecoveryPhase::Failed);
    p.event = static_cast<std::uint64_t>(RecoveryEvent::Final);
    p.reason = static_cast<std::uint64_t>(RecoveryReason::ClockFault);
    p.flags = RecoveryRestartRequired | RecoveryTerminal | RecoveryCreateCallbackObserved | RecoveryCallbackOwnTimingValid;
    p.qpc = 90; p.callbackOwnTicks = 5;
    p.oldSdkFingerprint = UINT64_MAX; p.newSdkFingerprint = 0x8000000000000000ULL;
    p.oldCacheFingerprint = UINT64_MAX; p.newCacheFingerprint = UINT64_MAX;
    char output[native_log::kMessageLimit + 1]{}; std::size_t bytes{};
    RS2_CHECK(FormatNativeRecord(c, record, output, sizeof(output), &bytes));
    CheckJson(output, bytes, c);
    RS2_CHECK(std::strstr(output, "\"type\":\"recovery\"") && std::strstr(output, "\"kind\":10"));
    RS2_CHECK(std::strstr(output, "\"qpc\":200") && std::strstr(output, "\"recovery_qpc\":90"));
    RS2_CHECK(std::strstr(output, "\"reason\":0") && std::strstr(output, "\"recovery_reason\":26"));
    RS2_CHECK(std::strstr(output, "\"flags\":0") && std::strstr(output, "\"recovery_record_sequence\":0"));
    RS2_CHECK(std::strstr(output, "\"recovery_old_sdk_fingerprint\":18446744073709551615"));
    RS2_CHECK(std::strstr(output, "\"recovery_new_sdk_fingerprint\":9223372036854775808"));
    const char* keys[] = {"recovery_phase", "recovery_event", "recovery_reason", "recovery_outcome", "recovery_flags",
        "recovery_operation_sequence", "recovery_transition_sequence", "recovery_qpc", "recovery_source_epoch",
        "recovery_sdk_epoch", "recovery_owner_thread_id", "recovery_resource_phase", "recovery_native_stage",
        "recovery_exception_code", "recovery_request_id", "recovery_callback_id", "recovery_callback_result",
        "recovery_api_returned_id", "recovery_old_sdk_fingerprint", "recovery_new_sdk_fingerprint",
        "recovery_old_cache_fingerprint", "recovery_new_cache_fingerprint", "recovery_finish_deadline_qpc",
        "recovery_overall_deadline_qpc", "recovery_record_sequence", "recovery_callback_own_ticks"};
    for (const auto key : keys) {
        const auto needle = std::string("\"") + key + "\":";
        const auto first = std::strstr(output, needle.c_str());
        RS2_CHECK(first && !std::strstr(first + needle.size(), needle.c_str()));
    }
    unsigned keyCount{};
    for (const char* at = output; (at = std::strstr(at, "\":")) != nullptr; at += 2) ++keyCount;
    RS2_CHECK(keyCount == 39 && !std::strstr(output, "unused_quota"));
    for (unsigned invalid = 0; invalid < 4; ++invalid) {
        auto bad = record;
        if (invalid == 0) bad.header.reason = 1;
        if (invalid == 1) bad.header.flags = 1;
        if (invalid == 2) bad.payload.recovery.recordSequence = 42;
        if (invalid == 3) bad.payload.recovery.flags &= ~RecoveryCallbackOwnTimingValid;
        RS2_CHECK(!FormatNativeRecord(c, bad, output, sizeof(output), &bytes) && !bytes && !output[0]);
    }
}
void ClockArithmetic() {
    auto c=Context(); std::uint64_t utc{};
    RS2_CHECK(DeriveUtcFiletime(c.log,10000000,101,&utc) && utc==c.log.utcFiletime);
    RS2_CHECK(DeriveUtcFiletime(c.log,10000000,99,&utc) && utc==c.log.utcFiletime-2);
    RS2_CHECK(DeriveUtcFiletime(c.log,10000000,10000101,&utc) && utc==c.log.utcFiletime+10000000);
    RS2_CHECK(DeriveUtcFiletime(c.log,3,102,&utc) && utc==c.log.utcFiletime+3333333);
    // Exercise a product above 64 bits without overflowing the final quotient.
    c.log.calibrationQpcBefore=c.log.calibrationQpcAfter=1;
    RS2_CHECK(DeriveUtcFiletime(c.log,UINT64_MAX,UINT64_MAX,&utc) &&
        utc==c.log.utcFiletime+9999999);
    RS2_CHECK(!DeriveUtcFiletime(c.log,1,UINT64_MAX,&utc) && utc==0);
    c.log.utcFiletime=UINT64_MAX;
    RS2_CHECK(!DeriveUtcFiletime(c.log,1,2,&utc) && utc==0);
    c.log.utcFiletime=1; c.log.calibrationQpcBefore=c.log.calibrationQpcAfter=2;
    RS2_CHECK(!DeriveUtcFiletime(c.log,10000000,1,&utc) && utc==0);
    RS2_CHECK(!DeriveUtcFiletime(c.log,0,2,&utc));
    c.log.calibrationQpcAfter=1;
    RS2_CHECK(!DeriveUtcFiletime(c.log,1,2,&utc));
}
}
void NativeLogFormatTests() { Formatting(); ClockArithmetic(); RecoveryFormatting(); }
}
