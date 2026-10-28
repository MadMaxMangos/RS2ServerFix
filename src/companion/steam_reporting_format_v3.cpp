#include "companion/steam_reporting_format_v3.h"
#include "shared/native_log_framing.h"
#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <intrin.h>

namespace rs2fix::reporting {
namespace {
// Worker-owned output only. No allocation, native logger calls or status mutation.
class Json {
public:
    Json(char* output,std::size_t capacity) noexcept
        : out_(output),capacity_(std::min(capacity,native_log::kMessageLimit+1)),
          good_(output && capacity_!=0) { if (good_) out_[0]=0; }
    void Append(const char* format,...) noexcept {
        if (!good_) return;
        va_list args; va_start(args,format);
        const int result=vsnprintf(out_+used_,capacity_-used_,format,args);
        va_end(args);
        if (result<0 || static_cast<std::size_t>(result)>=capacity_-used_) { good_=false; return; }
        used_+=static_cast<std::size_t>(result);
    }
    void Path(const LogIdentity& log) noexcept {
        if (!good_) return;
        std::size_t bytes{};
        if (!native_log::EscapeJsonUtf16(log.path,static_cast<std::size_t>(log.pathChars),
            out_+used_,capacity_-used_,&bytes)) { good_=false; return; }
        used_+=bytes;
    }
    bool Finish(std::size_t* bytes) noexcept {
        Append("}");
        if (!bytes) good_=false;
        if (good_) {
            for (std::size_t i=0;i<used_;++i)
                if (static_cast<unsigned char>(out_[i])<0x20 ||
                    static_cast<unsigned char>(out_[i])>0x7e) { good_=false; break; }
        }
        if (!good_) { if (out_ && capacity_) out_[0]=0; return false; }
        *bytes=used_; return true;
    }
private:
    char* out_; std::size_t capacity_,used_{}; bool good_;
};
void Hex(const std::uint8_t* input,std::size_t count,char* out) noexcept {
    constexpr char digits[]="0123456789abcdef";
    for (std::size_t i=0;i<count;++i) { out[2*i]=digits[input[i]>>4]; out[2*i+1]=digits[input[i]&15]; }
    out[2*count]=0;
}
bool ContextValid(const NativeFormatContext& c) noexcept {
    const auto& h=c.header; const auto& l=c.log;
    return h.magic==kStatusMagic && h.schema==kStatusSchemaV3 &&
        h.bytes==sizeof(StatusWireV3) && h.artifactVersion==kReportingArtifactVersionV3 &&
        h.validity==CompleteHeaderIdentity && h.pid && h.processCreation && h.qpcFrequency &&
        h.configuredMode==static_cast<std::uint32_t>(c.config.mode) &&
        c.config.mode>=Mode::Disabled && c.config.mode<=Mode::Repair &&
        c.config.diagnostics>=Diagnostics::Normal && c.config.diagnostics<=Diagnostics::Operational &&
        l.pathChars>0 && l.pathChars<1024 && l.path[l.pathChars]==0 &&
        l.prefixMode<=1 && l.transportKind==1 && l.durability==0 &&
        l.initialAtLineBoundary<=1 &&
        std::memcmp(h.hostDigest,c.identities.hostDigest.data(),sizeof(h.hostDigest))==0;
}
bool Begin(const NativeFormatContext& c,Json& json,const char* type,
           std::uint64_t sequence,std::uint64_t qpc) noexcept {
    std::uint64_t utc{};
    if (!ContextValid(c) || !DeriveUtcFiletime(c.log,c.header.qpcFrequency,qpc,&utc)) return false;
    char run[33]{}; Hex(c.header.runId,sizeof(c.header.runId),run);
    json.Append("%s{\"schema\":3,\"type\":\"%s\",\"run_id\":\"%s\",\"pid\":%u,"
        "\"sequence\":%llu,\"qpc\":%llu,\"utc_derived_filetime\":%llu",
        native_log::kMarker,type,run,c.header.pid,sequence,qpc,utc);
    return true;
}
void Clear(char* output,std::size_t capacity,std::size_t* bytes) noexcept {
    if (output && capacity) output[0]=0;
    if (bytes) *bytes=0;
}
} // namespace

bool DeriveUtcFiletime(const LogIdentity& log,std::uint64_t frequency,
    std::uint64_t sourceQpc,std::uint64_t* utc) noexcept {
    if (!utc) return false;
    *utc=0;
    if (!frequency || !sourceQpc || !log.utcFiletime || !log.calibrationQpcBefore ||
        log.calibrationQpcAfter<log.calibrationQpcBefore) return false;
    const auto midpoint=log.calibrationQpcBefore+
        (log.calibrationQpcAfter-log.calibrationQpcBefore)/2;
    const bool positive=sourceQpc>=midpoint;
    const auto delta=positive ? sourceQpc-midpoint : midpoint-sourceQpc;
    constexpr std::uint64_t perSecond=10000000;
    const auto seconds=delta/frequency;
    if (seconds>UINT64_MAX/perSecond) return false;
    // remainder*10^7 can exceed 64 bits even though its quotient cannot.
    unsigned __int64 high{},remainder{};
    const auto low=_umul128(delta%frequency,perSecond,&high);
    const auto fraction=_udiv128(high,low,frequency,&remainder);
    auto ticks=seconds*perSecond;
    if (fraction>UINT64_MAX-ticks) return false;
    ticks+=fraction;
    if ((positive && ticks>UINT64_MAX-log.utcFiletime) ||
        (!positive && ticks>=log.utcFiletime)) return false;
    *utc=positive ? log.utcFiletime+ticks : log.utcFiletime-ticks;
    return true;
}
bool FormatNativeBootstrap(const NativeFormatContext& c,char* output,
    std::size_t capacity,std::size_t* bytes) noexcept {
    Clear(output,capacity,bytes);
    if (!output || !capacity || !bytes) return false;
    Json json(output,capacity);
    if (c.log.calibrationQpcAfter<c.log.calibrationQpcBefore) return false;
    const auto midpoint=c.log.calibrationQpcBefore+
        (c.log.calibrationQpcAfter-c.log.calibrationQpcBefore)/2;
    if (!Begin(c,json,"startup",0,midpoint)) return false;
    char host[65]{},sdk[65]{},client[65]{},fileId[33]{};
    Hex(c.header.hostDigest,32,host);
    Hex(c.identities.steamApiDigest.data(),32,sdk);
    Hex(c.identities.steamClientDigest.data(),32,client);
    Hex(c.log.fileId,16,fileId);
    json.Append(",\"artifact\":\"RS2ServerFix-steam-reporting\",\"version\":\"0.7.1.0\","
        "\"artifact_version\":%u,\"process_start_filetime\":%llu,\"qpc_frequency\":%llu,"
        "\"mode\":\"%s\",\"configured_mode\":%u,\"header_validity\":%u,"
        "\"diagnostics\":\"%s\",\"anchor_interval_seconds\":%u,"
        "\"host_sha256\":\"%s\",\"qualified_steam_api_sha256\":\"%s\","
        "\"qualified_steamclient_sha256\":\"%s\",\"transport\":\"native\","
        "\"durability\":\"unknown\",\"utc_kind\":\"derived\","
        "\"utc_calibration_filetime\":%llu,\"calibration_qpc_before\":%llu,"
        "\"calibration_qpc_after\":%llu,\"volume_serial\":%llu,\"file_id\":\"%s\","
        "\"initial_eof\":%llu,\"initial_at_line_boundary\":%llu,\"prefix_mode\":%llu,"
        "\"record_bytes\":256,\"ring_capacity\":256,\"batch_limit\":32,"
        "\"ledger_capacity\":256,\"ready_capacity\":8,\"message_limit\":8192,"
        "\"native_service_hz\":4,\"native_frames_per_opportunity\":2,"
        "\"native_frames_per_second\":8,\"request_floor_seconds\":20,\"prepared_counts_schema\":1,"
        "\"prepared_dirty_schema\":1,\"recovery_origin_schema\":1,"
        "\"authentication_changed\":false,\"native_counting_preserved\":true,"
        "\"termination_may_lose_tail\":true,\"log_path\":",
        c.header.artifactVersion,c.header.processCreation,c.header.qpcFrequency,
        ModeName(c.config.mode),c.header.configuredMode,c.header.validity,
        DiagnosticsName(c.config.diagnostics),c.config.diagnostics==Diagnostics::Operational ? 60U :
            c.config.diagnostics==Diagnostics::Detailed ? 1U : 10U,
        host,sdk,client,c.log.utcFiletime,c.log.calibrationQpcBefore,c.log.calibrationQpcAfter,
        c.log.volumeSerial,fileId,c.log.initialEOF,c.log.initialAtLineBoundary,c.log.prefixMode);
    json.Path(c.log);
    if (c.config.diagnostics==Diagnostics::Operational)
        json.Append(",\"operational_fields_schema\":1,\"qualification_evidence\":false,"
            "\"recovery_detail_post_terminal_pairs\":4,\"recovery_detail_deadline_fallback\":true");
    const auto& s=c.startup;
    json.Append(",\"startup\":{\"build_identity\":%u,\"recon_mode\":%u,"
        "\"recon_outcome\":%u,\"recon_reason\":%u,\"recon_qualified\":%u,"
        "\"initialize_result\":%u,\"marker_complete\":%u,\"marker_error\":%u,"
        "\"startup_accepted\":%u}",s.buildIdentity,s.reconMode,s.reconOutcome,s.reconReason,
        s.reconQualified,s.initializeResult,s.markerComplete,s.markerError,s.startupAccepted);
    return json.Finish(bytes);
}
TransportReason PrepareNativeBootstrap(const NativeFormatContext& c,char* ascii,
    std::size_t capacity,wchar_t* wide,std::size_t wideCapacity,std::size_t* bytes) noexcept {
    if (wide && wideCapacity) wide[0]=0;
    if (!FormatNativeBootstrap(c,ascii,capacity,bytes) ||
        !native_log::PrepareMessage(ascii,*bytes,wide,wideCapacity)) {
        Clear(ascii,capacity,bytes);
        return TransportReason::FramingUnsupported;
    }
    return TransportReason::None;
}
bool FormatNativeRecord(const NativeFormatContext& c,const ReportRecordV3& record,
    char* output,std::size_t capacity,std::size_t* bytes,bool recoveryDetail) noexcept {
    Clear(output,capacity,bytes);
    if (!output || !capacity || !bytes || !record.header.sequence ||
        record.header.kind<1 || record.header.kind>=static_cast<std::uint32_t>(RecordKindV3::Count))
        return false;
    if (record.header.kind == static_cast<std::uint32_t>(RecordKindV3::Recovery) &&
        (record.header.reason || record.header.flags || record.payload.recovery.recordSequence ||
         !RecoveryPayloadValid(record.payload.recovery))) return false;
    constexpr const char* types[]={"","state","request","witness","builder-enter",
        "builder-return","builder-unwind","anchor","transport-summary","control","recovery"};
    static_assert(std::size(types) == static_cast<std::size_t>(RecordKindV3::Count));
    Json json(output,capacity);
    if (!Begin(c,json,types[record.header.kind],record.header.sequence,record.header.qpc)) return false;
    json.Append(",\"source_epoch\":%llu,\"binding_epoch\":%llu,\"kind\":%u,"
        "\"reason\":%u,\"flags\":%u,\"thread_id\":%u",
        record.header.sourceEpoch,record.header.bindingEpoch,record.header.kind,
        record.header.reason,record.header.flags,record.header.threadId);
    const auto scalar=[&json](const char* name,std::uint64_t value) noexcept {
        json.Append(",\"%s\":%llu",name,value);
    };
    const auto kind=static_cast<RecordKindV3>(record.header.kind);
    if (c.config.diagnostics==Diagnostics::Operational) {
        const bool compactKind=kind==RecordKindV3::State || kind==RecordKindV3::BuilderEnter ||
            kind==RecordKindV3::BuilderReturn || kind==RecordKindV3::BuilderUnwind ||
            kind==RecordKindV3::Anchor || kind==RecordKindV3::TransportSummary;
        json.Append(",\"detail\":\"%s\"",!recoveryDetail && compactKind ? "operational" : "full");
        if (!recoveryDetail && compactKind) {
            // Text-only projection: the scalar record, sequence, digest and
            // native receipt remain intact. Never use this subset to qualify timing.
            if (kind==RecordKindV3::State) {
                const auto& p=record.payload.state;
                scalar("phase",p.phase);scalar("mode",p.mode);scalar("bound",p.bound);
                scalar("pi",p.pi);scalar("bots",p.bots);scalar("maximum",p.maximum);
            } else if (kind==RecordKindV3::Anchor) {
                const auto& p=record.payload.anchor;
                scalar("normal_attempts",p.normalAttempts);scalar("normal_returns",p.normalReturns);
                scalar("native_unwinds",p.nativeUnwinds);scalar("build_sequence",p.buildSequence);
            } else if (kind==RecordKindV3::TransportSummary) {
                const auto& p=record.payload.transport;
                scalar("transport_state",p.transportState);scalar("transport_reason",p.transportReason);
                scalar("generated_sequence",p.generatedSequence);scalar("submitted_sequence",p.submittedSequence);
                scalar("observed_sequence",p.observedSequence);
            } else {
                const auto& p=record.payload.builder;
                scalar("build_sequence",p.buildSequence);scalar("pi",p.pi);scalar("bots",p.bots);
                scalar("maximum",p.maximum);scalar("classification",p.classification);
                scalar("selected",p.selected);scalar("result",p.result);
                scalar("prepared_valid",p.preparedValid);
                if (p.preparedValid==1) scalar("prepared_mismatch_mask",p.preparedMismatchMask);
            }
            return json.Finish(bytes);
        }
    }
    switch (kind) {
    case RecordKindV3::State: {
        const auto& p = record.payload.state;
        scalar("phase",p.phase); scalar("request_sequence",p.requestSequence);
        scalar("witness_sequence",p.witnessSequence); scalar("build_sequence",p.buildSequence);
        scalar("pending_since_qpc",p.pendingSinceQpc); scalar("fresh_since_qpc",p.freshSinceQpc);
        scalar("qualification_flags",p.qualificationFlags); scalar("native_task_state",p.nativeTaskState);
        scalar("client_qualification_ms",p.clientQualificationMs);
        scalar("native_schedule_valid",p.nativeScheduleValid);
        scalar("native_schedule_anchor_bits",p.nativeScheduleAnchorBits);
        scalar("native_errors_bits",p.nativeErrorsBits); scalar("native_throttles_bits",p.nativeThrottlesBits);
        scalar("native_expedite",p.nativeExpedite); scalar("native_retry_limit",p.nativeRetryLimit);
        scalar("native_interval_units",p.nativeIntervalUnits);
        scalar("native_interval_override_bits",p.nativeIntervalOverrideBits);
        scalar("native_retry_override_bits",p.nativeRetryOverrideBits);
        scalar("native_delay_units",p.nativeDelayUnits); scalar("native_tier",p.nativeTier);
        scalar("mode",p.mode); scalar("classification",p.classification);
        scalar("pi",p.pi); scalar("bots",p.bots); scalar("maximum",p.maximum);
        scalar("pending",p.pending); scalar("fresh",p.fresh); scalar("bound",p.bound);
        break;
    }
    case RecordKindV3::Request: case RecordKindV3::Witness: {
        const auto& p = record.payload.request;
        scalar("request_sequence",p.requestSequence); scalar("witness_sequence",p.witnessSequence);
        scalar("staged_qpc",p.stagedQpc); scalar("previous_sample_qpc",p.previousSampleQpc);
        scalar("observed_qpc",p.observedQpc); scalar("fresh_since_qpc",p.freshSinceQpc);
        scalar("source_age_ticks",p.sourceAgeTicks); scalar("pi",p.pi); scalar("bots",p.bots);
        scalar("maximum",p.maximum); scalar("staged_bots",p.stagedBots);
        scalar("human_players",p.humanPlayers); scalar("world_bots",p.worldBots);
        scalar("classification",p.classification); scalar("pending",p.pending);
        break;
    }
    case RecordKindV3::BuilderEnter: case RecordKindV3::BuilderReturn: case RecordKindV3::BuilderUnwind: {
        const auto& p = record.payload.builder;
        scalar("build_sequence",p.buildSequence); scalar("request_sequence",p.requestSequence);
        scalar("witness_sequence",p.witnessSequence); scalar("source_age_ticks",p.sourceAgeTicks);
        scalar("probe_elapsed_ticks",p.probeElapsedTicks);
        scalar("classification_elapsed_ticks",p.classificationElapsedTicks);
        scalar("original_elapsed_ticks",p.originalElapsedTicks);
        scalar("entry_qpc",p.entryQpc); scalar("return_qpc",p.returnQpc);
        scalar("pi",p.pi); scalar("bots",p.bots); scalar("maximum",p.maximum);
        scalar("classification",p.classification); scalar("selected",p.selected);
        scalar("result",p.result); scalar("pending",p.pending); scalar("fresh",p.fresh);
        scalar("prepared_valid",p.preparedValid);
        if (p.preparedValid==1) {
            scalar("prepared_mismatch_mask",p.preparedMismatchMask);
            scalar("prepared_maximum",p.preparedMaximum); scalar("prepared_members",p.preparedMembers);
            scalar("prepared_pi",p.preparedPi); scalar("prepared_bots",p.preparedBots);
            scalar("prepared_json_maximum",p.preparedJsonMaximum); scalar("prepared_json_bytes",p.preparedJsonBytes);
        }
        scalar("prepared_dirty_valid",p.preparedDirtyValid);
        if (p.preparedDirtyValid==1) scalar("prepared_dirty_at_entry",p.preparedDirtyAtEntry);
        break;
    }
    case RecordKindV3::Anchor: {
        // This is an owner-produced scalar copy. Never borrow status.owner or
        // infer a fresh anchor from mutable live owner fields on this worker.
        const auto& p = record.payload.anchor;
        scalar("normal_attempts",p.normalAttempts); scalar("full_selected",p.fullSelected);
        scalar("selected_true",p.selectedTrue); scalar("normal_returns",p.normalReturns);
        scalar("false_returns",p.falseReturns); scalar("native_unwinds",p.nativeUnwinds);
        scalar("request_sequence",p.requestSequence); scalar("witness_sequence",p.witnessSequence);
        scalar("build_sequence",p.buildSequence);
        scalar("distinct_selected_witnesses",p.distinctSelectedWitnesses);
        json.Append(",\"durations\":[");
        for (std::size_t i=0; i<reporting::kStatusDurationClasses; ++i) {
            const auto& duration=p.durations[i];
            json.Append("%s{\"class\":%u,\"calls\":%llu,\"elapsed_ticks\":%llu,"
                "\"maximum_ticks\":%llu,\"over_five_milliseconds\":%llu}",
                i ? "," : "", static_cast<unsigned>(i), duration.calls, duration.elapsedTicks,
                duration.maximumTicks, duration.overFiveMilliseconds);
        }
        json.Append("]"); break;
    }
    case RecordKindV3::TransportSummary: {
        const auto& p=record.payload.transport;
        scalar("anchor_sequence",p.anchorSequence);
        scalar("native_submit_calls",p.nativeSubmitCalls);
        scalar("native_submit_elapsed_ticks",p.nativeSubmitElapsedTicks);
        scalar("native_submit_maximum_ticks",p.nativeSubmitMaximumTicks);
        scalar("native_submit_over_five_milliseconds",p.nativeSubmitOverFiveMilliseconds);
        scalar("forwarded_pump_without_capture",p.forwardedPumpWithoutCapture);
        scalar("forwarded_builder_without_capture",p.forwardedBuilderWithoutCapture);
        scalar("transport_state",p.transportState); scalar("transport_reason",p.transportReason);
        scalar("pause_epoch",p.pauseEpoch); scalar("pause_boundary_sequence",p.pauseBoundarySequence);
        scalar("submitted_sequence",p.submittedSequence); scalar("observed_sequence",p.observedSequence);
        scalar("timing_accounted_through_qpc",p.timingAccountedThroughQpc);
        scalar("generated_sequence",p.generatedSequence); break;
    }
    case RecordKindV3::Control: {
        const auto& p=record.payload.control;
        scalar("event",p.event); scalar("transport_state",p.transportState);
        scalar("transport_reason",p.transportReason); scalar("pause_epoch",p.pauseEpoch);
        scalar("pause_boundary_sequence",p.pauseBoundarySequence);
        scalar("abandoned_pending_request",p.abandonedPendingRequest);
        scalar("abandoned_witness",p.abandonedWitness); scalar("last_request_qpc",p.lastRequestQpc);
        scalar("generated_before",p.generatedBefore); scalar("submitted_before",p.submittedBefore);
        scalar("observed_before",p.observedBefore);
        scalar("forwarded_pump_without_capture",p.forwardedPumpWithoutCapture);
        scalar("forwarded_builder_without_capture",p.forwardedBuilderWithoutCapture);
        scalar("timing_accounted_through_qpc",p.timingAccountedThroughQpc); break;
    }
    case RecordKindV3::Recovery: {
        const auto& p = record.payload.recovery;
        scalar("recovery_phase", p.phase); scalar("recovery_event", p.event);
        scalar("recovery_reason", p.reason); scalar("recovery_outcome", p.outcome); scalar("recovery_flags", p.flags);
        scalar("recovery_request_origin", !p.operationSequence ? 0ULL :
            ((p.flags & RecoveryConsoleRequested) ? 2ULL : 1ULL));
        scalar("recovery_operation_sequence", p.operationSequence); scalar("recovery_transition_sequence", p.transitionSequence);
        scalar("recovery_qpc", p.qpc); scalar("recovery_source_epoch", p.sourceEpoch); scalar("recovery_sdk_epoch", p.sdkEpoch);
        scalar("recovery_owner_thread_id", p.ownerThreadId); scalar("recovery_resource_phase", p.resourcePhase);
        scalar("recovery_native_stage", p.nativeStage); scalar("recovery_exception_code", p.exceptionCode);
        scalar("recovery_request_id", p.requestId); scalar("recovery_callback_id", p.callbackId);
        scalar("recovery_callback_result", p.callbackResult); scalar("recovery_api_returned_id", p.apiReturnedId);
        scalar("recovery_old_sdk_fingerprint", p.oldSdkFingerprint); scalar("recovery_new_sdk_fingerprint", p.newSdkFingerprint);
        scalar("recovery_old_cache_fingerprint", p.oldCacheFingerprint); scalar("recovery_new_cache_fingerprint", p.newCacheFingerprint);
        scalar("recovery_finish_deadline_qpc", p.finishDeadlineQpc); scalar("recovery_overall_deadline_qpc", p.overallDeadlineQpc);
        scalar("recovery_record_sequence", p.recordSequence); scalar("recovery_callback_own_ticks", p.callbackOwnTicks);
        break;
    }
    case RecordKindV3::Count: break;
    }
    return json.Finish(bytes);
}
} // namespace rs2fix::reporting
