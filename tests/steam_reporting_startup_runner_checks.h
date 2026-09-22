// Included only inside startup_runner.cpp's anonymous namespace for the
// reporting build. Reuses its qualified copies, CreateNew files and child I/O.
namespace report=rs2fix::reporting;
struct ReportExpected {
    bool healthy;
    bool writer;
    report::Mode mode;
    report::Reason reason;
};
ReportExpected ReportExpectation(unsigned scenario) {
    switch (scenario) {
    case 0: return {true,true,report::Mode::Observe,report::Reason::None};
    case 1: case 13: return {true,true,report::Mode::Repair,report::Reason::None};
    case 2: return {false,false,report::Mode::Invalid,report::Reason::ConfigMissing};
    case 3: return {false,false,report::Mode::Disabled,report::Reason::ConfigDisabled};
    case 4: return {false,false,report::Mode::Invalid,report::Reason::ConfigInvalid};
    case 5: return {false,false,report::Mode::Repair,report::Reason::ObserverRequired};
    case 6: case 12: return {false,false,report::Mode::Repair,report::Reason::SdkMismatch};
    case 7: return {false,false,report::Mode::Repair,report::Reason::WriterFailed};
    case 8: case 9: return {false,true,report::Mode::Repair,report::Reason::SteamClientMismatch};
    case 10: return {false,true,report::Mode::Repair,report::Reason::InitFailed};
    case 11: return {false,false,report::Mode::Repair,report::Reason::ReconIneligible};
    default: return {false,false,report::Mode::Invalid,report::Reason::PreparationFailed};
    }
}
bool AppendOwnOverlay(const std::wstring& path,const char* marker) {
    // The caller has just hash-verified a fresh copy into this own scenario.
    // Only its disposable overlay changes, never the qualified source artifact.
    const HANDLE file=CreateFileW(path.c_str(),FILE_APPEND_DATA,0,nullptr,OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if (file==INVALID_HANDLE_VALUE) return false;
    const auto length=std::strlen(marker); DWORD written{};
    const bool ok=length<MAXDWORD && WriteFile(file,marker,static_cast<DWORD>(length),&written,nullptr) &&
        written==length && FlushFileBuffers(file);
    return CloseHandle(file) && ok;
}
bool StageReporting(const Inputs& inputs,const Scenario& scenario,const std::wstring& directory) {
    const auto mode=scenario.reportMode;
    if (!Copy(inputs.sdk,directory,L"rs2_test_steam_api.dll") ||
        !Copy(inputs.client,directory,kFixtureSteamClientLeaf)) return false;
    if (!CreateText(Join(directory,L"RS2SteamObserve.ini"),mode==5 ? "enabled=0\r\n" :
        "enabled=1\r\nmax_log_mib=16\r\n")) return false;
    if (mode!=2) {
        const char* config=mode==0 ? "schema=2\r\nmode=observe\r\n" :
            mode==3 ? "schema=2\r\nmode=disabled\r\n" : mode==4 ? "schema=2\r\nmode=repair\r\nmode=repair\r\n" :
            "schema=2\r\nmode=repair\r\n";
        if (!CreateText(Join(directory,L"RS2SteamReport.ini"),config)) return false;
    }
    if (mode==6 && !AppendOwnOverlay(Join(directory,L"rs2_test_steam_api.dll"),"owned-reporting-sdk-overlay")) return false;
    if (mode==9 && !AppendOwnOverlay(Join(directory,kFixtureSteamClientLeaf),"owned-reporting-client-overlay")) return false;
    if (mode==7 && !CreateText(Join(directory,L"RS2SteamReport"),"owned-obstruction")) return false;
    return true;
}
bool UnsignedText(const std::string& text,std::uint64_t* value) {
    if (text.empty()) return false;
    *value=0;
    for (const auto ch:text) {
        if (ch<'0' || ch>'9') return false;
        const auto digit=static_cast<unsigned>(ch-'0');
        if (*value>(UINT64_MAX-digit)/10) return false;
        *value=*value*10+digit;
    }
    return true;
}
bool OutputFields(const std::string& output,const char* prefix,std::map<std::string,std::string>* fields) {
    const auto at=output.find(prefix);
    if (at==output.npos || (at && output[at-1]!='\n') || output.find(prefix,at+std::strlen(prefix))!=output.npos) return false;
    const auto end=output.find('\n',at);
    if (end==output.npos) return false;
    const auto limit=end>at && output[end-1]=='\r' ? end-1 : end;
    auto cursor=at;
    while (cursor<limit) {
        const auto next=output.find(' ',cursor);
        const auto last=next==output.npos || next>limit ? limit : next;
        const auto equals=output.find('=',cursor);
        if (equals==output.npos || equals<=cursor || equals>=last ||
            !fields->emplace(output.substr(cursor,equals-cursor),output.substr(equals+1,last-equals-1)).second) return false;
        cursor=last+1;
    }
    return true;
}
bool FieldUnsigned(const std::map<std::string,std::string>& fields,const char* name,std::uint64_t* value) {
    const auto found=fields.find(name);
    return found!=fields.end() && UnsignedText(found->second,value);
}
bool FieldEquals(const std::map<std::string,std::string>& fields,const char* name,const char* expected) {
    const auto found=fields.find(name); return found!=fields.end() && found->second==expected;
}
struct FixtureTiming {
    std::uint64_t frequency{},pumpCount{},builderCount{},selectedCount{},pumpMaximum{},builderMaximum{};
    std::uint64_t windowStart{},windowEnd{},windowTicks{},pumpOwn{},pumpCorrected{};
    std::uint64_t calibrationStart{},calibrationEnd{},calibrationTicks{},mainCount{},mainManagement{},ordinalCount{};
    report::DurationCounters classes[report::kStatusDurationClasses]{};
    report::DurationCounters mainClasses[report::kStatusDurationClasses]{};
    std::uint64_t auxiliaryCalls[report::kStatusDurationClasses]{},auxiliaryTicks[report::kStatusDurationClasses]{};
    std::uint64_t residualCount[report::kStatusDurationClasses]{},residualSum[report::kStatusDurationClasses]{};
    std::uint64_t residualMaximum[report::kStatusDurationClasses]{};
    bool eligible[report::kStatusDurationClasses]{};
    bool coverage{},rawAggregate{},correctedAggregate{},classLimits{},candidate{};
};
bool TimingAdd(std::uint64_t& total,std::uint64_t value) {
    if (value>UINT64_MAX-total) return false;
    total+=value; return true;
}
bool TimingOrdinals(const Child& child,const FixtureTiming& timing) {
    report::DurationCounters all[4]{},main[4]{};
    std::uint64_t residual[4]{},maxima[4]{},auxCalls[4]{},auxTicks[4]{};
    std::uint64_t previousPumpAfter{},priorPumpAfter{},currentPumpBefore{},previousBuilderAfter{};
    std::size_t cursor=0;
    const std::string prefix="report_timing_ordinal=";
    for (std::uint64_t index=0;index<8050;++index) {
        const auto at=child.output.find(prefix,cursor),end=child.output.find('\n',at);
        if (at==child.output.npos || (at && child.output[at-1]!='\n') || end==child.output.npos) return false;
        cursor=end+1;
        std::map<std::string,std::string> values;
        std::uint64_t recorded{},ordinal{},call{},outerBefore{},outerAfter{},innerBefore{},innerAfter{},kind{},own{},missing{};
        const bool selected=index>=6003 && (index-6003)%2==0;
        const bool tail=index==8048;
        const auto expectedOrdinal=index<=6001 ? index : 6002+(index-6002)/2;
        const auto expectedCall=selected ? 6+(index-6003)/2 : 5+expectedOrdinal;
        const char* role=index==0 ? "warmup" : (index<=6000 ? "main" :
            (index==6001 ? "bridge" : (selected ? "selected" : "support")));
        if (!OutputFields(child.output.substr(at,end-at+1),prefix.c_str(),&values) || values.size()!=13 ||
            !FieldUnsigned(values,"report_timing_ordinal",&recorded) || recorded!=index ||
            !FieldEquals(values,"role",role) || !FieldUnsigned(values,"ordinal",&ordinal) || ordinal!=expectedOrdinal ||
            !FieldUnsigned(values,"native_call",&call) || call!=expectedCall ||
            !FieldUnsigned(values,"outer_before",&outerBefore) || !outerBefore ||
            !FieldUnsigned(values,"outer_after",&outerAfter) || outerAfter<outerBefore || outerAfter>INT64_MAX ||
            !FieldUnsigned(values,"inner_before",&innerBefore) || innerBefore<outerBefore ||
            !FieldUnsigned(values,"inner_after",&innerAfter) || innerAfter<innerBefore || innerAfter>outerAfter ||
            !FieldUnsigned(values,"duration_class",&kind) || kind>3 ||
            !FieldUnsigned(values,"own_ticks",&own) || !FieldUnsigned(values,"residual_ticks",&missing)) return false;
        if (index && (outerBefore<timing.calibrationStart || outerAfter>timing.calibrationEnd)) return false;
        if (!selected) {
            if (outerBefore<previousPumpAfter) return false;
            priorPumpAfter=previousPumpAfter;
            previousPumpAfter=outerAfter; currentPumpBefore=outerBefore;
            if (index==1 && outerBefore!=timing.windowStart) return false;
            if (index==6000 && outerAfter!=timing.windowEnd) return false;
            if (tail && outerAfter!=timing.calibrationEnd) return false;
        } else {
            if (outerAfter>currentPumpBefore || outerBefore<previousBuilderAfter || outerBefore<priorPumpAfter) return false;
            previousBuilderAfter=outerAfter;
        }
        if (!index || tail) {
            if (!FieldEquals(values,"state","unpaired") || !FieldEquals(values,"reason",
                !index ? "warmup-outside-protocol" : "final-support-not-published") ||
                (tail && (kind || own || missing))) return false;
            continue;
        }
        const auto wall=outerAfter-outerBefore,inner=innerAfter-innerBefore;
        if (!FieldEquals(values,"state","paired") || !FieldEquals(values,"reason","none") ||
            (selected ? kind!=3 : kind>1) || own>wall || inner>wall-own || missing!=wall-own-inner) return false;
        auto& a=all[kind];
        if (!TimingAdd(a.calls,1) || !TimingAdd(a.elapsedTicks,own) ||
            !TimingAdd(a.overFiveMilliseconds,own>timing.frequency/200 ? 1U : 0U) ||
            !TimingAdd(residual[kind],missing)) return false;
        a.maximumTicks=(std::max)(a.maximumTicks,own); maxima[kind]=(std::max)(maxima[kind],missing);
        if (index<=6000) {
            auto& m=main[kind];
            if (!TimingAdd(m.calls,1) || !TimingAdd(m.elapsedTicks,own) ||
                !TimingAdd(m.overFiveMilliseconds,own>timing.frequency/200 ? 1U : 0U)) return false;
            m.maximumTicks=(std::max)(m.maximumTicks,own);
        } else if (!selected && (!TimingAdd(auxCalls[kind],1) || !TimingAdd(auxTicks[kind],own))) return false;
    }
    if (child.output.find(prefix,cursor)!=child.output.npos) return false;
    for (std::size_t i=0;i<4;++i) {
        const auto& a=all[i]; const auto& expected=timing.classes[i];
        const auto& m=main[i]; const auto& expectedMain=timing.mainClasses[i];
        if (a.calls!=expected.calls || a.elapsedTicks!=expected.elapsedTicks || a.maximumTicks!=expected.maximumTicks ||
            a.overFiveMilliseconds!=expected.overFiveMilliseconds || m.calls!=expectedMain.calls ||
            m.elapsedTicks!=expectedMain.elapsedTicks || m.maximumTicks!=expectedMain.maximumTicks ||
            m.overFiveMilliseconds!=expectedMain.overFiveMilliseconds || residual[i]!=timing.residualSum[i] ||
            maxima[i]!=timing.residualMaximum[i] || auxCalls[i]!=timing.auxiliaryCalls[i] || auxTicks[i]!=timing.auxiliaryTicks[i]) return false;
    }
    return true;
}
bool ReadFixtureTiming(const Child& child,std::uint64_t frequency,FixtureTiming* timing) {
    std::map<std::string,std::string> fields;
    if (!timing || !frequency || frequency>static_cast<std::uint64_t>(INT64_MAX)/45 ||
        !OutputFields(child.output,"report_timing=",&fields) || !FieldEquals(fields,"report_timing","pass") ||
        !FieldEquals(fields,"failure_reason","none") ||
        !FieldEquals(fields,"measurement_id","rs2-wrapper-own-deferred-v2") ||
        !FieldEquals(fields,"protocol_id","rs2-deferred-v2-fixed6000-1024") ||
        !FieldEquals(fields,"envelope","outer-wrapper-minus-recorded-own-minus-inner-original") ||
        !FieldEquals(fields,"inner_original_pairs","exact-call-checked") ||
        !FieldEquals(fields,"residual_bound","empirical-not-wcrt") ||
        !FieldEquals(fields,"candidate_scope","coverage-raw-main-pump-and-per-class-smoke") ||
        !FieldEquals(fields,"production_full_window","unqualified") ||
        !FieldEquals(fields,"builder_includes_pump_envelope","false") ||
        !FieldEquals(fields,"builder_stress_full_window_qualified","false") ||
        !FieldEquals(fields,"pump_bridge_calls","1") || !FieldEquals(fields,"pump_duration_lag","1") ||
        !FieldEquals(fields,"builder_duration_lag","0") ||
        !FieldUnsigned(fields,"qpc_frequency",&timing->frequency) || timing->frequency!=frequency ||
        !FieldUnsigned(fields,"pump_sample_count",&timing->pumpCount) || timing->pumpCount!=7024 ||
        !FieldUnsigned(fields,"main_pump_sample_count",&timing->mainCount) || timing->mainCount!=6000 ||
        !FieldUnsigned(fields,"main_management_sample_count",&timing->mainManagement) || timing->mainManagement>6000 ||
        !FieldUnsigned(fields,"ordinal_count",&timing->ordinalCount) || timing->ordinalCount!=8050 ||
        !FieldUnsigned(fields,"builder_sample_count",&timing->builderCount) || timing->builderCount!=1024 ||
        !FieldUnsigned(fields,"builder_selected_count",&timing->selectedCount) || timing->selectedCount!=1024 ||
        !FieldUnsigned(fields,"pump_maximum_missing_ticks",&timing->pumpMaximum) ||
        !FieldUnsigned(fields,"builder_maximum_missing_ticks",&timing->builderMaximum) ||
        !FieldUnsigned(fields,"calibration_start_qpc",&timing->calibrationStart) || !timing->calibrationStart ||
        !FieldUnsigned(fields,"calibration_end_qpc",&timing->calibrationEnd) ||
        timing->calibrationEnd<=timing->calibrationStart || timing->calibrationEnd>INT64_MAX ||
        !FieldUnsigned(fields,"calibration_ticks",&timing->calibrationTicks) ||
        timing->calibrationTicks!=timing->calibrationEnd-timing->calibrationStart ||
        !FieldUnsigned(fields,"pump_window_start_qpc",&timing->windowStart) ||
        !FieldUnsigned(fields,"pump_window_end_qpc",&timing->windowEnd) || timing->windowEnd<=timing->windowStart ||
        !FieldUnsigned(fields,"pump_window_ticks",&timing->windowTicks) ||
        timing->windowTicks!=timing->windowEnd-timing->windowStart ||
        timing->windowStart!=timing->calibrationStart || timing->windowEnd>timing->calibrationEnd ||
        !FieldUnsigned(fields,"pump_own_ticks",&timing->pumpOwn) ||
        !FieldUnsigned(fields,"pump_corrected_ticks",&timing->pumpCorrected))
        return false;
    std::uint64_t pumpCalls{},builderCalls{},mainCalls{},mainOwn{},auxiliaryCalls{},allOwn{},allResidual{};
    std::uint64_t corrected=timing->pumpOwn,pumpMaximum{},builderMaximum{};
    timing->classLimits=true;
    for (std::size_t i=0;i<report::kStatusDurationClasses;++i) {
        std::map<std::string,std::string> values;
        const auto key="report_timing_class"+std::to_string(i),prefix=key+"=";
        auto& c=timing->classes[i];
        auto& m=timing->mainClasses[i];
        if (!OutputFields(child.output,prefix.c_str(),&values) ||
            !FieldUnsigned(values,"calls",&c.calls) || c.calls>(i<2 ? 7024U : 1024U) ||
            !FieldUnsigned(values,"elapsed_ticks",&c.elapsedTicks) || c.elapsedTicks>timing->calibrationTicks ||
            !FieldUnsigned(values,"maximum_ticks",&c.maximumTicks) || c.maximumTicks>c.elapsedTicks ||
            !FieldUnsigned(values,"over_five_milliseconds",&c.overFiveMilliseconds) || c.overFiveMilliseconds>c.calls ||
            !FieldUnsigned(values,"residual_sample_count",&timing->residualCount[i]) || timing->residualCount[i]!=c.calls ||
            !FieldUnsigned(values,"residual_sum_ticks",&timing->residualSum[i]) || timing->residualSum[i]>timing->calibrationTicks ||
            !FieldUnsigned(values,"residual_maximum_ticks",&timing->residualMaximum[i]) ||
            timing->residualMaximum[i]>timing->residualSum[i] ||
            !FieldUnsigned(values,"main_calls",&m.calls) || m.calls>c.calls ||
            !FieldUnsigned(values,"main_elapsed_ticks",&m.elapsedTicks) || m.elapsedTicks>c.elapsedTicks ||
            !FieldUnsigned(values,"main_maximum_ticks",&m.maximumTicks) || m.maximumTicks>m.elapsedTicks || m.maximumTicks>c.maximumTicks ||
            !FieldUnsigned(values,"main_over_five_milliseconds",&m.overFiveMilliseconds) ||
            m.overFiveMilliseconds>m.calls || m.overFiveMilliseconds>c.overFiveMilliseconds ||
            !FieldUnsigned(values,"auxiliary_calls",&timing->auxiliaryCalls[i]) ||
            !FieldUnsigned(values,"auxiliary_elapsed_ticks",&timing->auxiliaryTicks[i]) ||
            (!c.calls && (c.elapsedTicks || c.maximumTicks || c.overFiveMilliseconds)) ||
            (!m.calls && (m.elapsedTicks || m.maximumTicks || m.overFiveMilliseconds)) ||
            (!c.calls && (timing->residualSum[i] || timing->residualMaximum[i])) ||
            !FieldEquals(values,"eligible",c.calls ? "true" : "false") ||
            !FieldEquals(values,key.c_str(),c.calls ? "observed" : "unobserved")) return false;
        timing->eligible[i]=c.calls!=0;
        const bool pass=i<2 ? c.overFiveMilliseconds<=c.calls/100 : c.maximumTicks<=frequency/200;
        if (!FieldEquals(values,"limit",pass ? "pass" : "fail")) return false;
        timing->classLimits=timing->classLimits && pass;
        if (i<2) {
            if (c.calls-m.calls!=timing->auxiliaryCalls[i] || c.elapsedTicks-m.elapsedTicks!=timing->auxiliaryTicks[i] ||
                (!timing->auxiliaryCalls[i] && timing->auxiliaryTicks[i]) ||
                !TimingAdd(pumpCalls,c.calls) || !TimingAdd(mainCalls,m.calls) || !TimingAdd(mainOwn,m.elapsedTicks) ||
                !TimingAdd(auxiliaryCalls,timing->auxiliaryCalls[i]) ||
                (m.calls && timing->residualMaximum[i]>UINT64_MAX/m.calls) ||
                !TimingAdd(corrected,m.calls*timing->residualMaximum[i])) return false;
            pumpMaximum=(std::max)(pumpMaximum,timing->residualMaximum[i]);
        } else {
            if (m.calls || m.elapsedTicks || timing->auxiliaryCalls[i] || timing->auxiliaryTicks[i] ||
                !TimingAdd(builderCalls,c.calls)) return false;
            builderMaximum=(std::max)(builderMaximum,timing->residualMaximum[i]);
        }
        if (!TimingAdd(allOwn,c.elapsedTicks) || !TimingAdd(allResidual,timing->residualSum[i])) return false;
    }
    if (pumpCalls!=7024 || builderCalls!=1024 || mainCalls!=6000 || mainOwn!=timing->pumpOwn || auxiliaryCalls!=1024 ||
        timing->mainManagement!=timing->mainClasses[1].calls || mainOwn>timing->windowTicks ||
        allOwn>timing->calibrationTicks || allResidual>timing->calibrationTicks-allOwn ||
        timing->classes[2].calls || timing->classes[3].calls!=1024 ||
        corrected!=timing->pumpCorrected || pumpMaximum!=timing->pumpMaximum || builderMaximum!=timing->builderMaximum) return false;
    timing->coverage=timing->mainManagement>=64;
    timing->classLimits=timing->classLimits && timing->classes[1].calls && timing->classes[3].calls;
    timing->rawAggregate=timing->pumpOwn<=(timing->windowTicks-1)/1000;
    timing->correctedAggregate=timing->pumpCorrected<=(timing->windowTicks-1)/1000;
    timing->candidate=timing->coverage && timing->rawAggregate && timing->classLimits;
    if (!FieldEquals(fields,"coverage_pass",timing->coverage ? "true" : "false") ||
        !FieldEquals(fields,"pump_raw_aggregate",timing->rawAggregate ? "pass" : "fail") ||
        !FieldEquals(fields,"pump_corrected_aggregate",timing->correctedAggregate ? "pass" : "fail") ||
        !FieldEquals(fields,"sample_class_limits",timing->classLimits ? "pass" : "fail") ||
        !FieldEquals(fields,"calibration_candidate",timing->candidate ? "pass" : "fail")) return false;
    return TimingOrdinals(child,*timing);
}
bool HexString(const std::string& text,std::size_t length) {
    return text.size()==length && std::all_of(text.begin(),text.end(),[](char ch) {
        return (ch>='0' && ch<='9') || (ch>='a' && ch<='f');
    });
}
std::string LowerDigest(const rs2fix::Sha256Digest& digest) {
    std::string text=rs2fix::FormatSha256Upper(digest).data();
    for (auto& ch:text) if (ch>='A' && ch<='F') ch=static_cast<char>(ch+('a'-'A'));
    return text;
}
bool JsonText(const std::string& line,const char* key,std::string* value) {
    const auto prefix=std::string("\"")+key+"\":\"";
    const auto start=line.find(prefix);
    if (start==line.npos || line.find(prefix,start+prefix.size())!=line.npos) return false;
    const auto at=start+prefix.size(),end=line.find('"',at);
    if (end==line.npos || end+1>=line.size() || (line[end+1]!=',' && line[end+1]!='}')) return false;
    *value=line.substr(at,end-at);
    return value->find('\\')==value->npos; // Only bounded scalar tags/hashes, not arbitrary JSON strings.
}
bool ReportingLogEvidence(const Inputs& inputs,const Scenario& scenario,const Child& child,
    const std::wstring& directory,const std::map<std::string,std::string>& before,
    const std::map<std::string,std::string>& after) {
    const auto expected=ReportExpectation(scenario.reportMode);
    const auto resultRoot=Join(directory,L"RS2SteamReport");
    if (!Absent(Join(directory,L"RS2SteamObserve")) || !Absent(Join(directory,L"RS2SteamObserveKeys"))) return false;
    if (!expected.writer) {
        if (scenario.reportMode!=7) return Absent(resultRoot);
        std::string obstruction;
        return Read(resultRoot,&obstruction,64) && obstruction=="owned-obstruction";
    }
    const auto run=before.find("run_id");
    if (run==before.end() || !HexString(run->second,32)) return false;
    const auto attributes=GetFileAttributesW(resultRoot.c_str());
    if (attributes==INVALID_FILE_ATTRIBUTES || !(attributes&FILE_ATTRIBUTE_DIRECTORY) || (attributes&FILE_ATTRIBUTE_REPARSE_POINT)) return false;
    std::error_code error; std::filesystem::directory_iterator runs(resultRoot,error);
    if (error) return false;
    std::wstring runDirectory;
    for (const auto& candidate:runs) {
        const auto path=candidate.path().wstring();
        const auto attr=GetFileAttributesW(path.c_str());
        if (!runDirectory.empty() || attr==INVALID_FILE_ATTRIBUTES || !(attr&FILE_ATTRIBUTE_DIRECTORY) ||
            (attr&FILE_ATTRIBUTE_REPARSE_POINT)) return false;
        runDirectory=path;
    }
    const std::wstring runWide(run->second.begin(),run->second.end());
    const auto suffix=L"-PID"+std::to_wstring(child.pid)+L"-"+runWide;
    if (runDirectory.size()<suffix.size() || runDirectory.substr(runDirectory.size()-suffix.size())!=suffix) return false;
    std::string bytes;
    const std::size_t logLimit=scenario.reportMode==13 ? 16*1024*1024 : 1024*1024;
    if (!Read(Join(runDirectory,L"events.jsonl"),&bytes,logLimit) || bytes.empty() || bytes.back()!='\n') return false;
    for (const auto* forbidden:{"steam_token","steamId","caller_rva","registration","payload", "endpoint", ".key",
        "1234605616436508552","1122334455667788"}) if (bytes.find(forbidden)!=bytes.npos) return false;
    std::uint64_t creation{},frequency{},normalAttempts{},fullSelected{},selectedTrue{},written{},flushed{},expectedRequests{},expectedWitnesses{};
    if (!FieldUnsigned(before,"process_creation",&creation) || !FieldUnsigned(before,"qpc_frequency",&frequency) ||
        !FieldUnsigned(before,"normalAttempts",&normalAttempts) || !FieldUnsigned(before,"fullSelected",&fullSelected) ||
        !FieldUnsigned(before,"selectedTrue",&selectedTrue) || !FieldUnsigned(after,"records_written",&written) ||
        !FieldUnsigned(after,"last_flushed_sequence",&flushed) || !FieldUnsigned(before,"request",&expectedRequests) ||
        !FieldUnsigned(before,"witness",&expectedWitnesses)) return false;
    std::uint64_t sequence=0,requests=0,witnesses=0,enters=0,returns=0,selected=0,trueSelected=0,falseSelected=0,anchors=0;
    std::map<std::uint64_t,bool> builders;
    bool startup=false; std::size_t cursor=0;
    while (cursor<bytes.size()) {
        const auto start=cursor;
        const auto end=bytes.find('\n',cursor);
        if (end==bytes.npos || end-cursor>8192) return false;
        const auto line=bytes.substr(cursor,end-cursor); cursor=end+1;
        std::string type,identity; std::uint64_t pid{},schema{};
        if (line.empty() || line.front()!='{' || line.back()!='}' || !JsonText(line,"type",&type) ||
            !JsonText(line,"run_id",&identity) || identity!=run->second || !JsonUnsigned(line,"pid",&pid) || pid!=child.pid ||
            !JsonUnsigned(line,"schema",&schema) || schema!=2) return false;
        if (type=="startup") {
            if (startup || sequence || start!=0) return false;
            startup=true; std::uint64_t recordedCreation{},recordedFrequency{},mode{};
            std::string host,sdk,client,version;
            if (!JsonUnsigned(line,"process_start_filetime",&recordedCreation) || recordedCreation!=creation ||
                !JsonUnsigned(line,"qpc_frequency",&recordedFrequency) || recordedFrequency!=frequency ||
                !JsonUnsigned(line,"configured_mode",&mode) || mode!=static_cast<std::uint32_t>(expected.mode) ||
                !JsonText(line,"version",&version) || version!=inputs.expectedVersion ||
                !JsonText(line,"host_sha256",&host) || host!=LowerDigest(inputs.host.digest) ||
                !JsonText(line,"qualified_steam_api_sha256",&sdk) || sdk!=LowerDigest(inputs.sdk.digest) ||
                !JsonText(line,"qualified_steamclient_sha256",&client) || client!=LowerDigest(inputs.client.digest)) return false;
            continue;
        }
        std::uint64_t current{},qpc{},source{},binding{},kind{},reason{},flags{},thread{};
        if (!startup || sequence==UINT64_MAX || !JsonUnsigned(line,"sequence",&current) || current!=sequence+1 ||
            !JsonUnsigned(line,"qpc",&qpc) || !JsonUnsigned(line,"source_epoch",&source) ||
            !JsonUnsigned(line,"binding_epoch",&binding) || !JsonUnsigned(line,"kind",&kind) ||
            !JsonUnsigned(line,"reason",&reason) || reason>=static_cast<unsigned>(report::Reason::Count) ||
            !JsonUnsigned(line,"flags",&flags) || !JsonUnsigned(line,"thread_id",&thread) || !thread) return false;
        sequence=current;
        if (type=="state") {
            std::uint64_t duration{}; if (kind!=1 || !JsonUnsigned(line,"client_qualification_ms",&duration)) return false;
        } else if (type=="request") {
            if (kind!=2) return false; ++requests;
        } else if (type=="witness") {
            if (kind!=3) return false; ++witnesses;
        } else if (type=="builder-enter" || type=="builder-return") {
            std::uint64_t build{},wasSelected{},result{},count{},bots{},maximum{};
            if (!JsonUnsigned(line,"build_sequence",&build) || !build || !JsonUnsigned(line,"selected",&wasSelected) ||
                wasSelected>1 || !JsonUnsigned(line,"result",&result) || result>1 ||
                !JsonUnsigned(line,"pi",&count) || !JsonUnsigned(line,"bots",&bots) ||
                !JsonUnsigned(line,"maximum",&maximum)) return false;
            if (type=="builder-enter") {
                if (kind!=4 || wasSelected || !builders.emplace(build,false).second) return false;
                ++enters;
            } else {
                const auto entered=builders.find(build);
                if (kind!=5 || entered==builders.end() || entered->second) return false;
                entered->second=true; ++returns;
                if (wasSelected) {
                    if (!source || !binding || count!=65 || bots!=24 || maximum!=64) return false;
                    ++selected; if (result) ++trueSelected; else ++falseSelected;
                }
            }
        } else if (type=="anchor") {
            if (kind!=7) return false; ++anchors;
        } else return false; // Unwinds/unknown records are not successes in these nonthrowing scenarios.
    }
    if (!startup || sequence!=written || flushed!=written || enters!=returns || enters!=normalAttempts ||
        selected!=fullSelected || trueSelected!=selectedTrue || requests!=expectedRequests || witnesses!=expectedWitnesses) return false;
    for (const auto& builder:builders) if (!builder.second) return false;
    if (!expected.healthy) return requests==0 && witnesses==0 && selected==0;
    if (!anchors || !enters) return false;
    if (scenario.reportMode==13) return requests>=1 && witnesses>=1 && selected==1027 && trueSelected==1027 && !falseSelected;
    return scenario.reportMode==0 ? requests==0 && witnesses==0 && selected==0 :
        requests==1 && witnesses==1 && selected==3 && trueSelected==2 && falseSelected==1;
}
bool ReportingEvidence(const Inputs& inputs,const Scenario& scenario,const Child& child,const std::wstring& directory) {
    const auto expected=ReportExpectation(scenario.reportMode);
    const bool calibration=scenario.reportMode==13;
    std::map<std::string,std::string> before,after;
    if (!OutputFields(child.output,"report_fixture=",&before) || !OutputFields(child.output,"report_shutdown=",&after) ||
        !FieldEquals(before,"report_fixture","pass") || !FieldEquals(after,"report_shutdown","pass") ||
        !FieldEquals(before,"status_available","true") || !FieldEquals(after,"status_available","true")) return false;
    std::uint64_t pid{},creation{},frequency{},headerReady{},validity{},mode{},phase{},reason{},revoke{},loss{},requests{},witnesses{};
    std::uint64_t attempts{},selected{},selectedTrue{},builders{},full{},falseBuilds{},consumed{},callbacks{},holders{},clocks{};
    std::uint64_t builderInnerClocks{},pumpInnerClocks{};
    std::uint64_t factories{},inits{},pumps{},loads{},loadFailures{},shutdowns{},unloads{},stopping{},finalPhase{},written{},flushed{};
    if (!FieldUnsigned(before,"pid",&pid) || pid!=child.pid || !FieldUnsigned(before,"header_ready",&headerReady) || headerReady!=1 ||
        !FieldUnsigned(before,"process_creation",&creation) || !creation ||
        !FieldUnsigned(before,"qpc_frequency",&frequency) || !frequency ||
        !FieldUnsigned(before,"header_validity",&validity) || !FieldUnsigned(before,"status_mode",&mode) ||
        mode!=static_cast<std::uint32_t>(expected.mode) || !FieldUnsigned(before,"phase",&phase) ||
        !FieldUnsigned(before,"reason",&reason) || !FieldUnsigned(before,"revoke",&revoke) ||
        !FieldUnsigned(before,"loss",&loss) || !FieldUnsigned(before,"request",&requests) ||
        !FieldUnsigned(before,"witness",&witnesses) || !FieldUnsigned(before,"normalAttempts",&attempts) ||
        !FieldUnsigned(before,"fullSelected",&selected) || !FieldUnsigned(before,"selectedTrue",&selectedTrue) ||
        !FieldUnsigned(before,"builder_calls",&builders) || builders!=(calibration ? 1029U : 5U) || !FieldUnsigned(before,"full_builds",&full) ||
        !FieldUnsigned(before,"false_builds",&falseBuilds) || !FieldUnsigned(before,"producer_consumed",&consumed) ||
        !FieldUnsigned(before,"callback_errors",&callbacks) || callbacks || !FieldUnsigned(before,"holder_errors",&holders) || holders ||
        !FieldUnsigned(before,"clock_errors",&clocks) || clocks ||
        !FieldUnsigned(before,"builder_inner_clock_errors",&builderInnerClocks) || builderInnerClocks ||
        !FieldUnsigned(before,"pump_inner_clock_errors",&pumpInnerClocks) || pumpInnerClocks ||
        !FieldUnsigned(before,"factory_calls",&factories) || !FieldUnsigned(before,"init_calls",&inits) || inits!=1 ||
        !FieldUnsigned(before,"pump_calls",&pumps) || pumps!=(calibration ? 7030U : 5U) || !FieldUnsigned(before,"client_loads",&loads) ||
        !FieldUnsigned(before,"client_load_failures",&loadFailures) || loadFailures ||
        !FieldUnsigned(after,"shutdown_calls",&shutdowns) || shutdowns!=1 ||
        !FieldUnsigned(after,"client_unloads",&unloads) || !FieldUnsigned(after,"stopping",&stopping) ||
        !FieldUnsigned(after,"phase",&finalPhase) || !FieldUnsigned(after,"records_written",&written) ||
        !FieldUnsigned(after,"last_flushed_sequence",&flushed)) return false;
    const bool noClient=scenario.reportMode==8 || scenario.reportMode==10;
    if (loads!=(noClient ? 0U : 1U) || unloads!=loads || factories!=1 ||
        !FieldEquals(before,"init_result",scenario.reportMode==10 ? "false" : "true")) return false;
    const auto run=before.find("run_id");
    if (run==before.end() || !HexString(run->second,32) || run->second==std::string(32,'0')) return false;
    const auto expectedValidity=static_cast<std::uint32_t>((scenario.reportMode==2 || scenario.reportMode==4) ?
        report::CompleteHeaderIdentity&~report::ConfigurationValid : report::CompleteHeaderIdentity);
    if (validity!=expectedValidity) return false;
    FixtureTiming timing{};
    if (calibration && !ReadFixtureTiming(child,frequency,&timing)) return false;
    if (expected.healthy) {
        if (revoke || loss || phase!=static_cast<std::uint64_t>(scenario.reportMode==0 ? report::ReportPhase::Observing : report::ReportPhase::Repairing) ||
            attempts!=(calibration ? 1028U : 4U) || selected!=full || selectedTrue>selected) return false;
        if (scenario.reportMode==0) {
            if (requests || witnesses || selected || full || falseBuilds || consumed) return false;
        } else if (calibration) {
            if (!requests || !witnesses || !consumed || selected!=1027 || selectedTrue!=1027 || falseBuilds) return false;
        } else if (requests!=1 || witnesses!=1 || consumed!=1 || selected!=3 || selectedTrue!=2 || falseBuilds!=1) return false;
        const auto prefix=std::string("[RS2SteamReport] v")+inputs.expectedVersion+"; status=ready; mode="+
            (scenario.reportMode==0 ? "observe" : "repair")+"; reason=none; run_id="+run->second+"; pid="+std::to_string(child.pid);
        if (child.output.find(prefix)==child.output.npos) return false;
    } else {
        const auto bit=1ULL<<static_cast<unsigned>(expected.reason);
        if (reason!=static_cast<unsigned>(expected.reason) || revoke!=bit || requests || witnesses ||
            attempts || selected || selectedTrue || full || falseBuilds || consumed ||
            phase!=static_cast<std::uint64_t>(expected.writer ? report::ReportPhase::Faulted : report::ReportPhase::Rejected)) return false;
        if (loss!=(scenario.reportMode==7 ? bit : 0)) return false;
        if (child.output.find("[RS2SteamReport] v"+inputs.expectedVersion+"; status=disabled;")==child.output.npos) return false;
        if (child.output.find("[RS2SteamReport] v"+inputs.expectedVersion+"; status=ready;")!=child.output.npos) return false;
    }
    if (expected.writer ? (stopping!=1 || finalPhase!=static_cast<std::uint64_t>(report::ReportPhase::Stopping)) :
        (stopping!=0 || finalPhase!=static_cast<std::uint64_t>(report::ReportPhase::Rejected) || written || flushed)) return false;
    if (scenario.reportMode==12 && child.output.find("steam_prehook=installed-before-audio preserved=true")==child.output.npos) return false;
    return ReportingLogEvidence(inputs,scenario,child,directory,before,after);
}
bool WriteTimingFixture(const Inputs& inputs,const std::wstring& root,const Child& child) {
    // Called only after every core marker, reporting status/log and input-custody
    // check passed. This records OWN-fixture envelopes, never a deployment-ready
    // calibration or a claim that production callbacks used these artifacts.
    std::map<std::string,std::string> fields;
    std::uint64_t frequency{},creation{};
    FixtureTiming timing{};
    if (!OutputFields(child.output,"report_fixture=",&fields) ||
        !FieldUnsigned(fields,"qpc_frequency",&frequency) || !FieldUnsigned(fields,"process_creation",&creation) ||
        !ReadFixtureTiming(child,frequency,&timing)) return false;
    const auto run=fields.find("run_id");
    if (run==fields.end() || !HexString(run->second,32)) return false;
    rs2fix::Sha256Digest stdoutDigest{};
    if (!rs2fix::HashBytesSha256(child.output.data(),child.output.size(),&stdoutDigest)) return false;
    auto json=std::string("{\n  \"schema\":5,\n  \"kind\":\"inert-timing-fixture-evidence\",\n")+
        "  \"measurement_id\":\"rs2-wrapper-own-deferred-v2\",\n"+
        "  \"protocol_id\":\"rs2-deferred-v2-fixed6000-1024\",\n"+
        "  \"protocol_complete\":true,\n  \"integrity_pass\":true,\n"+
        "  \"ordinal_stdout_sha256\":\""+LowerDigest(stdoutDigest)+"\",\n"+
        "  \"operator_ready\":false,\n  \"production_artifact_bound\":false,\n  \"real_game_or_sdk_execution\":false,\n"+
        "  \"run_id\":\""+run->second+"\",\n  \"pid\":"+std::to_string(child.pid)+
        ",\n  \"process_creation\":"+std::to_string(creation)+
        ",\n  \"fixture_host_sha256\":\""+LowerDigest(inputs.host.digest)+
        "\",\n  \"fixture_companion_sha256\":\""+LowerDigest(inputs.active.digest)+
        "\",\n  \"fixture_bootstrap_sha256\":\""+LowerDigest(inputs.bootstrap.digest)+
        "\",\n  \"steam_api_fixture_sha256\":\""+LowerDigest(inputs.sdk.digest)+
        "\",\n  \"steam_client_fixture_sha256\":\""+LowerDigest(inputs.client.digest)+
        "\",\n  \"qpc_frequency\":"+std::to_string(timing.frequency)+
        ",\n  \"pump_sample_count\":"+std::to_string(timing.pumpCount)+
        ",\n  \"main_pump_sample_count\":"+std::to_string(timing.mainCount)+
        ",\n  \"main_management_sample_count\":"+std::to_string(timing.mainManagement)+
        ",\n  \"coverage_pass\":"+(timing.coverage ? "true" : "false")+
        ",\n  \"builder_sample_count\":"+std::to_string(timing.builderCount)+
        ",\n  \"builder_selected_count\":"+std::to_string(timing.selectedCount)+
        ",\n  \"pump_maximum_missing_ticks\":"+std::to_string(timing.pumpMaximum)+
        ",\n  \"builder_maximum_missing_ticks\":"+std::to_string(timing.builderMaximum)+
        ",\n  \"native_pump_calls\":7030,\n  \"native_builder_calls\":1029,"+
        "\n  \"normal_attempts\":1028,\n  \"full_selected\":1027,"+
        "\n  \"ordinal_record_count\":8050,\n  \"unpaired_warmup_count\":1,\n  \"unpaired_tail_count\":1,"+
        "\n  \"ordinal_evidence\":\"calibration child stdout-stderr.txt; exact ordinal and class totals independently replayed by runner\","+
        "\n  \"pump_bridge_calls\":1,\n  \"pump_duration_lag\":1,\n  \"builder_duration_lag\":0"+
        ",\n  \"calibration_start_qpc\":"+std::to_string(timing.calibrationStart)+
        ",\n  \"calibration_end_qpc\":"+std::to_string(timing.calibrationEnd)+
        ",\n  \"calibration_ticks\":"+std::to_string(timing.calibrationTicks)+
        ",\n  \"pump_window_start_qpc\":"+std::to_string(timing.windowStart)+
        ",\n  \"pump_window_end_qpc\":"+std::to_string(timing.windowEnd)+
        ",\n  \"pump_window_ticks\":"+std::to_string(timing.windowTicks)+
        ",\n  \"pump_own_ticks\":"+std::to_string(timing.pumpOwn)+
        ",\n  \"pump_corrected_ticks\":"+std::to_string(timing.pumpCorrected)+
        ",\n  \"pump_raw_aggregate\":\""+(timing.rawAggregate ? "PASS" : "FAIL")+
        "\",\n  \"pump_corrected_aggregate\":\""+(timing.correctedAggregate ? "PASS" : "FAIL")+
        "\",\n  \"sample_class_limits\":\""+(timing.classLimits ? "PASS" : "FAIL")+
        "\",\n  \"calibration_candidate\":\""+(timing.candidate ? "PASS" : "FAIL")+
        "\",\n  \"candidate_scope\":\"coverage-raw-main-pump-and-per-class-smoke\""+
        ",\n  \"production_full_window\":\"unqualified\""+
        ",\n  \"builder_stress_full_window_qualified\":false"+
        ",\n  \"envelope\":\"outer-wrapper-minus-recorded-own-minus-inner-original\",\n"+
        "  \"builder_includes_pump_envelope\":false,\n"+
        "  \"inner_original_pairs\":\"exact-call-checked\",\n  \"residual_bound\":\"empirical-not-wcrt\",\n"+
        "  \"selected_store_and_native_full_consumption_verified\":true,\n"+
        "  \"conservative_overcount\":\"Subtracts only the exact matched inner-original interval. Original prologue/epilogue, QPC/LastError bookend and outer-host overhead remain; unrelated engine/producer work and the later pump are outside the builder envelope.\",\n"+
        "  \"bound_limitation\":\"Per-class maximum residual across all 8048 eligible pairs, without retries or averaged noise subtraction; empirical for these artifacts/run, not worst-case response time. Eligibility does not depend on coverage, cost or latency verdict.\",\n"+
        "  \"aggregate_scope\":\"Exactly 6000 main pump samples and their actual QPC span. Corrected sum charges each main class count with that class maximum over ALL paired main/bridge/support samples; no builder cost or bridge/support own ticks in main aggregate.\",\n"+
        "  \"builder_stress_scope\":\"1024 accelerated selected builders test per-call limits and maximum missing cost, not normal-cadence whole-window production budget.\",\n"+
        "  \"required_next_binding\":\"Final production artifact, source identity, representative full-window performance and review acceptance.\",\n  \"classes\":[";
    for (std::size_t i=0;i<report::kStatusDurationClasses;++i) {
        const auto& c=timing.classes[i];
        const auto& m=timing.mainClasses[i];
        json+=(i ? "," : "")+std::string("{\"class\":")+std::to_string(i)+
            ",\"calls\":"+std::to_string(c.calls)+",\"elapsed_ticks\":"+std::to_string(c.elapsedTicks)+
            ",\"maximum_ticks\":"+std::to_string(c.maximumTicks)+
            ",\"over_five_milliseconds\":"+std::to_string(c.overFiveMilliseconds)+
            ",\"residual_sample_count\":"+std::to_string(timing.residualCount[i])+
            ",\"residual_sum_ticks\":"+std::to_string(timing.residualSum[i])+
            ",\"residual_maximum_ticks\":"+std::to_string(timing.residualMaximum[i])+
            ",\"eligible\":"+(timing.eligible[i] ? "true" : "false")+
            ",\"main_calls\":"+std::to_string(m.calls)+",\"main_elapsed_ticks\":"+std::to_string(m.elapsedTicks)+
            ",\"main_maximum_ticks\":"+std::to_string(m.maximumTicks)+
            ",\"main_over_five_milliseconds\":"+std::to_string(m.overFiveMilliseconds)+
            ",\"auxiliary_calls\":"+std::to_string(timing.auxiliaryCalls[i])+
            ",\"auxiliary_elapsed_ticks\":"+std::to_string(timing.auxiliaryTicks[i])+"}";
    }
    json+="]\n}\n";
    const auto path=Join(root,L"timing-fixture.json");
    if (!CreateText(path,json)) return false;
    std::wcout << L"timing_fixture_evidence=" << path << std::endl;
    std::cout << "timing_fixture_calibration_smoke=" << (timing.candidate ? "pass" : "fail")
        << " production_full_window=unqualified\n";
    // Export is deliberately before candidate verdict: every complete,
    // integrity-valid failed-cost/latency/coverage run still contributes floors.
    // Local raw-pump/per-class smoke is not production performance acceptance.
    // The corrected pump diagnostic remains intact; only the real collector's
    // complete window can qualify the combined, MAX-charged wrapper workload.
    return timing.candidate;
}
