param([string]$Collector = (Join-Path $PSScriptRoot '..\tools\Collect-SteamReport.ps1'))
$ErrorActionPreference='Stop'
. $Collector
Initialize-ReportFileReader
$script:Checks=0
function Check([bool]$Condition,[string]$Why) { ++$script:Checks; if (!$Condition) { throw $Why } }
function Reject([scriptblock]$Action,[string]$Why) {
    $rejected=$false; try { $null=& $Action } catch { $rejected=$true }
    Check $rejected $Why
}
$caseRoot=Join-Path ([IO.Path]::GetTempPath()) ('RS2ReportingCollectorTests-'+[Guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($caseRoot)
Write-Host "Owned inert fixtures: $caseRoot"
function LogFile([string]$Name,$Records) {
    $path=Join-Path $caseRoot $Name
    $lines=@($Records|ForEach-Object { $_|ConvertTo-Json -Depth 8 -Compress })
    Save-ReportText $path (($lines -join "`n")+"`n")
    return $path
}
Check ((Read-ReportJson '{"sequence":9007199254740993}')['sequence'] -eq [uint64]9007199254740993) 'u64 precision lost.'
Reject { Read-ReportJson '{"sequence":1,"sequence":2}' } 'Duplicate JSON key accepted.'
Reject { Read-ReportJson '{"sequence":18446744073709551615}' } 'Saturated scalar accepted.'
Check ((Read-ReportJson '{"native_schedule_anchor_bits":18446744073709551615}')['native_schedule_anchor_bits'] -eq [uint64]::MaxValue) 'Raw signed native bits were mistaken for saturated counter.'
Reject { Read-ReportJson '{"sequence":01}' } 'Noncanonical number accepted.'
Reject { Read-ReportJson '{"sequence":1,"nested":{}}' } 'Unknown nested object accepted.'
Reject { Read-ReportFields "schema=1`r`nschema=2`r`n" } 'Duplicate evidence field accepted.'
Check ((Read-ReportFields "reporting.lastOwnerQpc=10`r`n")['reporting.lastOwnerQpc'] -ceq '10') 'Native camelCase field rejected.'
Check ((Read-ReportConfiguration "schema=2`r`nmode=repair`r`n" $true).mode -ceq 'repair') 'Repair semantic configuration rejected.'
Check ((Read-ReportConfiguration "enabled=1`r`nmax_log_mib=00016`r`n" $false).quota_mib -eq 16) 'Native-compatible leading-zero quota rejected.'
Reject { Read-ReportConfiguration "schema=2`r`r`nmode=observe`n" $true } 'Extra CR differs from native parser.'
Reject { Read-ReportConfiguration "schema=2`nmode=observe`nmode=repair`n" $true } 'Duplicate mode accepted.'
Reject { Read-ReportConfiguration "enabled=1`nmax_log_mib=15`n" $false } 'Invalid quota accepted.'
Reject { Read-ReportConfiguration ("schema=2`nmode=observe"+[char]0) $true } 'NUL configuration accepted.'

# Held plain handles, CreateNew output, and complete-line parsing preserve an
# unfinished UTF-8 tail without turning it into a valid required record.
$partial=Join-Path $caseRoot 'partial.jsonl'; $copy=Join-Path $caseRoot 'partial-copy.jsonl'
$bytes=[Text.Encoding]::UTF8.GetBytes("{`"fixture`":1}`n")+[byte[]]@(0xe2,0x82)
$stream=[IO.File]::Open($partial,[IO.FileMode]::CreateNew)
try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
$source=[RS2ReportCollection.Files]::Open($partial,$true)
try {
    $prefix=[RS2ReportCollection.Files]::CopyPrefix($source,$partial,$copy)
    Reject { [RS2ReportCollection.Files]::CopyPrefix($source,$partial,$copy) } 'Existing evidence overwritten.'
    Reject { [IO.File]::Move($partial,($partial+'.moved')) } 'Held source allowed replacement.'
} finally { $source.Dispose() }
Check ($prefix.PartialTail -and $prefix.CopiedLength -eq $bytes.Length) 'Incomplete prefix was discarded or extended.'
Check (@([RS2ReportCollection.Files]::CompleteLines($copy)).Count -eq 1) 'Partial UTF-8 was decoded.'
Assert-ReportPrefix $partial $copy
$rewritten=Join-Path $caseRoot 'rewritten.jsonl'; Save-ReportText $rewritten ('X'*$bytes.Length)
Reject { Assert-ReportPrefix $partial $rewritten } 'Earlier log prefix rewrite accepted.'
Reject { Resolve-ReportPlain (Join-Path $caseRoot '..\outside') $true } 'Traversal accepted.'

$runId='0123456789abcdef0123456789abcdef'
$created=[uint64]134000000000000000
$run=Join-Path $caseRoot ('20260917T000000Z-PID123-'+$runId)
$identity=@{pid='123';process_creation_filetime=[string]$created;'reporting.run_id'=$runId;'reporting.ownerThreadId'='4';
    'reporting.mode'='3';'reporting.qpc_frequency'='1000000'}
$startup=[ordered]@{type='startup';schema=2;artifact='RS2ServerFix-steam-reporting';version='0.4.1.0';artifact_version=262400;
    run_id=$runId;pid=123;process_start_filetime=$created;qpc_frequency=1000000;utc_filetime=$created;qpc=1;
    mode='repair';configured_mode=3;header_validity=31;host_sha256=$script:ReportHostHash;
    qualified_steam_api_sha256=$script:ReportSdkHash;qualified_steamclient_sha256=$script:ReportClientHash;
    max_log_bytes=16MB;record_bytes=256;ring_capacity=256;batch_limit=32;authentication_changed=$false;
    verbose_observer_trace=$false;termination_may_lose_tail=$true;directory=$run}
function Common([int]$Kind,[uint64]$Sequence,[uint64]$Qpc) {
    return [ordered]@{type=@('','state','request','witness','builder-enter','builder-return','builder-unwind','anchor')[$Kind];
        schema=2;run_id=$runId;pid=123;sequence=$Sequence;qpc=$Qpc;source_epoch=1;binding_epoch=1;kind=$Kind;reason=0;flags=0;thread_id=4}
}
function ScheduleState {
    $r=Common 1 1 2
    foreach($key in @('phase','request_sequence','witness_sequence','build_sequence','pending_since_qpc','fresh_since_qpc',
        'qualification_flags','native_task_state','client_qualification_ms','mode','classification','pi','bots','maximum','pending','fresh','bound',
        'native_schedule_valid','native_schedule_anchor_bits','native_errors_bits','native_throttles_bits','native_expedite',
        'native_retry_limit','native_interval_units','native_interval_override_bits','native_retry_override_bits','native_delay_units','native_tier')) { $r[$key]=0 }
    $r.phase=6;$r.mode=3;$r.native_task_state=3;$r.native_schedule_valid=1
    $r.native_interval_units=30000;$r.native_retry_limit=3;$r.native_errors_bits=12
    $r.native_tier=6;$r.native_delay_units=1800000;$r.native_schedule_anchor_bits=[uint64]::MaxValue
    return $r
}
$scheduler=Read-ReportLog (LogFile 'native-schedule.jsonl' @($startup,(ScheduleState))) $identity $run 16MB 0 10
Check ($scheduler.scheduler_samples.Count -eq 1 -and $scheduler.scheduler_samples[0].native_tier -ceq '6') 'Verified native retry tier omitted.'
Check ($scheduler.scheduler_samples[0].next_eligibility -ceq 'unknown' -and !$scheduler.scheduler_samples[0].proves_preventing_backoff) 'Native delay became a fabricated due time or coverage exemption.'
$state=ScheduleState;$state.native_interval_override_bits=[uint64]::MaxValue;$state.native_tier=0;$state.native_delay_units=0
$scheduler=Read-ReportLog (LogFile 'native-schedule-raw-bits.jsonl' @($startup,$state)) $identity $run 16MB 0 10
Check ($scheduler.scheduler_samples[0].native_interval_override_bits -ceq '18446744073709551615') 'Native raw64 metadata bits lost precision.'
$state=ScheduleState;$state.native_task_state=2
Reject { Read-ReportLog (LogFile 'native-schedule-poll.jsonl' @($startup,$state)) $identity $run 16MB 0 10 } 'Ordinary poll was falsely labeled retry backoff.'
$state=ScheduleState;$state.native_schedule_valid=0
Reject { Read-ReportLog (LogFile 'native-schedule-stale.jsonl' @($startup,$state)) $identity $run 16MB 0 10 } 'Unavailable scheduler leaked old scalars.'
$state=ScheduleState;$state.native_expedite=7
$scheduler=Read-ReportLog (LogFile 'native-schedule-expedite.jsonl' @($startup,$state)) $identity $run 16MB 0 10
Check ($scheduler.scheduler_samples[0].due_state -ceq 'expedite-pending' -and $scheduler.scheduler_samples[0].next_eligibility -ceq 'unknown') 'Expedite observation was converted into a timestamp.'
$state=ScheduleState;$state.native_interval_units=15000;$state.native_tier=0;$state.native_delay_units=0
$scheduler=Read-ReportLog (LogFile 'native-schedule-unknown-interval.jsonl' @($startup,$state)) $identity $run 16MB 0 10
Check ($scheduler.scheduler_samples[0].native_interval_units -ceq '15000' -and $scheduler.scheduler_samples[0].native_tier -ceq '0') 'Unsupported observed interval aborted diagnostics instead of staying unknown.'
$state.native_interval_units=[uint64]::MaxValue
$scheduler=Read-ReportLog (LogFile 'native-schedule-raw64-interval.jsonl' @($startup,$state)) $identity $run 16MB 0 10
Check ($scheduler.scheduler_samples[0].native_interval_units -ceq '18446744073709551615' -and $scheduler.scheduler_samples[0].native_tier -ceq '0') 'Raw native interval was mistaken for a saturated counter.'
$state.native_tier=6;$state.native_delay_units=1800000
Reject { Read-ReportLog (LogFile 'native-schedule-unknown-interval-tier.jsonl' @($startup,$state)) $identity $run 16MB 0 10 } 'Unsupported interval claimed a qualified native tier.'
function Request([int]$Kind,[uint64]$Sequence) {
    $r=Common $Kind $Sequence $Sequence
    foreach ($key in @('request_sequence','witness_sequence','staged_qpc','previous_sample_qpc','observed_qpc','fresh_since_qpc',
        'source_age_ticks','pi','bots','maximum','staged_bots','human_players','world_bots','classification','pending')) { $r[$key]=0 }
    $r.request_sequence=1; $r.witness_sequence=if($Kind -eq 3){1}else{0};$r.pi=1;$r.maximum=64;$r.human_players=1;$r.classification=1
    return $r
}
function Build([int]$Kind,[uint64]$Sequence,[uint64]$BuildId,[uint64]$Entry,[uint64]$Selected) {
    $r=Common $Kind $Sequence $(if($Kind -eq 4){$Entry}else{$Entry+1})
    foreach ($key in @('build_sequence','request_sequence','witness_sequence','source_age_ticks','probe_elapsed_ticks',
        'classification_elapsed_ticks','original_elapsed_ticks','entry_qpc','return_qpc','pi','bots','maximum','classification','selected','result','pending','fresh')) { $r[$key]=0 }
    $r.build_sequence=$BuildId;$r.request_sequence=1;$r.witness_sequence=1;$r.entry_qpc=$Entry;$r.pi=1;$r.maximum=64;$r.classification=2
    $r.selected=$Selected;$r.fresh=1
    if($Kind -ne 4){$r.return_qpc=$Entry+1;$r.result=1}
    return $r
}
function Anchor([uint64]$Sequence,[uint64]$Qpc) {
    $r=Common 7 $Sequence $Qpc
    foreach ($key in @('normal_attempts','full_selected','selected_true','normal_returns','false_returns','native_unwinds',
        'request_sequence','witness_sequence','build_sequence','distinct_selected_witnesses')) { $r[$key]=1 }
    $r.false_returns=0;$r.native_unwinds=0
    $r.durations=@(0..3|ForEach-Object { [ordered]@{class=$_;calls=1;elapsed_ticks=1;maximum_ticks=1;over_five_milliseconds=0} })
    return $r
}
$records=@($startup,(Request 2 1),(Request 3 2),(Build 4 3 1 3 0),(Build 5 4 1 3 1),(Anchor 5 5))
$valid=LogFile 'valid.jsonl' $records
$log=Read-ReportLog $valid $identity $run 16MB 0 100
Check ($log.pairs.Count -eq 1 -and $log.pairs[0].selected -eq 1 -and $log.counters.selected_true -eq 1) 'Valid Return selection or event reconciliation failed.'
Check ($log.population_samples -eq 2 -and $log.human_observed) 'Human population evidence lost.'
$bad=@($records);$bad[4]=Build 5 4 2 3 1
Reject { Read-ReportLog (LogFile 'wrong-pair.jsonl' $bad) $identity $run 16MB 0 100 } 'Wrong build pair accepted.'
$bad=@($records);$bad[3]=Build 4 3 1 3 1
Reject { Read-ReportLog (LogFile 'enter-selected.jsonl' $bad) $identity $run 16MB 0 100 } 'Pre-admission Enter claimed selection.'
$bad=@($records);$bad[5]=Anchor 5 5;$bad[5].normal_attempts=2
Reject { Read-ReportLog (LogFile 'anchor-lie.jsonl' $bad) $identity $run 16MB 0 100 } 'Anchor/event mismatch accepted.'
$bad=@($records);$bad[5]=Anchor 6 5
Reject { Read-ReportLog (LogFile 'gap.jsonl' $bad) $identity $run 16MB 0 100 } 'Missing required sequence accepted.'
$missing=Read-ReportLog (LogFile 'missing-return.jsonl' @($records[0],$records[1],$records[2],$records[3])) $identity $run 16MB 0 100
Check ($missing.pairs.Count -eq 0 -and $null -ne $missing.open_builder) 'Missing Return invented.'
$wrongIdentity=@{}+$identity;$wrongIdentity.process_creation_filetime=[string]($created+1)
Reject { Read-ReportLog $valid $wrongIdentity $run 16MB 0 100 } 'Reused PID/stale creation accepted.'
Reject { Read-ReportLog $valid $identity ($run+'-wrong') 16MB 0 100 } 'Wrong run path accepted.'

function Snapshot([uint64]$Qpc,[uint64]$Counter) {
    $f=@{'reporting.revoke_reasons'='0';'reporting.loss_reasons'='0';'reporting.stopping'='0';
        'reporting.run_id'=$runId;'reporting.owner_valid'='true';'reporting.timingAccountedThroughQpc'=[string]$Qpc}
    foreach($key in @('normalAttempts','fullSelected','selectedTrue','normalReturns','falseReturns','nativeUnwinds','managementCalls',
        'normalPumpClassifications','normalBuilderClassifications','requestSequence','witnessSequence','buildSequence','reportSequence','distinctSelectedWitnesses')) { $f['reporting.'+$key]=[string]$Counter }
    $f['reporting.falseReturns']='0';$f['reporting.nativeUnwinds']='0'
    for($i=0;$i -lt 64;++$i){$f['reporting.reason_count.'+$i]='0'}
    for($i=0;$i -lt 4;++$i){
        $n=if($i -eq 1){100*$Counter}elseif($i -eq 3){$Counter}else{0}
        foreach($key in @('calls','elapsed_ticks')){$f['reporting.duration.'+$i+'.'+$key]=[string]$n}
        $f['reporting.duration.'+$i+'.maximum_ticks']=if($n){'1'}else{'0'}
        $f['reporting.duration.'+$i+'.over_five_ms']='0'
        for($b=0;$b -lt 6;++$b){$f['reporting.duration.'+$i+'.bucket.'+$b]=if($b -eq 0){[string]$n}else{'0'}}
    }
    return @{fields=$f;coverage_range=@{lower=$Qpc;upper=$Qpc};timing_range=@{lower=$Qpc;upper=$Qpc};exit_code=0}
}
# DATA counters at an explicit report watermark must agree with all required
# events up to that sequence, even if the latest anchor looks healthy.
$status=Snapshot 5 1;$status.fields['reporting.reportSequence']='5'
$null=Read-ReportLog $valid $identity $run 16MB 0 100 @($status)
$status.fields['reporting.selectedTrue']='2'
Reject { Read-ReportLog $valid $identity $run 16MB 0 100 @($status) } 'DATA/log counter contradiction accepted.'

$artifact='A'*64
function Calibration {
    return @{qualified=$true;integrity_valid=$true;companion_sha256=$artifact;frequency=[uint64]1000000;reason='fixture-measured-not-hard-real-time';
        class_floors=@(0..3|ForEach-Object{@{class=$_;eligible=($_ -ne 2);floor_ticks=[uint64]1}})}
}
$calibration=Calibration
$absent=@{qualified=$false;integrity_valid=$false;companion_sha256=$artifact;frequency=[uint64]0;class_floors=@();reason='measurement-absent'}
$samples=@((Snapshot 1000000 0),(Snapshot 121000000 10),(Snapshot 181000000 12),(Snapshot 241000000 14),(Snapshot 301000000 16))
$pairSet=@(0..5|ForEach-Object { @{entry=[uint64](122000000+30000000*$_);returned=[uint64](122000001+30000000*$_);
    selected=1;result=1;witness=($_+1);unwind=$false} })
$windowLog=@{source_changes=$false;epoch_baseline_available=$true;pairs=$pairSet;window_requests=3;window_selections=3;population_samples=3;human_observed=$true}
$out=Measure-ReportWindow $samples $windowLog 1000000 1000000 'repair' $calibration $artifact
Check ($out.local_safety -ceq 'PASS' -and $out.local_coverage -ceq 'PASS' -and $out.local_performance -ceq 'PASS') 'Healthy fixed repair window failed.'
Check ($out.warmup_seconds -eq 120 -and $out.score_seconds -eq 180 -and $out.warmup.complete) 'Warmup/scored windows not retained.'
Check ($out.operator_smoke -ceq 'UNVERIFIED' -and $out.backend_client_effect -ceq 'UNVERIFIED' -and $out.outage_recovery -ceq 'UNVERIFIED') 'Local proof was promoted into efficacy.'
$out=Measure-ReportWindow $samples $windowLog 1000000 1000000 'repair' $absent $artifact
Check ($out.local_performance -ceq 'INCONCLUSIVE' -and $out.performance.measured -ceq 'PASS') 'Missing epilogue measurement claimed PASS.'
$out=Measure-ReportWindow @($samples[0],$samples[1],$samples[2]) $windowLog 1000000 1000000 'repair' $calibration $artifact
Check ($out.local_coverage -ceq 'INCONCLUSIVE' -and $out.end_qpc -ceq '301000000') 'Missing endpoint shifted/cherry-picked window.'
$uncertain=@((Snapshot 1000000 0),(Snapshot 120000000 0),(Snapshot 122000000 10),(Snapshot 300000000 10),(Snapshot 302000000 20))
$out=Measure-ReportWindow $uncertain $windowLog 1000000 1000000 'repair' $calibration $artifact
Check ($out.local_coverage -ceq 'INCONCLUSIVE') 'Boundary uncertainty manufactured coverage.'
$zero=@((Snapshot 1000000 0),(Snapshot 121000000 0),(Snapshot 301000000 0))
$out=Measure-ReportWindow $zero $windowLog 1000000 1000000 'repair' $calibration $artifact
Check ($out.local_coverage -ceq 'FAIL') 'Healthy zero repair coverage was excused.'
$zero[-1].fields['reporting.reason_count.49']='1'
$out=Measure-ReportWindow $zero $windowLog 1000000 1000000 'repair' $calibration $artifact
Check ($out.local_coverage -ceq 'FAIL' -and $out.reason -ceq 'healthy-repair-coverage-insufficient') 'A reason counter without preventing-delay evidence excused deficient coverage.'
$windowLog.human_observed=$false
$out=Measure-ReportWindow $samples $windowLog 1000000 1000000 'repair' $calibration $artifact
Check ($out.reason -ceq 'observed-no-human-test-population') 'Missing test population was silently qualified.'
$windowLog.human_observed=$true
$samples[-1].fields['reporting.loss_reasons']='1'
$out=Measure-ReportWindow $samples $windowLog 1000000 1000000 'repair' $calibration $artifact
Check ($out.local_safety -ceq 'FAIL') 'Sticky log loss ignored.'
$samples[-1].fields['reporting.loss_reasons']='0'
$decreased=Snapshot 301000001 15
Reject { Assert-ReportCounterProgress $samples[-1] $decreased } 'Cumulative counter decrease accepted.'
$regressed=Snapshot 301000001 16;$regressed.fields['reporting.timingAccountedThroughQpc']='1'
Reject { Assert-ReportCounterProgress $samples[-1] $regressed } 'Completed-root watermark regression accepted.'
# A live publication with a child committed but its parent unfinished cannot
# close the timing window. Coverage is deliberately allowed to finish first.
$lagged=@((Snapshot 1000000 0),(Snapshot 301000000 16))
$lagged[-1].timing_range.lower=[uint64]300999999
$durationEnd=Find-ReportBoundary $lagged 301000000 'timing'
$coverageEnd=Find-ReportBoundary $lagged 301000000 'coverage'
Check ($coverageEnd.complete -and !$durationEnd.complete) 'Owner liveness was used as a completed accounting boundary.'
$missingTiming=@((Snapshot 1000000 0),(Snapshot 301000000 16))
$missingTiming[0].timing_range=$null
Check (!(Find-ReportBoundary $missingTiming 1000000 'timing').complete) 'Absent initial timing was fabricated from coverage.'
Check ($out.warmup.coverage.range_family -ceq 'coverage_range' -and $out.warmup.timing.range_family -ceq 'timing_range') 'Warmup counter families were left unlabeled.'
$routed=@((Snapshot 1000000 0),(Snapshot 121000000 10),(Snapshot 301000000 16),(Snapshot 302000000 18))
$routed[2].timing_range.lower=[uint64]300999999
$routedOut=Measure-ReportWindow $routed $windowLog 1000000 1000000 'repair' $calibration $artifact
Check ($routedOut.scored_counters.coverage.counters['reporting.normalAttempts'].maximum -ceq '6' -and
    $routedOut.scored_counters.timing.counters['reporting.duration.3.calls'].maximum -ceq '8') 'Coverage and timing counters shared an incorrectly narrow envelope.'
Check (!$routedOut.scored_counters.coverage.counters.ContainsKey('reporting.duration.3.calls') -and
    !$routedOut.scored_counters.timing.counters.ContainsKey('reporting.normalAttempts')) 'Counter families were mixed.'

# A historical maximum cannot be subtracted. A new zero-overrun window remains
# measured-safe, but a nonzero allowance crossing the old max is inconclusive.
$a=Find-ReportBoundary $samples 121000000;$b=Find-ReportBoundary $samples 301000000
$samples[1].fields['reporting.duration.3.maximum_ticks']='6000'
$samples[-1].fields['reporting.duration.3.maximum_ticks']='6000'
$perf=Measure-ReportPerformance $a $b 180000000 1000000 $calibration $artifact
Check ($perf.measured -ceq 'PASS' -and $perf.verdict -ceq 'INCONCLUSIVE') 'Cumulative maximum was subtracted or blamed on this window.'
$samples[-1].fields['reporting.duration.3.over_five_ms']='1'
$perf=Measure-ReportPerformance $a $b 180000000 1000000 $calibration $artifact
Check ($perf.measured -ceq 'FAIL') 'A scored builder outlier was diluted.'
$samples[-1].fields['reporting.duration.3.over_five_ms']='0'
# One cheap pump class must not hide a failing management percentile.
$samples[-1].fields['reporting.duration.1.over_five_ms']='7'
$samples[-1].fields['reporting.duration.0.calls']='1000000000'
$perf=Measure-ReportPerformance $a $b 180000000 1000000 $calibration $artifact
Check ($perf.measured -ceq 'FAIL' -and $perf.classes[1].measured -ceq 'FAIL') 'Performance classes were pooled.'
# Integer widened difference/ratios retain units beyond binary64 exact integers.
$largeA=Snapshot 1 0;$largeB=Snapshot 2 0
$largeA.fields['reporting.normalAttempts']='9007199254740993';$largeB.fields['reporting.normalAttempts']='9007199254740997'
Check ((Get-ReportDifference $largeB $largeA 'reporting.normalAttempts') -eq 4) 'Difference lost large-integer precision.'
$overlap=Get-ReportEnvelope @{before=$largeA;after=$largeB} @{before=$largeA;after=$largeB} 'reporting.normalAttempts'
Check ($overlap.minimum -eq 0 -and $overlap.maximum -eq 4) 'Overlapping bracket bounds invalid.'

$splitBegin=Snapshot 1 0;$splitEnd=Snapshot 2 1
$splitEnd.fields['reporting.duration.0.calls']='1000';$splitEnd.fields['reporting.duration.0.elapsed_ticks']='1000'
$splitEnd.fields['reporting.duration.0.maximum_ticks']='1'
$splitEnd.fields['reporting.duration.1.calls']='1';$splitEnd.fields['reporting.duration.1.elapsed_ticks']='1'
$splitCal=Calibration;$splitCal.class_floors[1].floor_ticks=[uint64]100
$splitA=Find-ReportBoundary @($splitBegin,$splitEnd) 1 'timing';$splitB=Find-ReportBoundary @($splitBegin,$splitEnd) 2 'timing'
$splitResult=Measure-ReportPerformance $splitA $splitB 100000000 1000000 $splitCal $artifact
Check ($splitResult.verdict -ceq 'PASS' -and $splitResult.pooled_sensitivity.verdict -ceq 'INCONCLUSIVE' -and
    $splitResult.pass_depends_on_class_split -and $splitResult.pooled_sensitivity.split_only_reduction_ticks -ceq '99000') 'Same-floor split effect was lost or called a speedup.'
Check ($splitResult.legacy_stress.summed_upper_ticks -ceq '127146' -and !$splitResult.legacy_stress.qualification_gate -and
    $splitResult.attribution.causal_ticks_versus_r6 -ceq 'unknown') 'Legacy floor stress or honest attribution changed.'
$splitEnd.fields['reporting.duration.2.calls']='1'
$missingClass=Measure-ReportPerformance $splitA $splitB 100000000 1000000 $splitCal $artifact
Check ($missingClass.verdict -ceq 'INCONCLUSIVE' -and !$missingClass.pooled_sensitivity.available -and
    $null -eq $missingClass.summed_upper_ticks -and $missingClass.missing_called_classes -contains 2) 'Uncalibrated called class borrowed a pooled floor.'
# Uncertain zero lower calls still need a floor; only an upper bound of zero is
# genuinely unobserved and exempt from a residual charge.
$uncertainA=@{complete=$true;before=$splitBegin;after=$splitEnd}
$uncertainB=@{complete=$true;before=$splitBegin;after=$splitEnd}
$missingClass=Measure-ReportPerformance $uncertainA $uncertainB 100000000 1000000 $splitCal $artifact
Check ($missingClass.classes[2].calls_min -ceq '0' -and $missingClass.classes[2].calls_max -ceq '1' -and
    $missingClass.missing_called_classes -contains 2) 'Zero lower calls wrongly erased a required calibration class.'
$splitEnd.fields['reporting.duration.2.calls']='0'
$fractional=Calibration;$fractional.frequency=[uint64]3
$rounded=Measure-ReportPerformance $splitA $splitB 100000000 10 $fractional $artifact
Check ($rounded.classes[0].epilogue_ticks_per_call -ceq '4') 'Frequency conversion rounded a residual down.'
$equalCal=Calibration;$equalCal.class_floors[1].floor_ticks=0;$equalCal.class_floors[3].floor_ticks=0
$splitEnd.fields['reporting.duration.0.elapsed_ticks']='0';$splitEnd.fields['reporting.duration.1.elapsed_ticks']='0';$splitEnd.fields['reporting.duration.3.elapsed_ticks']='0'
$equal=Measure-ReportPerformance $splitA $splitB 1000000 1000000 $equalCal $artifact
Check ($equal.summed_upper_ticks -ceq '1000' -and $equal.verdict -ceq 'INCONCLUSIVE') 'Equality passed a strict less-than target.'
$splitEnd.fields['reporting.duration.0.elapsed_ticks']='1000'
$equal=Measure-ReportPerformance $splitA $splitB 1000000 1000000 $equalCal $artifact
Check ($equal.measured -ceq 'FAIL' -and $equal.verdict -ceq 'FAIL') 'Raw lower-bound failure was downgraded to uncertainty.'

# Only package-owned manifest entries can provide a calibration; unknown files
# and observer private keys never become a collection input.
$package=Join-Path $caseRoot 'package';$null=[IO.Directory]::CreateDirectory($package);$sums=@()
foreach($relative in $script:ReportPackageFiles){
    $path=Join-Path $package $relative.Replace('/','\');$null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
    Save-ReportText $path 'inert fixture - never executed';$sums+=(Get-FileHash -LiteralPath $path).Hash+'  '+$relative
}
Save-ReportText (Join-Path $package 'SHA256SUMS') (($sums -join "`r`n")+"`r`n")
$locks=New-Object 'Collections.Generic.List[IO.FileStream]'
try {
    $verified=Read-ReportPackage $package $locks
    Check ($verified.Files.Count -eq 12 -and $locks.Count -eq 13) 'Required package contract changed.'
    Check (!(Read-ReportTimingCalibration $verified.Files $package).qualified) 'Absent calibration trusted.'
    Reject { [IO.File]::WriteAllText((Join-Path $package 'dlls\RS2ServerFix.dll'),'changed') } 'Package file changed while held.'
} finally { foreach($locked in $locks){$locked.Dispose()} }
$badPackage=Join-Path $caseRoot 'bad-package';$null=[IO.Directory]::CreateDirectory($badPackage)
Save-ReportText (Join-Path $badPackage 'SHA256SUMS') (('A'*64)+"  RS2SteamObserveKeys/secret.key`r`n")
$locks=New-Object 'Collections.Generic.List[IO.FileStream]'
try { Reject { Read-ReportPackage $badPackage $locks } 'Private key accepted in manifest.' }
finally { foreach($locked in $locks){$locked.Dispose()} }
# Observe uses classified unchanged-return reachability, not repair witnesses.
$observed=@((Snapshot 1000000 0),(Snapshot 301000000 3))
foreach($s in $observed) {
    foreach($key in @('fullSelected','selectedTrue','requestSequence','witnessSequence','distinctSelectedWitnesses')) { $s.fields['reporting.'+$key]='0' }
}
$observeLog=@{source_changes=$false;epoch_baseline_available=$true;window_requests=0;window_selections=0;population_samples=0;human_observed=$false;
    pairs=@(0..2|ForEach-Object { @{entry=[uint64](2000000+30000000*$_);returned=[uint64](2000001+30000000*$_);
        selected=0;result=1;witness=0;unwind=$false;entry_reason=0;return_reason=0} })}
$out=Measure-ReportWindow $observed $observeLog 1000000 1000000 'observe' $calibration $artifact
Check ($out.local_coverage -ceq 'PASS' -and $out.local_performance -ceq 'PASS') 'Observe requires nonexistent repair witness.'
# Native-format observe logs: a normal original return does not by itself
# qualify a failed structural probe. Stable numeric staleness is the exception.
$observeStartup=[ordered]@{}
foreach($key in $startup.Keys){$observeStartup[$key]=$startup[$key]}
$observeStartup.mode='observe';$observeStartup.configured_mode=2
$observeIdentity=@{}+$identity;$observeIdentity['reporting.mode']='2'
foreach($reason in @(45,46,47,48)){
    $nativeRecords=New-Object 'Collections.Generic.List[object]';$nativeRecords.Add($observeStartup)
    $baseline=ScheduleState;$baseline.qpc=999999;$baseline.mode=2;$baseline.phase=5
    $nativeRecords.Add($baseline)
    for($i=0;$i -lt 3;++$i){
        $entry=Build 4 (2*$i+2) ($i+1) (2000000+30000000*$i) 0
        $returned=Build 5 (2*$i+3) ($i+1) (2000000+30000000*$i) 0
        foreach($record in @($entry,$returned)){$record.request_sequence=0;$record.witness_sequence=0;$record.reason=$reason;$record.fresh=0}
        $nativeRecords.Add($entry);$nativeRecords.Add($returned)
    }
    $nativeAnchor=Anchor 8 65000000
    foreach($key in @('normal_attempts','normal_returns','build_sequence')){$nativeAnchor[$key]=3}
    foreach($key in @('full_selected','selected_true','request_sequence','witness_sequence','distinct_selected_witnesses')){$nativeAnchor[$key]=0}
    for($i=0;$i -lt 4;++$i){
        $n=if($i -eq 1){300}elseif($i -eq 3){3}else{0}
        $nativeAnchor.durations[$i].calls=$n;$nativeAnchor.durations[$i].elapsed_ticks=$n
        $nativeAnchor.durations[$i].maximum_ticks=if($n){1}else{0}
    }
    $nativeRecords.Add($nativeAnchor)
    $path=LogFile ('observe-reason-'+$reason+'.jsonl') $nativeRecords.ToArray()
    $nativeLog=Read-ReportLog $path $observeIdentity $run 16MB 1000000 301000000
    $observed[-1].fields['reporting.reason_count.'+$reason]='3'
    $out=Measure-ReportWindow $observed $nativeLog 1000000 1000000 'observe' $calibration $artifact
    if($reason -eq 48){
        Check ($out.local_coverage -ceq 'PASS' -and $out.observe_qualifying_pairs -eq 3) 'Structurally supported numeric staleness was rejected.'
    }else{
        Check ($out.local_coverage -ceq 'FAIL' -and $out.observe_unsupported_pairs -eq 3 -and $out.observe_bypassed_pairs -eq 3) "Unsupported prepared reason $reason manufactured observe reachability."
    }
    Check ($nativeLog.pairs[0].entry_reason -eq $reason -and $nativeLog.pairs[0].return_reason -eq $reason) 'Probe reasons were lost during Enter/Return pairing.'
    $observed[-1].fields['reporting.reason_count.'+$reason]='0'
}
# Keep otherwise qualifying, fully paired native-format observe evidence. Only
# the authority transition's timestamp varies relative to the fixed score edge.
foreach($transitionQpc in @(999999,1000000,1000001)){
    $boundaryRecords=New-Object 'Collections.Generic.List[object]';$boundaryRecords.Add($observeStartup)
    $baseline=ScheduleState;$baseline.qpc=999998;$baseline.mode=2;$baseline.phase=5
    $boundaryRecords.Add($baseline)
    $transition=ScheduleState;$transition.sequence=2;$transition.qpc=$transitionQpc;$transition.mode=2;$transition.phase=5
    $transition.source_epoch=2;$transition.binding_epoch=2;$boundaryRecords.Add($transition)
    for($i=0;$i -lt 3;++$i){
        $entry=Build 4 (2*$i+3) ($i+1) (2000000+30000000*$i) 0
        $returned=Build 5 (2*$i+4) ($i+1) (2000000+30000000*$i) 0
        foreach($record in @($entry,$returned)){
            $record.request_sequence=0;$record.witness_sequence=0;$record.fresh=0
            $record.source_epoch=2;$record.binding_epoch=2;$boundaryRecords.Add($record)
        }
    }
    $boundaryLog=Read-ReportLog (LogFile ('epoch-boundary-'+$transitionQpc+'.jsonl') $boundaryRecords.ToArray()) $observeIdentity $run 16MB 1000000 301000000
    $out=Measure-ReportWindow $observed $boundaryLog 1000000 1000000 'observe' $calibration $artifact
    if($transitionQpc -lt 1000000){
        Check ($boundaryLog.epoch_baseline -ceq '2:2' -and !$boundaryLog.source_changes -and $out.local_coverage -ceq 'PASS') 'Transition before the fixed window invalidated the later stable epoch.'
    }else{
        Check ($boundaryLog.epoch_baseline -ceq '1:1' -and $boundaryLog.source_changes -and $out.local_coverage -ceq 'INCONCLUSIVE' -and $out.reason -ceq 'source-or-binding-epoch-change') 'First in-window rebind manufactured coverage PASS.'
    }
}
$withoutBaseline=New-Object 'Collections.Generic.List[object]';$withoutBaseline.Add($observeStartup)
for($i=2;$i -lt $boundaryRecords.Count;++$i){$record=$boundaryRecords[$i];$record.sequence-=1;$withoutBaseline.Add($record)}
$missingEpoch=Read-ReportLog (LogFile 'epoch-baseline-missing.jsonl' $withoutBaseline.ToArray()) $observeIdentity $run 16MB 1000000 301000000
$out=Measure-ReportWindow $observed $missingEpoch 1000000 1000000 'observe' $calibration $artifact
Check (!$missingEpoch.epoch_baseline_available -and $out.local_coverage -ceq 'INCONCLUSIVE' -and $out.reason -ceq 'pre-window-epoch-baseline-unavailable') 'Missing pre-window epoch baseline manufactured coverage PASS.'
$observeLog.pairs=@($observeLog.pairs[0],$observeLog.pairs[1])
$out=Measure-ReportWindow $observed $observeLog 1000000 1000000 'observe' $calibration $artifact
Check ($out.local_coverage -ceq 'INCONCLUSIVE') 'Two observe pairs manufactured reachability.'
$observed[-1].fields['reporting.fullSelected']='1'
$out=Measure-ReportWindow $observed $observeLog 1000000 1000000 'observe' $calibration $artifact
Check ($out.local_safety -ceq 'FAIL') 'Observe selection counter ignored.'

$calibRoot=Join-Path $caseRoot 'calibration';$null=[IO.Directory]::CreateDirectory($calibRoot)
function FixtureCalibration {
    $r=[ordered]@{schema=3;measurement_id='rs2-wrapper-own-deferred-v2';protocol_id='rs2-deferred-v2-fixed6000-1024';
        companion_sha256=$artifact;fixture_sha256=('B'*64);source_inventory_sha256=('C'*64);floor_ledger_sha256=('D'*64);
        compiler='MSVC-owned-fixture';configuration='Release-AMD64';qpc_frequency=1000000;coverage_pass=$true;
        pump_sample_count=7024;main_pump_sample_count=6000;main_management_sample_count=150;
        builder_sample_count=1024;builder_selected_count=1024;
        scope='outer-wrapper-minus-recorded-own-minus-inner-original';limitation='fixture-measured-not-hard-real-time'}
    for($i=0;$i -lt 4;++$i) {
        $count=@(6874,150,0,1024)[$i];$maximum=@(2,5,0,3)[$i]
        $r['class'+$i+'_sample_count']=$count;$r['class'+$i+'_residual_sum_ticks']=$count*$maximum
        $r['class'+$i+'_current_maximum_missing_ticks']=$maximum;$r['class'+$i+'_floor_ticks']=$maximum
        $r['class'+$i+'_eligible']=$count -gt 0
    }
    return $r
}
$fixtureCalibration=FixtureCalibration
$calibPath=Join-Path $calibRoot 'timing-calibration.json'
Save-ReportText $calibPath (($fixtureCalibration|ConvertTo-Json -Compress)+"`r`n")
$calibFiles=@{'dlls/RS2ServerFix.dll'=$artifact;'timing-calibration.json'=(Get-FileHash -LiteralPath $calibPath).Hash}
$c=Read-ReportTimingCalibration $calibFiles $calibRoot
Check ($c.qualified -and $c.class_floors[0].floor_ticks -eq 2 -and $c.class_floors[1].floor_ticks -eq 5 -and
    !$c.class_floors[2].eligible -and $c.class_floors[3].floor_ticks -eq 3 -and $c.builder_selected_count -eq 1024) 'Valid package-owned class calibration rejected.'
$calibFiles['dlls/RS2ServerFix.dll']='C'*64
Reject { Read-ReportTimingCalibration $calibFiles $calibRoot } 'Calibration for another companion accepted.'
$calibFiles['dlls/RS2ServerFix.dll']=$artifact;$calibFiles['timing-calibration.json']='C'*64
Reject { Read-ReportTimingCalibration $calibFiles $calibRoot } 'Changed calibration file accepted.'

foreach($kind in @('unselected','old-method','old-schema','wrong-protocol','bad-sum','lowered-floor','invented-class','unavailable-floor','available-current-denied','false-coverage','wrong-type','old-pooled')){
    $rejectRoot=Join-Path $caseRoot ('calibration-'+$kind);$null=[IO.Directory]::CreateDirectory($rejectRoot)
    $fixtureBad=FixtureCalibration
    switch($kind) {
        'unselected' {$fixtureBad.builder_selected_count=0}
        'old-method' {$fixtureBad.measurement_id='inert-originals-outer-minus-recorded-own'}
        'old-schema' {$fixtureBad.schema=2}
        'wrong-protocol' {$fixtureBad.protocol_id='rs2-other'}
        'bad-sum' {$fixtureBad.class0_residual_sum_ticks=13749}
        'lowered-floor' {$fixtureBad.class0_floor_ticks=1}
        'invented-class' {$fixtureBad.class2_eligible=$true}
        'unavailable-floor' {$fixtureBad.class2_floor_ticks=1}
        'available-current-denied' {$fixtureBad.class1_eligible=$false}
        'false-coverage' {$fixtureBad.main_management_sample_count=63}
        'wrong-type' {$fixtureBad.class0_eligible='true'}
        'old-pooled' {$fixtureBad.pump_maximum_missing_ticks=1259}
    }
    $rejectPath=Join-Path $rejectRoot 'timing-calibration.json';Save-ReportText $rejectPath ($fixtureBad|ConvertTo-Json -Compress)
    $rejectFiles=@{'dlls/RS2ServerFix.dll'=$artifact;'timing-calibration.json'=(Get-FileHash -LiteralPath $rejectPath).Hash}
    Reject { Read-ReportTimingCalibration $rejectFiles $rejectRoot } "Insufficient $kind calibration accepted."
}
$lowCoverage=FixtureCalibration;$lowCoverage.main_management_sample_count=63;$lowCoverage.coverage_pass=$false
$lowRoot=Join-Path $caseRoot 'calibration-low-coverage';$null=[IO.Directory]::CreateDirectory($lowRoot)
$lowPath=Join-Path $lowRoot 'timing-calibration.json';Save-ReportText $lowPath ($lowCoverage|ConvertTo-Json -Compress)
$lowFiles=@{'dlls/RS2ServerFix.dll'=$artifact;'timing-calibration.json'=(Get-FileHash -LiteralPath $lowPath).Hash}
$low=Read-ReportTimingCalibration $lowFiles $lowRoot
Check (!$low.qualified -and $low.class_floors[1].floor_ticks -eq 5) 'Failed coverage erased eligible floor evidence or qualified the candidate.'
$diagnosticSamples=@((Snapshot 1 0),(Snapshot 2 1))
$diagnosticA=Find-ReportBoundary $diagnosticSamples 1 'timing';$diagnosticB=Find-ReportBoundary $diagnosticSamples 2 'timing'
$lowPerformance=Measure-ReportPerformance $diagnosticA $diagnosticB 300000000 1000000 $low $artifact
Check ($low.integrity_valid -and $lowPerformance.bound_available -and $null -ne $lowPerformance.summed_upper_ticks -and
    $lowPerformance.pooled_sensitivity.available -and $lowPerformance.diagnostic_only -and
    $lowPerformance.pooled_sensitivity.diagnostic_only -and !$lowPerformance.epilogue_qualified -and
    $lowPerformance.verdict -ceq 'INCONCLUSIVE' -and $lowPerformance.measured -ceq 'PASS') 'Insufficient coverage erased valid comparisons or qualified diagnostic-only arithmetic.'
$diagnosticSamples[1].fields['reporting.duration.1.elapsed_ticks']='300000'
$lowPerformance=Measure-ReportPerformance $diagnosticA $diagnosticB 300000000 1000000 $low $artifact
Check ($lowPerformance.measured -ceq 'FAIL' -and $lowPerformance.verdict -ceq 'FAIL') 'Diagnostic-only calibration hid a proven raw performance failure.'
# Current sample count describes this run, but eligibility/floors describe the
# retained same-contract ledger. Historical zero is distinguishable from absent.
foreach($historyCase in @('positive','zero','unavailable')) {
    $historical=FixtureCalibration
    $historical.main_management_sample_count=0;$historical.coverage_pass=$false
    $historical.class0_sample_count=7024;$historical.class0_residual_sum_ticks=14048
    $historical.class1_sample_count=0;$historical.class1_residual_sum_ticks=0;$historical.class1_current_maximum_missing_ticks=0
    $historical.class1_floor_ticks=if($historyCase -ceq 'positive'){5}else{0}
    $historical.class1_eligible=$historyCase -cne 'unavailable'
    $historyRoot=Join-Path $caseRoot ('calibration-history-'+$historyCase);$null=[IO.Directory]::CreateDirectory($historyRoot)
    $historyPath=Join-Path $historyRoot 'timing-calibration.json';Save-ReportText $historyPath ($historical|ConvertTo-Json -Compress)
    $historyFiles=@{'dlls/RS2ServerFix.dll'=$artifact;'timing-calibration.json'=(Get-FileHash -LiteralPath $historyPath).Hash}
    $history=Read-ReportTimingCalibration $historyFiles $historyRoot
    $historySamples=@((Snapshot 1 0),(Snapshot 2 1))
    $historyA=Find-ReportBoundary $historySamples 1 'timing';$historyB=Find-ReportBoundary $historySamples 2 'timing'
    $historyPerformance=Measure-ReportPerformance $historyA $historyB 300000000 1000000 $history $artifact
    if($historyCase -ceq 'unavailable') {
        Check (!$history.class_floors[1].eligible -and !$historyPerformance.bound_available -and
            $null -eq $historyPerformance.summed_upper_ticks -and $historyPerformance.missing_called_classes -contains 1) 'Unobserved zero was inferred to be an available calibration.'
    } else {
        Check ($history.class_floors[1].eligible -and $history.class_floors[1].sample_count -eq 0 -and
            $history.class_floors[1].floor_ticks -eq $historical.class1_floor_ticks -and $historyPerformance.bound_available -and
            $historyPerformance.classes[1].epilogue_ticks_per_call -ceq [string]$historical.class1_floor_ticks -and
            $historyPerformance.diagnostic_only -and $historyPerformance.verdict -ceq 'INCONCLUSIVE' -and !$historyPerformance.epilogue_qualified) 'Historical eligibility was lost or insufficient coverage became qualifying.'
    }
}

# Optional empirical model: a separate identity-bound assessment, never a new
# meaning for the existing maximum-based qualification or its latency guard.
function FixtureAssessment($Bound) {
    $r=[ordered]@{schema=1;assessment_id='rs2-sustained-phase-mean-observe-v1';measurement_id=$Bound.measurement_id;
        protocol_id=$Bound.protocol_id;scope='post-capture-isolated-observe-only';mean_rule='max-all-run-phase-means-ceil';
        reference_frequency=10000000;companion_sha256=$artifact;timing_calibration_sha256=$Bound.calibration_sha256;
        floor_ledger_sha256=$Bound.floor_ledger_sha256;source_inventory_sha256=$Bound.source_inventory_sha256;model_provenance_sha256=('E'*64)}
    for($i=0;$i -lt 4;++$i){$r['class'+$i+'_coefficient_ticks']=@(17,16,0,16)[$i];$r['class'+$i+'_eligible']=$i -ne 2}
    return $r
}
$assessmentRoot=Join-Path $caseRoot 'assessment';$null=[IO.Directory]::CreateDirectory($assessmentRoot)
Copy-Item -LiteralPath $calibPath -Destination (Join-Path $assessmentRoot 'timing-calibration.json')
$assessmentFiles=@{'dlls/RS2ServerFix.dll'=$artifact;'timing-calibration.json'=(Get-FileHash -LiteralPath $calibPath).Hash}
$assessmentCal=Read-ReportTimingCalibration $assessmentFiles $assessmentRoot
Check (!(Read-ReportPerformanceAssessment $assessmentFiles $assessmentRoot $assessmentCal).available) 'Absent optional model enabled support.'
$assessmentPath=Join-Path $assessmentRoot 'performance-assessment.json'
Save-ReportText $assessmentPath ((FixtureAssessment $assessmentCal)|ConvertTo-Json -Compress)
$assessmentFiles['performance-assessment.json']=(Get-FileHash -LiteralPath $assessmentPath).Hash
$model=Read-ReportPerformanceAssessment $assessmentFiles $assessmentRoot $assessmentCal
Check ($model.available -and $model.qualified -and $model.frequency -eq 10000000 -and
    $model.class_coefficients[0].ticks -eq 17 -and !$model.class_coefficients[2].eligible -and
    $model.assessment_sha256 -ceq $assessmentFiles['performance-assessment.json']) 'Valid model contract rejected.'
Reject { Read-ReportPerformanceAssessment $assessmentFiles $assessmentRoot $absent } 'Model without calibration accepted.'
foreach($case in @('policy','domain','protocol','scope','clock','companion','calibration','ledger','source','digest','coefficient-type',
    'coefficient-limit','availability','unavailable-cost','bool-type','float','saturated','unknown','duplicate','oversize')) {
    $badModel=FixtureAssessment $assessmentCal
    switch($case){
        'policy' {$badModel.assessment_id='unreviewed'}
        'domain' {$badModel.measurement_id='rs2-wrapper-gap-diagnostic-v1'}
        'protocol' {$badModel.protocol_id='different'}
        'scope' {$badModel.scope='production'}
        'clock' {$badModel.reference_frequency=9999999}
        'companion' {$badModel.companion_sha256='F'*64}
        'calibration' {$badModel.timing_calibration_sha256='F'*64}
        'ledger' {$badModel.floor_ledger_sha256='F'*64}
        'source' {$badModel.source_inventory_sha256='F'*64}
        'digest' {$badModel.model_provenance_sha256='Z'*64}
        'coefficient-type' {$badModel.class0_coefficient_ticks='17'}
        'coefficient-limit' {$badModel.class0_coefficient_ticks=21}
        'availability' {$badModel.class2_eligible=$true}
        'unavailable-cost' {$badModel.class2_coefficient_ticks=1}
        'bool-type' {$badModel.class0_eligible='true'}
        'float' {$badModel.class0_coefficient_ticks=1.5}
        'saturated' {$badModel.class0_coefficient_ticks=[uint64]::MaxValue}
        'unknown' {$badModel['unexpected']=1}
    }
    $text=$badModel|ConvertTo-Json -Compress
    if($case -ceq 'duplicate'){$text=$text.Replace('{"schema":1,','{"schema":1,"schema":1,')}
    if($case -ceq 'oversize'){$text=' '*8193}
    $dir=Join-Path $caseRoot ('assessment-'+$case);$null=[IO.Directory]::CreateDirectory($dir)
    $path=Join-Path $dir 'performance-assessment.json';Save-ReportText $path $text
    $files=@{}+$assessmentFiles;$files['performance-assessment.json']=(Get-FileHash -LiteralPath $path).Hash
    Reject {Read-ReportPerformanceAssessment $files $dir $assessmentCal} "Invalid model $case accepted."
}
$changedFiles=@{}+$assessmentFiles;$changedFiles['performance-assessment.json']='F'*64
Reject {Read-ReportPerformanceAssessment $changedFiles $assessmentRoot $assessmentCal} 'Changed model digest accepted.'
$zeroRoot=Join-Path $caseRoot 'assessment-zero';$null=[IO.Directory]::CreateDirectory($zeroRoot)
$zeroModel=FixtureAssessment $assessmentCal;$zeroModel.class0_coefficient_ticks=0
$zeroPath=Join-Path $zeroRoot 'performance-assessment.json';Save-ReportText $zeroPath ($zeroModel|ConvertTo-Json -Compress)
$zeroFiles=@{}+$assessmentFiles;$zeroFiles['performance-assessment.json']=(Get-FileHash -LiteralPath $zeroPath).Hash
Check ((Read-ReportPerformanceAssessment $zeroFiles $zeroRoot $assessmentCal).class_coefficients[0].eligible) 'Observed zero was made unavailable.'

# Manifest integration checks real file/hash holding, no executable invocation.
foreach($case in @('listed','unlisted','changed')){
    $dir=Join-Path $caseRoot ('assessment-package-'+$case);$null=[IO.Directory]::CreateDirectory($dir);$manifest=@()
    foreach($relative in $script:ReportPackageFiles){$p=Join-Path $dir $relative.Replace('/','\');$null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($p));Save-ReportText $p 'owned inert file';$manifest+=(Get-FileHash -LiteralPath $p).Hash+'  '+$relative}
    $p=Join-Path $dir 'performance-assessment.json';Save-ReportText $p 'owned inert metadata'
    if($case -cne 'unlisted'){$hash=if($case -ceq 'changed'){'F'*64}else{(Get-FileHash -LiteralPath $p).Hash};$manifest+=$hash+'  performance-assessment.json'}
    Save-ReportText (Join-Path $dir 'SHA256SUMS') (($manifest -join "`r`n")+"`r`n")
    $held=New-Object 'Collections.Generic.List[IO.FileStream]'
    try {if($case -ceq 'listed'){$v=Read-ReportPackage $dir $held;Check ($v.Files.Count -eq 13) 'Optional model was made required or rejected.'}
        else{Reject {Read-ReportPackage $dir $held} "Unsafe optional manifest $case accepted."}}
    finally{foreach($s in $held){$s.Dispose()}}
}

function AssessmentSummary($Cal, [object[]]$Counts=@(1000,100,0,1), [object[]]$Own=@(1000,100,0,1), [uint64]$Window=300000000) {
    $start=Snapshot 1 0;$finish=Snapshot ($Window+1) 1
    for($i=0;$i -lt 4;++$i){$finish.fields['reporting.duration.'+$i+'.calls']=[string]$Counts[$i];$finish.fields['reporting.duration.'+$i+'.elapsed_ticks']=[string]$Own[$i];
        $finish.fields['reporting.duration.'+$i+'.maximum_ticks']=if($Counts[$i]){'1'}else{'0'}}
    $a=Find-ReportBoundary @($start,$finish) 1 'timing';$b=Find-ReportBoundary @($start,$finish) ($Window+1) 'timing'
    $perf=Measure-ReportPerformance $a $b $Window 1000000 $Cal $artifact
    return @{start_qpc='1';score_start_qpc='1';end_qpc=[string]($Window+1);local_safety='PASS';local_coverage='PASS';
        local_performance=$perf.verdict;performance=$perf;final_safety='AVAILABLE';collection_stop=$null;
        scored_counters=@{timing=@{complete=$true;counters=(Get-ReportWindowCounters $a $b 'timing')}}}
}
$modelCal=@{}+$assessmentCal;$modelCal.class_floors=@($assessmentCal.class_floors|ForEach-Object{@{}+$_})
$modelCal.class_floors[0].floor_ticks=[uint64]675 # Inert state: legacy aggregate above budget, unchanged tail remains safe.
$support=AssessmentSummary $modelCal
$projection=Measure-ReportSustainedModel $support 1000000 $modelCal $model $artifact
$decision=Complete-ReportTrialAssessment $support $projection $model 'observe' -Finalized
Check ($projection.state -ceq 'WITHIN_MODEL' -and $projection.projected_high_ticks -ceq '3303' -and
    $projection.latency_guard -ceq 'PASS' -and $support.local_performance -ceq 'INCONCLUSIVE' -and
    $decision.verdict -ceq 'SUPPORTED_OBSERVE_ONLY' -and !$decision.pilot_start_authorized -and
    $decision.not_production_qualification) 'Only legacy MAX aggregate must not veto distinctly labelled empirical support.'
Check ($projection.management.calls_per_second.lower_numerator -ceq '100000000' -and
    $projection.management.calls_per_second.denominator -ceq '300000000' -and
    $projection.management.own_us_per_call.upper_numerator -ceq '100000000') 'Management diagnostics changed units/window.'
Check ((Complete-ReportTrialAssessment $support $projection $model 'observe').verdict -ceq 'INCONCLUSIVE') 'Provisional result gained support before finalization.'
Check ((Complete-ReportTrialAssessment $support $projection $model 'repair' -Finalized).verdict -ceq 'NOT_APPLICABLE') 'Repair mode gained empirical support.'
Check ((Complete-ReportTrialAssessment $support $projection $model '' -Finalized).verdict -ceq 'INCONCLUSIVE') 'Unknown mode became applicable.'
foreach($case in @('safety','coverage','measured','latency-fail','latency-unknown','final','stop','coverage-unknown','model-missing')){
    $s=AssessmentSummary $modelCal;$m=Measure-ReportSustainedModel $s 1000000 $modelCal $model $artifact
    switch($case){'safety'{$s.local_safety='FAIL'} 'coverage'{$s.local_coverage='FAIL'} 'measured'{$s.performance.measured='FAIL'}
        'latency-fail'{$m.latency_guard='FAIL'} 'latency-unknown'{$m.latency_guard='INCONCLUSIVE'}
        'final'{$s.final_safety='UNAVAILABLE'} 'stop'{$s.collection_stop='operator-aborted'}
        'coverage-unknown'{$s.local_coverage='INCONCLUSIVE'} 'model-missing'{$m.available=$false}}
    $want=if($case -in 'safety','coverage','measured','latency-fail'){'NOT_SUPPORTED'}else{'INCONCLUSIVE'}
    Check ((Complete-ReportTrialAssessment $s $m $model 'observe' -Finalized).verdict -ceq $want) "Trial failed to veto $case."
}
$equal=AssessmentSummary $modelCal @(0,1,0,1) @(0,994,0,2) 1000000
$p=Measure-ReportSustainedModel $equal 1000000 $modelCal $model $artifact
Check ($p.projected_low_ticks -ceq '1000' -and $p.state -ceq 'ABOVE_MODEL' -and
    (Complete-ReportTrialAssessment $equal $p $model 'observe' -Finalized).verdict -ceq 'NOT_SUPPORTED') 'Equality passed model target.'
$equal.scored_counters.timing.counters['reporting.duration.1.elapsed_ticks'].minimum=993
$p=Measure-ReportSustainedModel $equal 1000000 $modelCal $model $artifact
Check ($p.state -ceq 'STRADDLES' -and (Complete-ReportTrialAssessment $equal $p $model 'observe' -Finalized).verdict -ceq 'INCONCLUSIVE') 'Model straddling became support.'
$equal.scored_counters.timing.counters['reporting.duration.1.elapsed_ticks'].maximum=993
Check ((Measure-ReportSustainedModel $equal 1000000 $modelCal $model $artifact).state -ceq 'WITHIN_MODEL') 'Strictly below model target rejected.'
$mixed=AssessmentSummary $modelCal @(0,1,0,1) @(0,1,0,997) 1000000
Check ((Measure-ReportSustainedModel $mixed 1000000 $modelCal $model $artifact).state -ceq 'ABOVE_MODEL') 'Builder cost omitted from mixed window.'
$unknown=AssessmentSummary $modelCal @(0,1,1,1) @(0,1,1,1)
$unknown.scored_counters.timing.counters['reporting.duration.2.calls'].minimum=0;$unknown.performance.classes[2].calls_min='0'
$p=Measure-ReportSustainedModel $unknown 1000000 $modelCal $model $artifact
Check (!$p.available -and $p.missing_called_classes -contains 2) 'Zero lower called class borrowed another coefficient.'
$uncertain=AssessmentSummary $modelCal;$uncertain.scored_counters.timing.counters['reporting.duration.1.calls'].minimum=0;$uncertain.performance.classes[1].calls_min='0'
Check ($null -eq (Measure-ReportSustainedModel $uncertain 1000000 $modelCal $model $artifact).management.own_us_per_call) 'Uncertain calls caused invented per-call mean.'
$missingTime=AssessmentSummary $modelCal;$missingTime.scored_counters.timing.complete=$false
Check (!(Measure-ReportSustainedModel $missingTime 1000000 $modelCal $model $artifact).available) 'Missing timing boundary was reconstructed.'
$noCoverage=@{}+$modelCal;$noCoverage.qualified=$false
Check (!(Measure-ReportSustainedModel $support 1000000 $noCoverage $model $artifact).available) 'Missing calibration coverage qualified model.'
$rounded=Measure-ReportSustainedModel $support 3 $modelCal $model $artifact
Check ($rounded.classes[0].runtime_coefficient_ticks -ceq '1') 'Runtime coefficient rounded down.'
$overflow=AssessmentSummary $modelCal @([uint64]9223372036854775807,1,0,1) @([uint64]9223372036854775807,1,0,1)
$p=Measure-ReportSustainedModel $overflow 1000000 $modelCal $model $artifact
Check (!$p.available -and $p.reason -ceq 'model-numeric-or-envelope-invalid' -and
    (Complete-ReportTrialAssessment $overflow $p $model 'observe' -Finalized).verdict -ceq 'NOT_SUPPORTED') 'Model overflow wrapped or concealed measured failure.'

# Execute only the orchestration's rejection path using local function stubs.
# No target process, native inventory executable, SDK, or log path is accessed.
$oldPackage=${function:Read-ReportPackage};$oldInventory=${function:Invoke-ReportInventory};$oldMarker=${function:Read-ReportMarker}
$ProcessId=123;$TargetRoot=Join-Path $caseRoot 'empty-server';$ReportRoot=Join-Path $caseRoot 'diagnostics'
$null=[IO.Directory]::CreateDirectory($TargetRoot);$null=[IO.Directory]::CreateDirectory($ReportRoot)
$ReportingRunDirectory='Z:\deliberately-missing-no-log'
function Read-ReportPackage { return @{Files=@{};ManifestHash=('D'*64)} }
function Invoke-ReportInventory($Package,$Files,$ServerRoot,$SelectedId,$Report) {
    Save-ReportText $Report "schema=1`r`nreporting.state=rejected`r`n"
    return @{fields=@{'reporting.current_ready'='false';'reporting.revoke_reasons'='0';'reporting.loss_reasons'='0'};exit_code=0;path=$Report}
}
function Read-ReportMarker { throw 'Rejected status must never request a marker/log.' }
try {
    Invoke-SteamReportCollection
    $folders=@(Get-ChildItem -LiteralPath $ReportRoot -Directory)
    Check ($folders.Count -eq 1) 'Rejected status evidence was not preserved.'
    $report=Get-Content -LiteralPath (Join-Path $folders[0].FullName 'collection.json') -Raw|ConvertFrom-Json
    Check ($report.status_first -and !$report.log_requested -and $report.local_coverage -ceq 'INCONCLUSIVE') 'Rejected/no-log path claimed coverage.'
    Check ($report.trial_assessment.verdict -ceq 'INCONCLUSIVE' -and !$report.trial_assessment.pilot_start_authorized) 'Unready status gained trial support.'
    Check (Test-Path -LiteralPath (Join-Path $folders[0].FullName 'inventory-0000.txt')) 'Rejected DATA evidence missing.'
} finally {
    Set-Item Function:Read-ReportPackage $oldPackage;Set-Item Function:Invoke-ReportInventory $oldInventory;Set-Item Function:Read-ReportMarker $oldMarker
}

# Reach the real successful finalization with Generic.List[object] measurement
# samples. Only external package/inventory/marker boundaries and waits are inert
# stubs; real configuration custody, prefix copying, log reconciliation, coverage
# arithmetic and JSON finalization still run. These timestamps are explicit
# synthetic fixture inputs, not reconstructed times from any operator capture.
$TargetRoot=Join-Path $caseRoot 'finalization-server';$ReportRoot=Join-Path $caseRoot 'finalization-reports'
$null=[IO.Directory]::CreateDirectory($TargetRoot);$null=[IO.Directory]::CreateDirectory($ReportRoot)
$inertExe=Join-Path $TargetRoot 'VNGame.exe';Save-ReportText $inertExe 'inert text fixture - never executed'
Save-ReportText (Join-Path $TargetRoot 'RS2SteamObserve.ini') "enabled=1`r`nmax_log_mib=16`r`n"
Save-ReportText (Join-Path $TargetRoot 'RS2SteamReport.ini') "schema=2`r`nmode=observe`r`n"
$ReportingRunDirectory=Join-Path $TargetRoot ('RS2SteamReport\fixture-PID123-'+$runId)
$null=[IO.Directory]::CreateDirectory($ReportingRunDirectory);$MarkerPath=$null
$fixtureFrequency=[uint64][Diagnostics.Stopwatch]::Frequency
$fixtureStart=$fixtureFrequency;$fixtureEnd=301*$fixtureFrequency;$fixtureFinal=302*$fixtureFrequency
$finalizeStartup=[ordered]@{}
foreach($key in $observeStartup.Keys){$finalizeStartup[$key]=$observeStartup[$key]}
$finalizeStartup.qpc_frequency=$fixtureFrequency;$finalizeStartup.directory=$ReportingRunDirectory
$finalizeRecords=New-Object 'Collections.Generic.List[object]';$finalizeRecords.Add($finalizeStartup)
$baseline=ScheduleState;$baseline.qpc=$fixtureStart-1;$baseline.mode=2;$baseline.phase=5;$finalizeRecords.Add($baseline)
for($i=0;$i -lt 4;++$i){
    # Three measured attempts span 60 seconds; the fourth is AFTER the endpoint
    # and appears only in the final independent safety read/log watermark.
    $entryQpc=if($i -lt 3){$fixtureStart+(10+30*$i)*$fixtureFrequency}else{$fixtureEnd+[uint64]($fixtureFrequency/2)}
    $sequence=if($i -lt 3){2*$i+2}else{9}
    $entry=Build 4 $sequence ($i+1) $entryQpc 0;$returned=Build 5 ($sequence+1) ($i+1) $entryQpc 0
    foreach($record in @($entry,$returned)){
        $record.request_sequence=0;$record.witness_sequence=0;$record.fresh=0;$finalizeRecords.Add($record)
    }
    if($i -ge 2){
        $anchor=Anchor $(if($i -eq 2){8}else{11}) $(if($i -eq 2){$fixtureEnd-1}else{$fixtureFinal-1})
        foreach($key in @('normal_attempts','normal_returns','build_sequence')){$anchor[$key]=$i+1}
        foreach($key in @('full_selected','selected_true','request_sequence','witness_sequence','distinct_selected_witnesses')){$anchor[$key]=0}
        for($class=0;$class -lt 4;++$class){
            $n=if($class -eq 1){100*($i+1)}elseif($class -eq 3){$i+1}else{0}
            $anchor.durations[$class].calls=$n;$anchor.durations[$class].elapsed_ticks=$n
            $anchor.durations[$class].maximum_ticks=if($n){1}else{0}
        }
        $finalizeRecords.Add($anchor)
    }
}
$eventText=@($finalizeRecords.ToArray()|ForEach-Object{$_|ConvertTo-Json -Depth 8 -Compress}) -join "`n"
Save-ReportText (Join-Path $ReportingRunDirectory 'events.jsonl') ($eventText+"`n")
$script:FinalizeFiles=@{'dlls/RS2ServerFix.dll'=$artifact;
    'config/RS2SteamObserve.ini'=(Get-FileHash -LiteralPath (Join-Path $TargetRoot 'RS2SteamObserve.ini')).Hash;
    'config/RS2SteamReport.ini'=(Get-FileHash -LiteralPath (Join-Path $TargetRoot 'RS2SteamReport.ini')).Hash}
$script:FinalizeInputs=@()
foreach($point in @(@($fixtureStart,0,1),@($fixtureEnd,3,8),@($fixtureFinal,4,11))){
    $sample=Snapshot $point[0] $point[1]
    foreach($key in @('fullSelected','selectedTrue','requestSequence','witnessSequence','distinctSelectedWitnesses')){$sample.fields['reporting.'+$key]='0'}
    $sample.fields['reporting.reportSequence']=[string]$point[2]
    $fields=@{pid='123';process_creation_filetime=[string]$created;process_image_path=$inertExe;
        host_sha256=$script:ReportHostHash;sdk_sha256=$script:ReportSdkHash;steamclient_sha256=$script:ReportClientHash;
        observed_bootstrap_sha256=('B'*64);bootstrap_sha256=('B'*64);observed_companion_sha256=$artifact;companion_sha256=$artifact;
        'reporting.mode'='2';'reporting.qpc_frequency'=[string]$fixtureFrequency;'reporting.ownerThreadId'='4';
        'reporting.schema'='2';'reporting.bytes'='1288';'reporting.artifact_version'='262400';'reporting.header_validity'='31';
        'reporting.pid'='123';'reporting.process_creation'=[string]$created;
        'reporting.lastOwnerQpc'=[string]$point[0];'reporting.observed_qpc'=[string]$point[0];
        expect='proxy-pass';deployment_mode='active';expected_recon='corrected';observed_recon='corrected';
        recon_sha256='F402D3262D39EC73E9B33E14CC4F74B06EC981ECDE94D59ADF67D905CC1DA2D5';
        constant_match='true';finding_count='0';result='pass';recon_artifact_result='pass'}
    foreach($key in $fields.Keys){$sample.fields[$key]=$fields[$key]}
    foreach($key in @('current_ready','captured','header_valid','owner_valid','identity_complete')){$sample.fields['reporting.'+$key]='true'}
    $sample.command_start_qpc=[uint64]($point[0]-13);$sample.command_end_qpc=[uint64]($point[0]+17)
    $script:FinalizeInputs+=,$sample
}
$expectedBrackets=@($script:FinalizeInputs|ForEach-Object{
    @{start=$_.command_start_qpc;end=$_.command_end_qpc;lower=$_.coverage_range.lower;upper=$_.coverage_range.upper}
})
$boundProbe=$script:FinalizeInputs[1]
$oldWatermark=$boundProbe.fields['reporting.timingAccountedThroughQpc']
$boundProbe.fields['reporting.timingAccountedThroughQpc']='0'
$bounds=Assert-ReportSnapshot $boundProbe $script:FinalizeInputs[0]
Check ($null -eq $bounds.timing_range -and $null -ne $bounds.coverage_range) 'Zero watermark discarded otherwise valid coverage.'
$boundProbe.fields['reporting.timingAccountedThroughQpc']=[string]$fixtureStart
$bounds=Assert-ReportSnapshot $boundProbe $script:FinalizeInputs[0]
Check ($bounds.timing_range.lower -eq $fixtureStart) 'Wide but live completed-accounting range rejected.'
$boundProbe.fields['reporting.timingAccountedThroughQpc']=[string]($fixtureEnd+1)
Reject { Assert-ReportSnapshot $boundProbe $script:FinalizeInputs[0] } 'Future completed-accounting watermark accepted.'
$boundProbe.fields['reporting.timingAccountedThroughQpc']=$oldWatermark
$script:FinalizeInventoryCalls=0;$script:FinalizeSleeps=0
function Test-ReportOperatorAbort { return $false }
function Read-ReportPackage { return @{Files=$script:FinalizeFiles;ManifestHash=('D'*64)} }
function Invoke-ReportInventory($Package,$Files,$ServerRoot,$SelectedId,$Report) {
    if($script:FinalizeInventoryCalls -ge $script:FinalizeInputs.Count){throw 'Unexpected extra inventory call.'}
    $sample=$script:FinalizeInputs[$script:FinalizeInventoryCalls];++$script:FinalizeInventoryCalls
    $sample.path=$Report
    Save-ReportText $Report ((@($sample.fields.Keys|Sort-Object|ForEach-Object{$_+'='+$sample.fields[$_]}) -join "`r`n")+"`r`n")
    return $sample
}
function Read-ReportMarker { return "owned inert startup marker`r`n" }
function Start-Sleep { param([int]$Seconds);++$script:FinalizeSleeps;if($Seconds -ne 1){throw 'Unexpected measurement wait.'} }
$realCalibration=${function:Read-ReportTimingCalibration};$realAssessment=${function:Read-ReportPerformanceAssessment}
$realHash=${function:Get-ReportHash};$successfulInventory=${function:Invoke-ReportInventory}
try {
    Invoke-SteamReportCollection
    $folders=@(Get-ChildItem -LiteralPath $ReportRoot -Directory)
    Check ($folders.Count -eq 1 -and $script:FinalizeInventoryCalls -eq 3 -and $script:FinalizeSleeps -eq 1) 'Successful finalization did not finish its exact inert inventory sequence.'
    $resultPath=Join-Path $folders[0].FullName 'collection.json'
    Check ((Test-Path -LiteralPath $resultPath) -and !(Test-Path -LiteralPath (Join-Path $folders[0].FullName 'collection-failure.txt'))) 'Successful collector finalization produced failure evidence instead of collection.json.'
    $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
    Check ($result.local_safety -ceq 'PASS' -and $result.local_coverage -ceq 'PASS' -and $result.local_performance -ceq 'INCONCLUSIVE') 'Finalization changed observe coverage or invented absent calibration.'
    Check ($result.trial_assessment.verdict -ceq 'INCONCLUSIVE') 'Missing model gained support during finalization.'
    Check ($result.start_qpc -ceq [string]$fixtureStart -and $result.end_qpc -ceq [string]$fixtureEnd -and $result.attempts_min -ceq '3' -and $result.attempts_max -ceq '3') 'Final safety sample replaced a measurement boundary or entered the denominator.'
    Check ($result.required_log_sequence -ceq '8' -and $result.copied_last_sequence -ceq '11' -and $result.observe_qualifying_pairs -eq 3) 'Final safety evidence/log watermark was dropped or scored as another attempt.'
    Check ($result.samples.Count -eq 3 -and $result.samples[2].file -ceq 'inventory-final.txt') 'Final independent safety sample is missing.'
    Check ($result.final_safety -ceq 'AVAILABLE' -and !$result.samples[2].measurement -and $result.samples[1].measurement) 'Final safety read was not explicitly excluded from scoring.'
    for($i=0;$i -lt 3;++$i){
        $expected=$expectedBrackets[$i];$saved=$result.samples[$i]
        Check ($saved.command_start_qpc -ceq [string]$expected.start -and $saved.command_end_qpc -ceq [string]$expected.end -and
            $saved.coverage_range.lower -eq $expected.lower -and $saved.coverage_range.upper -eq $expected.upper -and
            $saved.timing_range.lower -eq $expected.lower -and $saved.timing_range.upper -eq $expected.upper) 'Finalization reconstructed or changed an original inventory command/range bracket.'
        Check (Test-Path -LiteralPath (Join-Path $folders[0].FullName $saved.file)) 'Finalization omitted the raw inventory evidence file.'
    }
    Check ($result.status_scope -ceq 'independent-DATA-not-last-log-anchor' -and !$result.private_keys_collected -and
        $result.operator_smoke -ceq 'UNVERIFIED' -and $result.backend_client_effect -ceq 'UNVERIFIED') 'Finalization promoted local evidence or changed collection scope.'
    Check ($result.configurations.'RS2SteamReport.ini'.sha256 -ceq $result.configurations.'RS2SteamReport.ini'.after_sha256 -and
        (Test-Path -LiteralPath (Join-Path $folders[0].FullName 'events-before.jsonl')) -and
        (Test-Path -LiteralPath (Join-Path $folders[0].FullName 'events-after.jsonl'))) 'Finalization did not retain configuration custody and both raw log prefixes.'

    # Route metadata reads to owned files (not the real checkout's package).
    # Preserve the actual readers, finalization order and verdict calculation.
    $script:ModelFinalizeCase='valid'
    function Read-ReportTimingCalibration { return & $realCalibration $assessmentFiles $assessmentRoot }
    function Read-ReportPerformanceAssessment($Files,$Package,$Calibration) {
        if($script:ModelFinalizeCase -ceq 'invalid-model') {
            $dir=Join-Path $caseRoot 'assessment-policy';$files=@{}+$assessmentFiles
            $files['performance-assessment.json']=(Get-FileHash -LiteralPath (Join-Path $dir 'performance-assessment.json')).Hash
            return & $realAssessment $files $dir $Calibration
        }
        return & $realAssessment $assessmentFiles $assessmentRoot $Calibration
    }
    function Get-ReportHash($Stream) {
        $hash=& $realHash $Stream
        if($script:ModelFinalizeCase -ceq 'config-final' -and $script:FinalizeInventoryCalls -eq 3 -and
            $hash -ceq $script:FinalizeFiles['config/RS2SteamReport.ini']){return 'F'*64}
        return $hash
    }
    function Invoke-ReportInventory($Package,$Files,$ServerRoot,$SelectedId,$Report) {
        $sample=& $successfulInventory $Package $Files $ServerRoot $SelectedId $Report
        if([IO.Path]::GetFileName($Report) -ceq 'inventory-final.txt') {
            if($script:ModelFinalizeCase -ceq 'final-sticky') {
                $sample=@{}+$sample;$sample.fields=@{}+$sample.fields;$sample.fields['reporting.loss_reasons']='1'
                # The synthetic DATA and its preserved raw file describe the same fault.
                [IO.File]::WriteAllText($Report,((@($sample.fields.Keys|Sort-Object|ForEach-Object{$_+'='+$sample.fields[$_]}) -join "`r`n")+"`r`n"))
            }
        }
        if($script:ModelFinalizeCase -ceq 'prefix-partial' -and [IO.Path]::GetFileName($Report) -ceq 'inventory-0001.txt') {
            [IO.File]::AppendAllText((Join-Path $ReportingRunDirectory 'events.jsonl'),'{')
        }
        return $sample
    }
    foreach($case in @('valid','invalid-model','final-sticky','prefix-partial','config-final')) {
        $script:ModelFinalizeCase=$case;$script:FinalizeInventoryCalls=0;$script:FinalizeSleeps=0
        $ReportRoot=Join-Path $caseRoot ('model-finalization-'+$case);$null=[IO.Directory]::CreateDirectory($ReportRoot)
        if($case -in 'invalid-model','config-final') {
            Reject {Invoke-SteamReportCollection} "Finalization concealed $case."
            $folder=@(Get-ChildItem -LiteralPath $ReportRoot -Directory)[0]
            $saved=Get-Content -LiteralPath (Join-Path $folder.FullName 'collection-incomplete.json') -Raw|ConvertFrom-Json
            Check ($saved.trial_assessment.verdict -ceq 'INCONCLUSIVE' -and $saved.local_performance -ceq 'INCONCLUSIVE' -and
                !$saved.overall_qualified -and $saved.samples.Count -eq 3 -and
                !(Test-Path -LiteralPath (Join-Path $folder.FullName 'collection.json')) -and
                (Test-Path -LiteralPath (Join-Path $folder.FullName 'events-after.jsonl'))) "Finalization $case retained support or discarded evidence."
        } else {
            Invoke-SteamReportCollection
            $folder=@(Get-ChildItem -LiteralPath $ReportRoot -Directory)[0]
            $saved=Get-Content -LiteralPath (Join-Path $folder.FullName 'collection.json') -Raw|ConvertFrom-Json
            $want=switch($case){'valid'{'SUPPORTED_OBSERVE_ONLY'} 'final-sticky'{'NOT_SUPPORTED'} default{'INCONCLUSIVE'}}
            Check ($saved.trial_assessment.verdict -ceq $want -and !$saved.trial_assessment.pilot_start_authorized) "Incorrect final $case trial verdict."
        }
        if($case -ceq 'prefix-partial'){[IO.File]::WriteAllText((Join-Path $ReportingRunDirectory 'events.jsonl'),($eventText+"`n"),(New-Object Text.UTF8Encoding($false)))}
    }
    $script:ModelFinalizeCase='valid'

    # Deadline, stuck-QPC attempt backstop, operator stop and expiration while
    # waiting for writer progress must retain evidence without another helper.
    $script:CollectionStopCase=''
    $script:CollectorClockCalls=0
    function Get-ReportCollectorQpc {
        ++$script:CollectorClockCalls
        if ($script:CollectionStopCase -ceq 'clock' -and $script:CollectorClockCalls -gt 1) { return [uint64](340*$fixtureFrequency) }
        if ($script:CollectionStopCase -ceq 'final-wait' -and $script:FinalizeSleeps -gt 0) { return [uint64](340*$fixtureFrequency) }
        return [uint64](10*$fixtureFrequency)
    }
    function Test-ReportOperatorAbort { return $script:CollectionStopCase -ceq 'abort' }
    function Start-Sleep { param([int]$Seconds);++$script:FinalizeSleeps }
    function Invoke-ReportInventory($Package,$Files,$ServerRoot,$SelectedId,$Report) {
        $isFinal=[IO.Path]::GetFileName($Report) -ceq 'inventory-final.txt'
        if ($isFinal -and $script:CollectionStopCase -cne 'late-final') { throw 'Expired/aborted collection invoked final safety helper.' }
        $source=$script:FinalizeInputs[0]
        if ($script:FinalizeInventoryCalls -gt 0 -and $script:CollectionStopCase -in 'observed','sticky','final-wait','in-flight-abort','late-final') { $source=$script:FinalizeInputs[1] }
        if ($isFinal) { $source=$script:FinalizeInputs[2] }
        $sample=@{}+$source;$sample.fields=@{}+$source.fields;$sample.path=$Report
        if (($script:CollectionStopCase -in 'observed','sticky' -and $script:FinalizeInventoryCalls -gt 0) -or $isFinal) {
            $expired=331*$fixtureFrequency
            $sample.fields['reporting.observed_qpc']=[string]$expired;$sample.fields['reporting.lastOwnerQpc']=[string]$expired
            if (!$isFinal) { $sample.fields['reporting.timingAccountedThroughQpc']=[string]$fixtureStart }
            $sample.command_start_qpc=[uint64]($expired-13);$sample.command_end_qpc=[uint64]($expired+17)
            if ($script:CollectionStopCase -ceq 'sticky') { $sample.fields['reporting.loss_reasons']='1' }
        }
        ++$script:FinalizeInventoryCalls
        Save-ReportText $Report ((@($sample.fields.Keys|Sort-Object|ForEach-Object{$_+'='+$sample.fields[$_]}) -join "`r`n")+"`r`n")
        if ($script:CollectionStopCase -ceq 'in-flight-abort' -and $script:FinalizeInventoryCalls -gt 1) { throw 'Owned fixture interruption during helper.' }
        return $sample
    }
    foreach($stopCase in @('clock','observed','attempts','abort','final-wait','sticky','in-flight-abort','late-final')) {
        $script:CollectionStopCase=$stopCase;$script:CollectorClockCalls=0;$script:FinalizeInventoryCalls=0;$script:FinalizeSleeps=0
        $ReportRoot=Join-Path $caseRoot ('termination-'+$stopCase);$null=[IO.Directory]::CreateDirectory($ReportRoot)
        if($stopCase -ceq 'in-flight-abort') {
            Reject { Invoke-SteamReportCollection } 'In-flight helper interruption was hidden.'
            $folder=@(Get-ChildItem -LiteralPath $ReportRoot -Directory)[0]
            $incomplete=Get-Content -LiteralPath (Join-Path $folder.FullName 'collection-incomplete.json') -Raw|ConvertFrom-Json
            Check (!$incomplete.overall_qualified -and $incomplete.final_safety -ceq 'INCOMPLETE' -and
                $incomplete.samples.Count -eq 1 -and $incomplete.samples[0].command_start_qpc -ceq [string]$script:FinalizeInputs[0].command_start_qpc -and
                (Test-Path -LiteralPath (Join-Path $folder.FullName 'inventory-0001.txt')) -and $script:FinalizeInventoryCalls -eq 2) 'In-flight interruption lost completed evidence or invoked a later helper.'
            Check ($incomplete.trial_assessment.verdict -ceq 'INCONCLUSIVE') 'In-flight exception retained model support.'
            continue
        }
        Invoke-SteamReportCollection
        $folder=@(Get-ChildItem -LiteralPath $ReportRoot -Directory)[0]
        $stopped=Get-Content -LiteralPath (Join-Path $folder.FullName 'collection.json') -Raw|ConvertFrom-Json
        Check ($stopped.trial_assessment.verdict -cne 'SUPPORTED_OBSERVE_ONLY' -and !$stopped.trial_assessment.pilot_start_authorized) "Termination $stopCase retained model support."
        if($stopCase -ceq 'late-final') {
            Check ($script:FinalizeInventoryCalls -eq 3 -and $stopped.final_safety -ceq 'AVAILABLE' -and
                $stopped.collection_stop -ceq 'boundary-catch-up-deadline' -and !$stopped.overall_qualified -and
                !$stopped.samples[2].measurement) 'A final helper returning after the deadline silently qualified the collection.'
            continue
        }
        $expectedCalls=if($stopCase -ceq 'attempts'){73}elseif($stopCase -in 'observed','sticky','final-wait'){2}else{1}
        $expectedSafety=if($stopCase -ceq 'sticky'){'FAIL'}else{'UNVERIFIED'}
        Check ($script:FinalizeInventoryCalls -eq $expectedCalls -and $stopped.final_safety -ceq 'UNAVAILABLE' -and
            $stopped.local_safety -ceq $expectedSafety -and !$stopped.overall_qualified -and
            !(Test-Path -LiteralPath (Join-Path $folder.FullName 'inventory-final.txt'))) "Termination $stopCase invoked final helper or qualified missing safety."
        if($stopCase -ceq 'observed') { Check ($stopped.local_performance -ceq 'INCONCLUSIVE') 'Stalled accounting cutoff passed performance at expiry.' }
    }
} finally {
    Set-Item Function:Read-ReportTimingCalibration $realCalibration;Set-Item Function:Read-ReportPerformanceAssessment $realAssessment
    Set-Item Function:Get-ReportHash $realHash
    Set-Item Function:Read-ReportPackage $oldPackage;Set-Item Function:Invoke-ReportInventory $oldInventory;Set-Item Function:Read-ReportMarker $oldMarker
    Remove-Item Function:Start-Sleep
    Remove-Item Function:Get-ReportCollectorQpc
    Remove-Item Function:Test-ReportOperatorAbort
}
Write-Host "checks=$script:Checks failures=0; fixtures retained in $caseRoot"
