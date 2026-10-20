param(
    [uint32]$ProcessId=0,
    [string]$TargetRoot,
    [ValidateRange(1,120)][int]$Samples=3,
    [ValidateRange(0,30)][int]$IntervalSeconds=3,
    [string]$ReportRoot
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:ProbePins=@{
    tool='414F4F3FCC3B6CB338C8485E5B6FB21AE2453229DDDB9A52ED5A9171A849BF91'
    manifest='63D96BA7F55AC05EDBEE62C2FD9EFA2DA345D785863996C63AD5452B19B80FEF'
    host='0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393'
    bootstrap='114EC2545906ACD724947C8F955FCA7B8DA782940EC476D510D3C67498A0F0DC'
    # Exact locally built 0.6 bytes; re-pin if a reviewed code change rebuilds them.
    companion='62F3FFE70DCD71810C40A8812EF41F945BEAC3F9B461920F38E8A7F1143CD421'
    sdk='A44E5537939AE4EEBC69000589AA9B2437A667813A1657CC779198BAE9B815A9'
    client='8165D2A8E82753E5CD5AD985D6D08C2379E0AA8D0340669BCF05890584F51ACE'
}
function Resolve-ProbeDirectory([string]$Path) {
    if($Path -cnotmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or $Path -match '[\x00-\x1F"<>|?*/\[\]]'){
        throw 'Use a full local directory path, not an EXE, share or wildcard.'
    }
    foreach($part in $Path.Substring(3).TrimEnd('\').Split('\')){
        if(!$part -or $part -in @('.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ')){throw 'Ambiguous path component.'}
    }
    $item=Get-Item -LiteralPath $Path -Force
    if(!$item.PSIsContainer -or $item.FullName.Length -le 3){throw 'A non-root directory is required.'}
    $full=$item.FullName.TrimEnd('\');$cursor=$item
    while($null -ne $cursor){if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse paths are not accepted.'};$cursor=$cursor.Parent}
    if(([IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))).DriveType -ne [IO.DriveType]::Fixed){throw 'Use a fixed local drive.'}
    return $full
}
function Test-ProbeWithin([string]$Root,[string]$Path) {
    return $Path.Equals($Root,[StringComparison]::OrdinalIgnoreCase) -or $Path.StartsWith($Root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)
}
function Read-ProbeFields([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force
    if($item.Length -gt 8MB -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Invalid inventory report.'}
    $f=@{}
    foreach($line in [IO.File]::ReadLines($Path)){
        $split=$line.IndexOf('=');if($split -le 0){throw 'Malformed inventory line.'}
        $key=$line.Substring(0,$split);if($f.ContainsKey($key)){throw 'Duplicate inventory key.'}
        $f[$key]=$line.Substring($split+1)
    }
    return $f
}
function Assert-ProbeFields($Fields,$Expected) {
    foreach($key in $Expected.Keys){if(!$Fields.ContainsKey($key) -or $Fields[$key] -cne [string]$Expected[$key]){throw ('Inventory rejected: '+$key)}}
}
function Get-ProbeHost($Fields) {
    $hostMatches=New-Object 'Collections.Generic.List[object]'
    foreach($key in $Fields.Keys){
        if($key -cmatch '^module_sha256\.([0-9]+)$' -and $Fields[$key] -ceq $script:ProbePins.host){
            $slot=$Matches[1];$parts=$Fields['module.'+$slot].Split('|')
            if($parts.Count -ne 4 -or $parts[0] -cnotmatch '^[0-9a-fA-F]{1,16}$' -or $parts[1] -cnotmatch '^[0-9]+$'){throw 'Invalid host module record.'}
            $hostMatches.Add([pscustomobject]@{Base=[Convert]::ToUInt64($parts[0],16);Size=[uint32]$parts[1];Slot=$slot})
        }
    }
    if($hostMatches.Count -ne 1){throw 'Host module is missing or ambiguous.'}
    return $hostMatches[0]
}
function Assert-ProbeInventoryIdentity($Fields,[uint32]$SelectedPid) {
    # Shared by the real inventory path and its artifact-mismatch regression.
    Assert-ProbeFields $Fields @{
        schema='1';mode='runtime-inventory';pid=[string]$SelectedPid;companion_kind='companion-reporting'
        tool_sha256=$script:ProbePins.tool;manifest_sha256=$script:ProbePins.manifest
        host_sha256=$script:ProbePins.host;observed_bootstrap_sha256=$script:ProbePins.bootstrap
        observed_companion_sha256=$script:ProbePins.companion;sdk_sha256=$script:ProbePins.sdk;steamclient_sha256=$script:ProbePins.client
        recon_artifact_result='pass';'reporting.captured'='true';'reporting.header_valid'='true';'reporting.identity_complete'='true'
        'reporting.schema'='3';'reporting.bytes'='3896';'reporting.artifact_version'='393728';'reporting.pid'=[string]$SelectedPid
        'reporting.qpc_frequency'=[string][Diagnostics.Stopwatch]::Frequency
    }
    if(!$Fields.ContainsKey('reporting.mode') -or $Fields['reporting.mode'] -cnotin @('2','3')){throw 'CountProbe requires an explicit observe or repair reporting run.'}
}
function Invoke-ProbeInventory([string]$Package,[string]$Server,[uint32]$SelectedPid,[string]$Path) {
    $tool=Join-Path $Package 'rs2_runtime_inventory.exe';$manifest=Join-Path $Package 'qualified_x3audio_genuine.manifest'
    $begin=[Diagnostics.Stopwatch]::GetTimestamp()
    $errorPath=[IO.Path]::ChangeExtension($Path,'.stderr.txt')
    if(Test-Path -LiteralPath $errorPath){throw 'Inventory error output already exists.'}
    # Windows PowerShell 5.1 turns redirected native stderr into ErrorRecords.
    # Preserve it without Stop terminating before the helper's exit code/report.
    $previousPreference=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        $message=@(& $tool --pid ([string]$SelectedPid) --target-root $Server --expect proxy-pass --mode active --expected-recon corrected --companion-kind companion-reporting --bootstrap-sha256 $script:ProbePins.bootstrap --companion-sha256 $script:ProbePins.companion --genuine-manifest $manifest --report $Path 2> $errorPath)
        $code=$LASTEXITCODE
    }finally{$ErrorActionPreference=$previousPreference}
    $end=[Diagnostics.Stopwatch]::GetTimestamp()
    $textPath=[IO.Path]::ChangeExtension($Path,'.stdout.txt')
    $textWriter=[IO.StreamWriter]::new([IO.File]::Open($textPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read),[Text.UTF8Encoding]::new($false))
    try{foreach($line in $message){$textWriter.WriteLine([string]$line)}}finally{$textWriter.Dispose()}
    if(!(Test-Path -LiteralPath $Path)){throw ('Inventory produced no report; exit '+$code+'. No bypass.')}
    $f=Read-ProbeFields $Path
    Assert-ProbeInventoryIdentity $f $SelectedPid
    if($code -ne 0){throw ('Inventory identity/artifact check failed; exit '+$code)}
    Assert-ProbeFields $f @{'reporting.process_creation'=$f.process_creation_filetime}
    if($f['reporting.run_id'] -cnotmatch '^[0-9a-f]{32}$'){throw 'Invalid reporting run identity.'}
    return @{fields=$f;begin_qpc=$begin;end_qpc=$end;file=[IO.Path]::GetFileName($Path);host=(Get-ProbeHost $f)}
}
function Get-ProbeCorrelation($Before,$After,$Raw) {
    $a=$Before.fields;$b=$After.fields
    if($a.process_creation_filetime -cne $b.process_creation_filetime -or $a['reporting.run_id'] -cne $b['reporting.run_id'] -or
        $Before.host.Base -ne $After.host.Base -or $Before.host.Size -ne $After.host.Size){return 'identity-changed'}
    if(!$Raw.Stable){return 'raw-unavailable-or-changing'}
    if($Before.end_qpc -gt $Raw.BeginQpc -or $Raw.BeginQpc -gt $Raw.EndQpc -or $Raw.EndQpc -gt $After.begin_qpc){return 'timing-inconsistent'}
    if($a['reporting.owner_valid'] -cne 'true' -or $b['reporting.owner_valid'] -cne 'true'){return 'owner-status-unavailable'}
    if($a['reporting.state'] -notin @('ready','not-ready') -or $b['reporting.state'] -notin @('ready','not-ready')){return 'reporting-state-outside-ready-or-not-ready'}
    foreach($key in @('reporting.sourceEpoch','reporting.bindingEpoch','reporting.stopping','reporting.revoke_reasons','reporting.loss_reasons','reporting.phase','reporting.reason','reporting.builderBound','reporting.current_ready','reporting.state',
        'reporting.mode','reporting.transport.state','reporting.transport.reason','reporting.transport.pauseEpoch',
        'reporting.transport.transitionSequence','reporting.transport.qualifiedSinkEpoch','reporting.transport.actualRepairAdmitted',
        'reporting.transport.startupSubmitted','reporting.worker.startupObserved','reporting.worker.pauseReason',
        'reporting.worker.pauseConditionSequence','reporting.worker_pause_reason','reporting.worker_pause_changed',
        'reporting.fatal_transport_reason','reporting.log_identity_available')){
        if(!$a.ContainsKey($key) -or !$b.ContainsKey($key)){return 'v3-status-unavailable'}
        if($a[$key] -cne $b[$key]){return 'status-transition'}
    }
    return 'nearby-stable-observations-not-an-atomic-event'
}
function Test-ProbeQuit {
    if(![Console]::IsInputRedirected -and [Console]::KeyAvailable){return [Console]::ReadKey($true).Key -eq [ConsoleKey]::Q}
    return $false
}
function Format-ProbeReason([string]$Reason) {
    $names=@{'0'='none';'20'='unsupported-reinit';'21'='stopping';'22'='source-unavailable';'23'='source-lifetime';'24'='source-class';'25'='world-not-ready';'26'='travel';
        '27'='unsupported-counts';'28'='wrapper-mismatch';'29'='proxy-unavailable';'30'='unregistered';'31'='public-ip-unavailable';'32'='producer-pending';'33'='request-floor';'34'='producer-ambiguous';'35'='freshness-expired';
        '36'='task-not-ready';'48'='prepared-mismatch';'57'='spectators-present';'58'='capacity-mismatch'}
    if($names.ContainsKey($Reason)){return $names[$Reason]+' ('+$Reason+')'}
    return $Reason
}
function Format-ProbeTransportReason([string]$Reason) {
    $names=@('none','awaiting-logger','category-suppressed','force-flush-missing','framing-unsupported',
        'sink-unsupported','file-manager-unsupported','receipt-unavailable','reader-behind','receipt-overdue',
        'credit-pressure','same-file-requalification','receipt-gap','receipt-corrupt','file-identity-changed',
        'file-truncated','profile-unsafe','native-log-exception')
    [uint32]$value=0
    if($Reason -cmatch '^(0|[1-9][0-9]?)$' -and [uint32]::TryParse($Reason,[ref]$value) -and $value -lt $names.Count){return $names[$value]+' ('+$Reason+')'}
    return 'unavailable-or-invalid'
}
function Assert-ProbeReaderUnloaded {
    if('RS2CountProbe.Reader' -as [type]){throw 'A count reader is already loaded in this PowerShell process. Use Run-RS2CountProbe.cmd for a fresh session.'}
}
function Invoke-CountProbe {
    $output=$null;$stream=$null;$process=$null
    $locks=New-Object 'Collections.Generic.List[IDisposable]'
    try {
        if($script:ProbePins.companion -ceq ('0'*64)){throw 'This source copy is not a pinned kit yet. Use the matched packaged V3 CountProbe.'}
        if(![Environment]::Is64BitProcess){throw 'Run this kit with 64-bit Windows PowerShell.'}
        if(!$ProcessId){$entered=Read-Host 'PID of the running public server';if($entered -cnotmatch '^[1-9][0-9]{0,9}$' -or ![uint32]::TryParse($entered,[ref]$ProcessId)){throw 'Invalid PID.'}}
        if(!$TargetRoot){$TargetRoot=Read-Host 'Full server root directory (not Binaries/Win64 or the EXE)'}
        $server=Resolve-ProbeDirectory $TargetRoot;$package=Resolve-ProbeDirectory $PSScriptRoot
        if((Test-ProbeWithin $server $package) -or (Test-ProbeWithin $package $server)){throw 'Keep this kit outside the server directory.'}
        if(!$ReportRoot){
            $parent=[IO.Path]::GetDirectoryName($package)
            if($parent.Length -le 3){throw 'Extract the kit under a folder such as E:\RS2Capture, not directly under the drive root.'}
            $ReportRoot=Join-Path $parent 'reports'
        }
        if(!(Test-Path -LiteralPath $ReportRoot)){
            $parent=Resolve-ProbeDirectory ([IO.Path]::GetDirectoryName($ReportRoot));$leaf=[IO.Path]::GetFileName($ReportRoot)
            if($leaf -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$'){throw 'Invalid report directory name.'}
            $candidate=Join-Path $parent $leaf
            if((Test-ProbeWithin $server $candidate) -or (Test-ProbeWithin $package $candidate)){throw 'Reports must be outside server and kit.'}
            $null=New-Item -ItemType Directory -Path $candidate
        }
        $reportBase=Resolve-ProbeDirectory $ReportRoot
        if((Test-ProbeWithin $server $reportBase) -or (Test-ProbeWithin $package $reportBase)){throw 'Reports must be outside server and kit.'}
        foreach($pair in @(@('rs2_runtime_inventory.exe','tool'),@('qualified_x3audio_genuine.manifest','manifest'))){
            $file=Get-Item -LiteralPath (Join-Path $package $pair[0]) -Force
            if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw ('Package member is not a plain file: '+$pair[0])}
            $locks.Add([IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
            if((Get-FileHash -LiteralPath $file.FullName).Hash -cne $script:ProbePins[$pair[1]]){throw ('Package identity failed: '+$pair[0])}
        }
        $reader=Get-Item -LiteralPath (Join-Path $package 'RS2CountProbe.cs') -Force
        if($reader.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reader source must be a plain file.'}
        Assert-ProbeReaderUnloaded
        $locks.Add([IO.File]::Open($reader.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
        $locks.Add([IO.File]::Open($PSCommandPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
        Add-Type -Path $reader.FullName
        $output=Join-Path $reportBase ('RS2CountProbe-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-PID'+$ProcessId+'-'+[Guid]::NewGuid().ToString('N'))
        $null=New-Item -ItemType Directory -Path $output
        Write-Host ('Evidence folder: '+$output)
        Write-Host 'Read-only. Q stops collection after the current sample is safely saved. No server restart.'
        $stream=[IO.StreamWriter]::new([IO.File]::Open((Join-Path $output 'counts.jsonl'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read),[Text.UTF8Encoding]::new($false));$stream.AutoFlush=$true
        $stream.WriteLine(([ordered]@{type='startup';schema=1;version='0.3.0';reporting_schema=3;utc=[DateTime]::UtcNow.ToString('o');pid=$ProcessId;
            samples_requested=$Samples;interval_seconds=$IntervalSeconds;reader_sha256=(Get-FileHash -LiteralPath $reader.FullName).Hash;
            script_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash;meaning='Nearby read-only samples, not exact past DLL failure values or proof of backend recovery.'}|ConvertTo-Json -Compress))
        $identity=$null;$completed=0;$stop='sample-limit'
        for($i=0;$i -lt $Samples;++$i){
            if(Test-ProbeQuit){$stop='operator-q';break}
            Write-Host ('[{0}/{1}] Checking identity/status before sample; Q stops after the current sample.' -f ($i+1),$Samples)
            $before=Invoke-ProbeInventory $package $server $ProcessId (Join-Path $output ('inventory-{0:D3}-before.txt' -f $i))
            if($null -eq $identity){
                $identity=$before
                $process=[RS2CountProbe.ProcessMemory]::new($ProcessId,[uint64]$before.fields.process_creation_filetime)
                $probe=[RS2CountProbe.Reader]::new($process,$before.host.Base,$before.host.Size)
            }elseif($before.fields.process_creation_filetime -cne $identity.fields.process_creation_filetime -or $before.fields['reporting.run_id'] -cne $identity.fields['reporting.run_id'] -or $before.host.Base -ne $identity.host.Base -or $before.host.Size -ne $identity.host.Size){throw 'Selected process/run changed; no reattachment.'}
            $raw=$probe.Capture()
            # Save immediately; an exit or failed after-inventory must not discard the raw observation.
            $stream.WriteLine(([ordered]@{type='raw';sample=$i;utc=[DateTime]::UtcNow.ToString('o');before=$before.file;observation=$raw}|ConvertTo-Json -Depth 8 -Compress))
            Write-Host ('[{0}/{1}] Checking identity/status after sample.' -f ($i+1),$Samples)
            $after=Invoke-ProbeInventory $package $server $ProcessId (Join-Path $output ('inventory-{0:D3}-after.txt' -f $i))
            $correlation=Get-ProbeCorrelation $before $after $raw
            $stream.WriteLine(([ordered]@{type='bracket';sample=$i;before=$before.file;after=$after.file;
                before_begin_qpc=$before.begin_qpc;before_end_qpc=$before.end_qpc;after_begin_qpc=$after.begin_qpc;after_end_qpc=$after.end_qpc;
                correlation=$correlation}|ConvertTo-Json -Depth 6 -Compress))
            if($correlation -eq 'identity-changed'){throw 'Process/run identity changed across sample; no reattachment.'}
            ++$completed
            $counts=if($raw.Stable){
                $checks=if($raw.Second.FailedCountChecks.Length){$raw.Second.FailedCountChecks -join ','}else{'none'}
                $readiness=if($raw.Second.ReadinessNotes.Length){$raw.Second.ReadinessNotes -join ','}else{'none'}
                'humans={0} bots={1} spectators={2} max={3}; sampled_checks={4}; readiness={5}' -f $raw.Second.Humans,$raw.Second.Bots,$raw.Second.Spectators,$raw.Second.Maximum,$checks,$readiness
            }else{$raw.State+'; pass='+$raw.Pass+' stage='+$raw.Stage+'; '+$raw.Detail}
            $reason=if($after.fields.ContainsKey('reporting.reason')){Format-ProbeReason $after.fields['reporting.reason']}else{'unavailable'}
            $transport=if($after.fields.ContainsKey('reporting.transport.reason')){Format-ProbeTransportReason $after.fields['reporting.transport.reason']}else{'unavailable'}
            $worker=if($after.fields.ContainsKey('reporting.worker_pause_reason')){Format-ProbeTransportReason $after.fields['reporting.worker_pause_reason']}else{'unavailable'}
            Write-Host ('[{0}/{1}] {2}; DLL={3} runtime_reason={4}; transport_reason={5}; worker_gate={6}; {7}' -f $completed,$Samples,$counts,$after.fields['reporting.state'],$reason,$transport,$worker,$correlation)
            if(Test-ProbeQuit){$stop='operator-q';break}
            if($i+1 -lt $Samples){for($wait=0;$wait -lt $IntervalSeconds*5;++$wait){Start-Sleep -Milliseconds 200;if(Test-ProbeQuit){$stop='operator-q';break}};if($stop -eq 'operator-q'){break}}
        }
        $stream.WriteLine(([ordered]@{type='end';utc=[DateTime]::UtcNow.ToString('o');samples_completed=$completed;stop=$stop;verdict='diagnostic-only-no-runtime-or-recovery-PASS'}|ConvertTo-Json -Compress))
        Write-Host ('Saved '+$completed+' samples. Return the whole evidence folder; no PASS is required.')
    }catch{
        $failure=$_
        if($stream){try{$stream.WriteLine(([ordered]@{type='error';utc=[DateTime]::UtcNow.ToString('o');message=$failure.Exception.Message}|ConvertTo-Json -Compress))}catch{}}
        if($output){Write-Host ('Preserve incomplete evidence: '+$output)}
        throw $failure
    }finally{if($process){$process.Dispose()};foreach($held in $locks){$held.Dispose()};if($stream){$stream.Dispose()}}
}
if($MyInvocation.InvocationName -ne '.') {Invoke-CountProbe}
