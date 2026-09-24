Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$scriptPath=Join-Path $repo 'tools\Collect-RS2CountProbe.ps1'
$tokens=$null;$parseErrors=$null
$null=[Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw ($parseErrors|Out-String)}
. $scriptPath
Add-Type -Path (Join-Path $repo 'tools\RS2CountProbe.cs'),(Join-Path $PSScriptRoot 'count_probe_fixture.cs')
$native=[RS2CountProbeTests.Checks]::Run()
$own=[RS2CountProbeTests.Checks]::OwnProcessRead()
$scriptChecks=0
function Assert($Value,[string]$Message){$script:scriptChecks++;if(!$Value){throw $Message}}
function Reject($Block,[string]$Message){$rejected=$false;try{& $Block}catch{$rejected=$true};Assert $rejected $Message}
$identity=@{
    schema='1';mode='runtime-inventory';pid='1234';companion_kind='companion-reporting'
    tool_sha256=$script:ProbePins.tool;manifest_sha256=$script:ProbePins.manifest
    host_sha256=$script:ProbePins.host;observed_bootstrap_sha256=$script:ProbePins.bootstrap
    observed_companion_sha256=$script:ProbePins.companion;sdk_sha256=$script:ProbePins.sdk;steamclient_sha256=$script:ProbePins.client
    recon_artifact_result='pass';'reporting.captured'='true';'reporting.header_valid'='true';'reporting.identity_complete'='true'
    'reporting.schema'='2';'reporting.bytes'='1288';'reporting.artifact_version'='262656';'reporting.mode'='3';'reporting.pid'='1234'
    'reporting.qpc_frequency'=[string][Diagnostics.Stopwatch]::Frequency
}
Assert-ProbeInventoryIdentity $identity 1234
Assert $true 'new reporting artifact accepted by the real inventory assertion'
$oldIdentity=$identity.Clone();$oldIdentity['reporting.artifact_version']='262400'
Reject {Assert-ProbeInventoryIdentity $oldIdentity 1234} 'old reporting artifact rejected with otherwise matching identity'
$f=@{'module_sha256.7'=$script:ProbePins.host;'module.7'='7ff700000000|26000000|1:2:3|<TARGET_ROOT>/Binaries/Win64/VNGame.exe'}
$hostModule=Get-ProbeHost $f;Assert ($hostModule.Base -eq [Convert]::ToUInt64('7ff700000000',16)) 'host module decoding'
$f['module_sha256.8']=$script:ProbePins.host;$f['module.8']=$f['module.7'];Reject {Get-ProbeHost $f} 'ambiguous module rejected'
Assert (Test-ProbeWithin 'E:\server' 'E:\server\x') 'inside target'
Assert (!(Test-ProbeWithin 'E:\server' 'E:\server-copy\x')) 'prefix sibling outside target'
foreach($bad in @('D:\','\\host\share','D:\foo\..\bar','D:\bad:stream','D:\bad.','D:\bad*','D:\bad[1]')){Reject {Resolve-ProbeDirectory $bad} ('unsafe directory '+$bad)}
$fields=@{process_creation_filetime='123';'reporting.run_id'='abc';'reporting.owner_valid'='true';'reporting.state'='ready'}
foreach($key in @('sourceEpoch','bindingEpoch','stopping','revoke_reasons','loss_reasons','phase','reason','builderBound','current_ready')){$fields['reporting.'+$key]='0'}
$a=@{fields=$fields;host=@{Base=1;Size=2};end_qpc=1};$b=@{fields=$fields.Clone();host=@{Base=1;Size=2};begin_qpc=4}
$raw=[pscustomobject]@{Stable=$true;BeginQpc=2;EndQpc=3}
Assert ((Get-ProbeCorrelation $a $b $raw) -eq 'nearby-stable-observations-not-an-atomic-event') 'stable does not claim atomic event'
$b.fields['reporting.reason']='27';Assert ((Get-ProbeCorrelation $a $b $raw) -eq 'status-transition') 'source rejection transition separated'
$b.fields=$fields.Clone();$b.fields['reporting.run_id']='different';Assert ((Get-ProbeCorrelation $a $b $raw) -eq 'identity-changed') 'PID/run change'
$b.fields=$fields.Clone();$b.begin_qpc=2;Assert ((Get-ProbeCorrelation $a $b $raw) -eq 'timing-inconsistent') 'cross-clock/inconsistent bracket'
$b.begin_qpc=4;$b.fields['reporting.state']='stale';Assert ((Get-ProbeCorrelation $a $b $raw) -eq 'reporting-state-outside-ready-or-not-ready') 'stale status not current correlation'
$memory=[RS2CountProbeTests.FakeMemory]::new();$reader=[RS2CountProbe.Reader]::new($memory,[RS2CountProbeTests.FakeMemory]::Base,[RS2CountProbeTests.FakeMemory]::Size)
$encoded=$reader.Capture()|ConvertTo-Json -Depth 8
Assert ($encoded -notmatch '"Identity"') 'no pointer tokens serialized'
$decoded=$encoded|ConvertFrom-Json;Assert ($decoded.Stable -and $decoded.Second.Humans -eq 64) 'serialized count fields'
Reject {Assert-ProbeReaderUnloaded} 'cached reader cannot masquerade as current source'
Write-Output ('PASS: '+$native+' synthetic reader checks; '+$own+' own-process Win32 checks; '+$scriptChecks+' PowerShell checks. No live game read or server mutation.')
