param([string]$HelperPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (!$HelperPath) { $HelperPath=Join-Path $PSScriptRoot '..\tools\Request-LeechRecovery.ps1' }
. $HelperPath
$script:Checks=0
function Check-Leech([bool]$Condition,[string]$Name) {
    ++$script:Checks
    if (!$Condition) { throw "CHECK failed: $Name" }
}
function Reject-Leech([scriptblock]$Action,[string]$Name) {
    $rejected=$false
    try { & $Action | Out-Null } catch { $rejected=$true }
    Check-Leech $rejected $Name
}
$fixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('rs2-leech-control-fixture-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
if (!$fixtureRoot.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase) -or
    $fixtureRoot.StartsWith('E:\rs2v_trainingsrv',[StringComparison]::OrdinalIgnoreCase)) { throw 'Fixture path custody failed.' }
$user=[Security.Principal.WindowsIdentity]::GetCurrent()
try { $operatorSid=$user.User.Value } finally { $user.Dispose() }
$security=New-Object Security.AccessControl.DirectorySecurity
$security.SetSecurityDescriptorSddlForm('O:'+$operatorSid+'G:BAD:P(A;OICI;FA;;;'+$operatorSid+')(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)')
Set-Acl -LiteralPath $fixtureRoot -AclObject $security
$hash='A'*64; $run='000102030405060708090a0b0c0d0e0f'
$fields=[ordered]@{
    'schema'='1';'mode'='runtime-inventory';'pid'='73';'result'='pass';'tool_sha256'=$hash;
    'bootstrap_sha256'=$hash;'companion_sha256'=$hash;'observed_bootstrap_sha256'=$hash;
    'observed_companion_sha256'=$hash;'companion_kind'='companion-reporting';
    'process_image_path'='E%3A/rs2v_trainingsrv/Binaries/Win64/VNGame.exe';
    'host_sha256'='0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393';
    'reporting.header_valid'='true';'reporting.artifact_version'='459008';'reporting.pid'='73';
    'reporting.run_id'=$run;'reporting.current_ready'='true';'recovery.snapshot_result'='Coherent';
    'recovery.schema'='1';'recovery.bytes'='256';'recovery.artifact_version'='459008';
    'recovery.pid'='73';'recovery.run_id'=$run;'recovery.header_ready'='1';'recovery.owner_sequence'='2'
}
foreach ($key in $script:LeechPayloadNames) { $fields['recovery.'+$key]='0' }
$fields['recovery.phase']='1';$fields['recovery.flags']='1';$fields['recovery.transition_sequence']='1'
$report=Join-Path $fixtureRoot 'inventory.txt'
$completed=$false
function Write-LeechFixtureReport {
    $lines=@($fields.GetEnumerator() | ForEach-Object { $_.Key+'='+$_.Value })
    [IO.File]::WriteAllLines($report,$lines,[Text.Encoding]::ASCII)
}
try {
    Initialize-LeechFileApi
    Assert-LeechAcl ('O:'+$operatorSid+'G:BAD:P(A;;FA;;;'+$operatorSid+')(A;;FR;;;BU)') $operatorSid $false
    ++$script:Checks
    Reject-Leech { Assert-LeechAcl 'O:BAG:BAD:P(A;;FA;;;BA)(A;;FW;;;BU)' $operatorSid $false } 'unapproved writer rejected'
    Reject-Leech { Assert-LeechAcl 'O:BUG:BAD:P(A;;FA;;;BA)(A;;FR;;;BU)' $operatorSid $false } 'unapproved owner rejected'
    Write-LeechFixtureReport
    $identity=Read-LeechInventoryIdentity $report 73 $hash $hash $hash
    Check-Leech ($identity.Pid -eq 73 -and $identity.RunId -ceq $run) 'matching current-run inventory'
    $initialFields=@{};foreach($key in $fields.Keys){$initialFields[$key]=$fields[$key]}
    $fields['recovery.phase']='10';$fields['recovery.flags']='2097665';$fields['recovery.reason']='40';$fields['recovery.outcome']='1'
    $fields['recovery.operation_sequence']='1';$fields['recovery.transition_sequence']='4'
    Write-LeechFixtureReport
    $retryIdentity=Read-LeechInventoryIdentity $report 73 $hash $hash $hash
    Check-Leech ($retryIdentity.RunId -ceq $run) 'explicit retryable preflight accepted'
    $fields['recovery.reason']='18';$fields['recovery.outcome']='4';Write-LeechFixtureReport
    $loggingRetry=Read-LeechInventoryIdentity $report 73 $hash $hash $hash
    Check-Leech ($loggingRetry.RunId -ceq $run) 'recording-refused preflight accepted after readiness restored'
    $fields['recovery.reason']='40';$fields['recovery.outcome']='1'
    foreach($pair in @(@('recovery.flags','2097729'),@('recovery.native_stage','1'),@('recovery.resource_phase','1'),
        @('recovery.exception_code','1'),@('recovery.reason','26'),@('recovery.outcome','9'),@('recovery.phase','9'))) {
        $old=$fields[$pair[0]];$fields[$pair[0]]=$pair[1];Write-LeechFixtureReport
        Reject-Leech {Read-LeechInventoryIdentity $report 73 $hash $hash $hash} ('unsafe retry rejected '+$pair[0])
        $fields[$pair[0]]=$old
    }
    foreach($key in @($fields.Keys)){$fields[$key]=$initialFields[$key]};Write-LeechFixtureReport
    $faults=@{
        'recovery.snapshot_result'='Busy'; 'recovery.artifact_version'='327680';
        'reporting.current_ready'='false'; 'reporting.run_id'=('1'*32);
        'recovery.phase'='0'; 'recovery.flags'='5';'recovery.operation_sequence'='1';
        'process_image_path'='E:\rs2v_trainingsrv\Binaries\Win64\VNGame.exe'
    }
    foreach ($pair in $faults.GetEnumerator()) {
        $old=$fields[$pair.Key];$fields[$pair.Key]=$pair.Value;Write-LeechFixtureReport
        Reject-Leech { Read-LeechInventoryIdentity $report 73 $hash $hash $hash } ('rejected '+$pair.Key)
        $fields[$pair.Key]=$old
    }
    $fields['recovery.unused_quota']='0';Write-LeechFixtureReport
    Reject-Leech { Read-LeechInventoryIdentity $report 73 $hash $hash $hash } 'unknown recovery field rejected'
    $fields.Remove('recovery.unused_quota');Write-LeechFixtureReport
    $pilotPath='E:\servertwo\Binaries\Win64\VNGame_pr2.exe'
    $oldImage=$fields['process_image_path']
    $fields['process_image_path']='E%3A/servertwo/Binaries/Win64/VNGame_pr2.exe'
    $fields['process_creation_filetime']='12345';$fields['reporting.process_creation']='12345'
    Write-LeechFixtureReport
    $pilotIdentity=Read-LeechInventoryIdentity $report 73 $hash $hash $hash $pilotPath '12345'
    Check-Leech ($pilotIdentity.Pid -eq 73 -and $pilotIdentity.RunId -ceq $run) 'explicit pilot image/creation identity'
    foreach($key in @('process_creation_filetime','reporting.process_creation','process_image_path')) {
        $original=$fields[$key];$fields[$key]=if($key -ceq 'process_image_path'){'E%3A/serverone/Binaries/Win64/VNGame_pr2.exe'}else{'12346'}
        Write-LeechFixtureReport
        Reject-Leech {Read-LeechInventoryIdentity $report 73 $hash $hash $hash $pilotPath '12345'} ('pilot identity rejects '+$key)
        $fields[$key]=$original
    }
    $fields['process_image_path']=$oldImage
    $fields.Remove('process_creation_filetime');$fields.Remove('reporting.process_creation');Write-LeechFixtureReport
    [IO.File]::AppendAllText($report,"pid=73`r`n",[Text.Encoding]::ASCII)
    Reject-Leech { Read-LeechInventoryIdentity $report 73 $hash $hash $hash } 'duplicate inventory identity rejected'
    $message=New-LeechPipeMessage $identity
    Check-Leech ($message.Path -ceq ('\\.\pipe\RS2LeechRecovery.73.'+$run)) 'exact local PID/run endpoint'
    Check-Leech ($message.Bytes.Length -le 512) 'bounded request'
    $request=[Text.Encoding]::ASCII.GetString($message.Bytes) | ConvertFrom-Json
    Check-Leech ($request.pid -eq 73 -and $request.run_id -ceq $run -and $request.training_root -ceq 'E:\rs2v_trainingsrv' -and $request.action -ceq 'finish-recreate') 'fixed request identity/action/root'
    $pilotScope=[pscustomobject]@{Schema=2;Root='E:\servertwo'}
    $pilotMessage=New-LeechPipeMessage $identity $pilotScope
    $pilotRequest=[Text.Encoding]::ASCII.GetString($pilotMessage.Bytes) | ConvertFrom-Json
    Check-Leech ($pilotRequest.schema -eq 2 -and $pilotRequest.server_root -ceq $pilotScope.Root -and
        !$pilotRequest.PSObject.Properties['training_root']) 'pilot schema/root do not inherit training permission'
    Reject-Leech {New-LeechPipeMessage $identity ([pscustomobject]@{Schema=1;Root='E:\servertwo'})} 'training request cannot target production root'
    Reject-Leech {New-LeechPipeMessage $identity ([pscustomobject]@{Schema=3;Root='E:\servertwo'})} 'unsupported request schema rejected'
    foreach($root in @('E:\','E:server','E:/server','E:\server\child','E:\..','E:\server.','E:\server name','\\server\share','\\?\E:\server','E:\server~1')) {
        Reject-Leech {Assert-LeechRoot $root} ('root escape rejected '+$root)
    }
    Reject-Leech {Assert-LeechRoot "E:\servertwo`n"} 'trailing newline is not a root terminator'
    $permissionPath=Join-Path $fixtureRoot 'RS2LeechRecovery.ini'
    $pilotPermission="schema=2`npermission=manual-pilot-finish-recreate`nserver_root=E:\servertwo`noperator_sid=$operatorSid`n"
    [IO.File]::WriteAllText($permissionPath,$pilotPermission,[Text.Encoding]::ASCII)
    $permission=Read-LeechPermission $permissionPath 'E:\servertwo'
    Check-Leech ($permission.ConsoleTrigger -ceq 'disabled') 'console defaults to disabled'
    foreach($choice in @('disabled','server-admin')) {
        [IO.File]::WriteAllText($permissionPath,($pilotPermission+"console_trigger=$choice`n"),[Text.Encoding]::ASCII)
        $withConsole=Read-LeechPermission $permissionPath 'E:\servertwo'
        Check-Leech ($withConsole.ConsoleTrigger -ceq $choice) 'explicit supported console opt-in'
    }
    foreach($extra in @("console_trigger=enabled`n","console_trigger=server-admin`nconsole_trigger=disabled`n")) {
        [IO.File]::WriteAllText($permissionPath,($pilotPermission+$extra),[Text.Encoding]::ASCII)
        Reject-Leech {Read-LeechPermission $permissionPath 'E:\servertwo'} 'invalid or duplicate console opt-in refused'
    }
    $trainingPermission="schema=1`npermission=training-finish-recreate`ntraining_root=E:\rs2v_trainingsrv`noperator_sid=$operatorSid`n"
    [IO.File]::WriteAllText($permissionPath,$trainingPermission,[Text.Encoding]::ASCII)
    $training=Read-LeechPermission $permissionPath
    Check-Leech ($training.Schema -eq 1 -and $training.Root -ceq 'E:\rs2v_trainingsrv' -and
        $training.OperatorSid -ceq $operatorSid -and $training.ConsoleTrigger -ceq 'disabled') 'valid legacy training permission remains accepted'
    [IO.File]::WriteAllText($permissionPath,($trainingPermission+"console_trigger=disabled`n"),[Text.Encoding]::ASCII)
    Reject-Leech {Read-LeechPermission $permissionPath} 'training schema does not admit console entry point'
    [IO.File]::WriteAllText($permissionPath,$pilotPermission,[Text.Encoding]::ASCII)
    Check-Leech ($permission.Schema -eq 2 -and $permission.Root -ceq 'E:\servertwo' -and $permission.OperatorSid -ceq $operatorSid) 'explicit pilot permission scope'
    Reject-Leech {Read-LeechPermission $permissionPath 'E:\serverone'} 'different instance permission rejected'
    Reject-Leech {Read-LeechPermission $permissionPath} 'pilot permission does not select a default arbitrary server'
    [IO.File]::WriteAllText($permissionPath,$pilotPermission.Replace('manual-pilot-finish-recreate','training-finish-recreate'),[Text.Encoding]::ASCII)
    Reject-Leech {Read-LeechPermission $permissionPath 'E:\servertwo'} 'schema/permission mismatch rejected'
    Reject-Leech { New-LeechPipeMessage ([pscustomobject]@{Pid=0;RunId=$run}) } 'zero PID rejected'
    Reject-Leech { New-LeechPipeMessage ([pscustomobject]@{Pid=73;RunId=('0'*32)}) } 'zero run rejected'
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
public sealed class OwnedLeechPipeFixture : IDisposable {
    readonly NamedPipeServerStream server;
    readonly Thread worker;
    public byte[] Message;
    public Exception Error;
    public OwnedLeechPipeFixture(string name) {
        server = new NamedPipeServerStream(name, PipeDirection.In, 1,
            PipeTransmissionMode.Message, PipeOptions.None);
        worker = new Thread(() => {
            try {
                server.WaitForConnection();
                var bytes = new byte[513];
                int count = server.Read(bytes, 0, bytes.Length);
                Message = new byte[count]; Array.Copy(bytes, Message, count);
            } catch (Exception error) { Error = error; }
        });
        worker.IsBackground = true; worker.Start();
    }
    public bool Wait() { return worker.Join(3000); }
    public void Dispose() { server.Dispose(); worker.Join(3000); }
}
'@
    $ownPid=[uint32][Diagnostics.Process]::GetCurrentProcess().Id
    $ownLease=New-Object RS2LeechManual.ProcessLease($ownPid)
    try {
        Check-Leech ($ownLease.Pid -eq $ownPid -and $ownLease.Creation -gt 0 -and $ownLease.OwnerSid -ceq $operatorSid -and
            [IO.Path]::IsPathRooted($ownLease.Path)) 'read-only own process identity and owner'
        $ownLease.Verify()
    } finally {$ownLease.Dispose()}
    Reject-Leech {New-Object RS2LeechManual.ProcessLease(0)} 'invalid process lease refused'
    $ownIdentity=[pscustomobject]@{Pid=$ownPid;RunId=[Guid]::NewGuid().ToString('N')}
    $ownMessage=New-LeechPipeMessage $ownIdentity
    $ownedPipe=New-Object OwnedLeechPipeFixture($ownMessage.Path.Substring(9))
    try {
        [RS2LeechManual.PipeSender]::Send($ownMessage.Path,$ownPid,$ownMessage.Bytes)
        Check-Leech ($ownedPipe.Wait() -and $null -eq $ownedPipe.Error) 'actual helper transmission completed'
        Check-Leech ([Text.Encoding]::ASCII.GetString($ownedPipe.Message) -ceq
            [Text.Encoding]::ASCII.GetString($ownMessage.Bytes)) 'actual pipe bytes preserved'
    } finally { $ownedPipe.Dispose() }
    $wrongIdentity=[pscustomobject]@{Pid=($ownPid+1);RunId=[Guid]::NewGuid().ToString('N')}
    $wrongMessage=New-LeechPipeMessage $wrongIdentity
    $wrongPipe=New-Object OwnedLeechPipeFixture($wrongMessage.Path.Substring(9))
    try {
        Reject-Leech { [RS2LeechManual.PipeSender]::Send($wrongMessage.Path,$wrongIdentity.Pid,$wrongMessage.Bytes) } 'kernel server PID mismatch rejected'
    } finally { $wrongPipe.Dispose() }
    Write-Output ('manual-control-helper checks='+$script:Checks+' failures=0; TEMP fixture only, no inventory process/game/training tree used')
    $completed=$true
} finally {
    # Exact generated fixture custody was checked above. Preserve failures for
    # inspection; successful checks remove only the named disposable fixture.
    if ($completed) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
}
