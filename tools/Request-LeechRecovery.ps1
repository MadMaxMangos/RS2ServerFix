param(
    [uint32]$ProcessId = 0,
    [string]$RuntimeInventory,
    [string]$InventorySha256,
    [string]$BootstrapSha256,
    [string]$CompanionSha256,
    [string]$GenuineManifest,
    [string]$EvidenceDirectory,
    [string]$TargetRoot
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:LeechTrainingRoot = 'E:\rs2v_trainingsrv'
$script:LeechExecutableDirectory = 'E:\rs2v_trainingsrv\Binaries\Win64'
$script:LeechPayloadNames = @('phase','event','reason','outcome','flags','operation_sequence',
    'transition_sequence','qpc','source_epoch','sdk_epoch','owner_thread_id','resource_phase',
    'native_stage','exception_code','request_id','callback_id','callback_result','api_returned_id',
    'old_sdk_fingerprint','new_sdk_fingerprint','old_cache_fingerprint','new_cache_fingerprint',
    'finish_deadline_qpc','overall_deadline_qpc','record_sequence','callback_own_ticks')

function Initialize-LeechFileApi {
    if ('RS2LeechManual.Files' -as [type]) {
        if (!('RS2LeechManual.ProcessLease' -as [type]) -or !('RS2LeechManual.PipeSender' -as [type])) {
            throw 'An older RS2 helper is already loaded. Open a fresh PowerShell window and invoke the matching helper with -File.'
        }
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace RS2LeechManual {
public sealed class Metadata {
    public string Path, Sddl;
    public uint Attributes, Links;
    public long Size;
}
public static class Files {
    [StructLayout(LayoutKind.Sequential)] struct Info {
        public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh,
            WriteLow, WriteHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle file, out Info info);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint GetFileType(SafeFileHandle file);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint length, uint flags);
    [DllImport("advapi32.dll")]
    static extern uint GetSecurityInfo(SafeFileHandle file, uint type, uint information,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr descriptor,
        uint revision, uint information, out IntPtr text, out uint length);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    public static SafeFileHandle Open(string path, bool directory, bool create) {
        uint access = create ? 0x40020000u : (directory ? 0x20080u : 0x80020000u);
        var file = CreateFile(path, access, 1, IntPtr.Zero, create ? 1u : 3u,
            0x00200000u | (directory ? 0x02000000u : 0x80u), IntPtr.Zero);
        if (file.IsInvalid) { file.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
        return file;
    }
    public static Metadata Describe(SafeFileHandle file) {
        Info info;
        if (GetFileType(file) != 1 || !GetFileInformationByHandle(file, out info))
            throw new IOException("Not a regular disk object.");
        var path = new StringBuilder(512);
        uint count = GetFinalPathNameByHandle(file, path, 512, 0);
        if (count == 0 || count >= 512 || !path.ToString().StartsWith(@"\\?\", StringComparison.Ordinal))
            throw new IOException("Final path unavailable or unsupported.");
        IntPtr owner, group, dacl, sacl, descriptor, text = IntPtr.Zero;
        uint result = GetSecurityInfo(file, 1, 5, out owner, out group, out dacl, out sacl, out descriptor);
        if (result != 0) throw new Win32Exception((int)result);
        try {
            uint length;
            if (!ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor, 1, 5, out text, out length))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (length == 0 || length > 8192) throw new IOException("ACL evidence exceeds bound.");
            return new Metadata { Path = path.ToString().Substring(4), Sddl = Marshal.PtrToStringUni(text),
                Attributes = info.Attributes, Links = info.Links, Size = ((long)info.SizeHigh << 32) | info.SizeLow };
        } finally { if (text != IntPtr.Zero) LocalFree(text); LocalFree(descriptor); }
    }
    public static byte[] Read(SafeFileHandle file, int count) {
        using (var stream = new FileStream(file, FileAccess.Read)) {
            var bytes = new byte[count]; int offset = 0;
            while (offset < count) {
                int read = stream.Read(bytes, offset, count - offset);
                if (read == 0) throw new EndOfStreamException();
                offset += read;
            }
            return bytes;
        }
    }
    public static void Write(SafeFileHandle file, byte[] bytes) {
        using (var stream = new FileStream(file, FileAccess.Write)) {
            stream.Write(bytes, 0, bytes.Length); stream.Flush(true);
        }
    }
}
public static class PipeSender {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetNamedPipeServerProcessId(SafeFileHandle pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint GetFileType(SafeFileHandle pipe);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool WriteFile(SafeFileHandle pipe, byte[] bytes, uint length,
        out uint written, IntPtr overlapped);
    public static void Send(string path, uint expectedPid, byte[] bytes) {
        if (expectedPid == 0 || bytes == null || bytes.Length == 0 || bytes.Length > 512 ||
            !path.StartsWith(@"\\.\pipe\RS2LeechRecovery.", StringComparison.Ordinal))
            throw new IOException("Invalid bounded local recovery endpoint/message.");
        // Identification-only SQOS: the server can inspect our token, not act as
        // us. Exact write rights avoid FILE_CREATE_PIPE_INSTANCE/GENERIC_WRITE.
        using (var pipe = CreateFile(path, 0x00120082u, 0, IntPtr.Zero, 3, 0x00110000u, IntPtr.Zero)) {
            if (pipe.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            uint actualPid, written;
            if (GetFileType(pipe) != 3 || !GetNamedPipeServerProcessId(pipe, out actualPid) ||
                actualPid != expectedPid) throw new IOException("Recovery pipe server PID mismatch.");
            if (!WriteFile(pipe, bytes, (uint)bytes.Length, out written, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (written != bytes.Length) throw new IOException("Incomplete recovery message.");
        }
    }
}
// A query-only retained process identity; never starts, stops, injects or writes
// into the target. A denied query is a refusal, not an elevation request.
public sealed class ProcessLease : IDisposable {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint GetProcessId(SafeProcessHandle process);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint WaitForSingleObject(SafeProcessHandle process, uint timeout);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetProcessTimes(SafeProcessHandle process, out long creation,
        out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags,
        StringBuilder path, ref uint count);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeFileHandle token);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool GetTokenInformation(SafeFileHandle token, uint type,
        IntPtr buffer, uint capacity, out uint count);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr text);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    readonly SafeProcessHandle process;
    public uint Pid;
    public long Creation;
    public string Path, OwnerSid;
    public ProcessLease(uint pid) {
        process=OpenProcess(0x00101000u,false,pid); // QUERY_LIMITED_INFORMATION | SYNCHRONIZE
        if(process.IsInvalid) { int error=Marshal.GetLastWin32Error();process.Dispose();throw new Win32Exception(error); }
        try {
            Pid=GetProcessId(process);
            long exit,kernel,user;
            if(Pid!=pid || !GetProcessTimes(process,out Creation,out exit,out kernel,out user) || Creation<=0)
                throw new IOException("Selected process identity is unavailable.");
            var path=new StringBuilder(512);uint count=512;
            if(!QueryFullProcessImageName(process,0,path,ref count) || count==0 || count>=512)
                throw new IOException("Selected process image path is unavailable.");
            Path=path.ToString();
            SafeFileHandle token;
            if(!OpenProcessToken(process,8,out token)) throw new Win32Exception(Marshal.GetLastWin32Error());
            using(token) {
                IntPtr buffer=Marshal.AllocHGlobal(256),text=IntPtr.Zero;
                try {
                    uint bytes;
                    if(!GetTokenInformation(token,1,buffer,256,out bytes) || bytes<16 || bytes>256 ||
                        !ConvertSidToStringSid(Marshal.ReadIntPtr(buffer),out text))
                        throw new IOException("Selected process owner is unavailable.");
                    OwnerSid=Marshal.PtrToStringUni(text);
                } finally { if(text!=IntPtr.Zero) LocalFree(text);Marshal.FreeHGlobal(buffer); }
            }
            Verify();
        } catch { process.Dispose();throw; }
    }
    public void Verify() {
        long creation,exit,kernel,user;
        if(WaitForSingleObject(process,0)!=258 || GetProcessId(process)!=Pid ||
            !GetProcessTimes(process,out creation,out exit,out kernel,out user) || creation!=Creation)
            throw new IOException("Selected process exited or its identity changed.");
    }
    public void Dispose() { process.Dispose(); }
}
}
'@
}
function Assert-LeechRoot([string]$Root) {
    if($Root -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_-]{1,32}\z') { throw 'Supply a plain fixed-drive server root with one path component.' }
}
function Get-LeechAdministratorSid {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return $identity.User.Value }
        return ''
    } finally { $identity.Dispose() }
}
function Assert-LeechAcl([string]$Sddl, [string]$OperatorSid, [bool]$PermissionFile) {
    $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor($Sddl)
    $trusted = @('S-1-5-18','S-1-5-32-544')
    $administrator = Get-LeechAdministratorSid
    if ($administrator) { $trusted += $administrator }
    if (!$PermissionFile -and $OperatorSid) { $trusted += $OperatorSid }
    if ($null -eq $descriptor.Owner -or $descriptor.Owner.Value -cnotin $trusted -or
        $null -eq $descriptor.DiscretionaryAcl) { throw 'Control owner or DACL is not approved.' }
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or
            $ace.AceType -notin @([Security.AccessControl.AceType]::AccessAllowed,[Security.AccessControl.AceType]::AccessDenied) -or
            ([int]$ace.AceFlags -band (-bnot 31)) -ne 0) { throw 'Unsupported control ACE.' }
        $mask = [uint32]([int64]$ace.AccessMask -band 4294967295L)
        if (($mask -band 266403328L) -ne 0) { throw 'Unsupported control access mask.' }
        # Generic-write/all and concrete file/directory mutation rights. Deny
        # entries cannot grant write authority; unsupported ACE forms rejected.
        if ($ace.AceType -eq [Security.AccessControl.AceType]::AccessAllowed -and
            ($mask -band 1343029590L) -ne 0 -and $ace.SecurityIdentifier.Value -cnotin $trusted) {
            throw 'Control ACL permits an unapproved writer.'
        }
    }
}
function Assert-LeechMetadata($Metadata, [string]$ExactPath, [bool]$Directory,
    [string]$OperatorSid, [bool]$PermissionFile, [bool]$CheckAcl=$true) {
    if (!$Metadata.Path.Equals($ExactPath,[StringComparison]::OrdinalIgnoreCase) -or
        ($Metadata.Attributes -band 1024) -ne 0 -or
        (($Metadata.Attributes -band 16) -ne 0) -ne $Directory -or
        (!$Directory -and $Metadata.Links -ne 1)) { throw 'Control file type/final path/link identity rejected.' }
    if ($CheckAcl) { Assert-LeechAcl $Metadata.Sddl $OperatorSid $PermissionFile }
}
function Read-LeechPermission([string]$Path,[string]$ExpectedRoot=$script:LeechTrainingRoot) {
    Initialize-LeechFileApi
    $handle = [RS2LeechManual.Files]::Open($Path,$false,$false)
    try {
        $metadata = [RS2LeechManual.Files]::Describe($handle)
        Assert-LeechMetadata $metadata $Path $false '' $true $false
        if ($metadata.Size -le 0 -or $metadata.Size -gt 512) { throw 'Permission exceeds fixed byte bound.' }
        $bytes = [RS2LeechManual.Files]::Read($handle,[int]$metadata.Size)
        if (@($bytes | Where-Object { $_ -eq 0 -or $_ -gt 127 -or ($_ -lt 32 -and $_ -notin @(9,10,13)) }).Count) {
            throw 'Permission is not strict ASCII.'
        }
        $fields = New-Object 'Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
        foreach ($line in ([Text.Encoding]::ASCII.GetString($bytes) -split "`n")) {
            if ($line.EndsWith("`r",[StringComparison]::Ordinal)) { $line=$line.Substring(0,$line.Length-1) }
            $trimmed = $line.Trim([char[]]@(' ',"`t"))
            if (!$trimmed) { continue }
            if ($trimmed -cnotmatch '^([^=]+)=([^=]*)$') { throw 'Malformed permission line.' }
            $key = $Matches[1].Trim([char[]]@(' ',"`t")); $value = $Matches[2].Trim([char[]]@(' ',"`t"))
            if ($fields.ContainsKey($key)) { throw 'Duplicate permission field.' }
            $fields.Add($key,$value)
        }
        if(!$fields.ContainsKey('schema') -or $fields['schema'] -cnotin '1','2') { throw 'Unsupported permission schema.' }
        $rootKey=if($fields['schema'] -ceq '1'){'training_root'}else{'server_root'}
        $permissionName=if($fields['schema'] -ceq '1'){'training-finish-recreate'}else{'manual-pilot-finish-recreate'}
        $hasConsole=$fields.ContainsKey('console_trigger')
        $consoleTrigger='disabled'
        if($hasConsole) {
            if($fields['schema'] -cne '2' -or $fields['console_trigger'] -cnotin 'disabled','server-admin') {
                throw 'Console trigger opt-in is unsupported for this permission schema.'
            }
            $consoleTrigger=$fields['console_trigger']
        }
        if ($fields.Count -ne (4+[int]$hasConsole) -or @('schema','permission',$rootKey,'operator_sid' | Where-Object { !$fields.ContainsKey($_) }).Count -or
            $fields['permission'] -cne $permissionName) { throw 'Explicit matching manual permission is absent or unsupported.' }
        Assert-LeechRoot $ExpectedRoot
        Assert-LeechRoot $fields[$rootKey]
        if(!$fields[$rootKey].Equals($ExpectedRoot,[StringComparison]::OrdinalIgnoreCase) -or
            ($fields['schema'] -ceq '1' -and $fields[$rootKey] -cne $script:LeechTrainingRoot)) { throw 'Permission does not name the selected server root.' }
        $sid = New-Object Security.Principal.SecurityIdentifier($fields['operator_sid'])
        if ($sid.Value -cne $fields['operator_sid'] -or $sid.Value -cin @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-7')) {
            throw 'Operator SID is not a canonical explicit approved identity.'
        }
        return [pscustomobject]@{ OperatorSid=$sid.Value; Sddl=$metadata.Sddl; Schema=[int]$fields['schema']; Root=$fields[$rootKey]; ConsoleTrigger=$consoleTrigger }
    } finally { $handle.Dispose() }
}
function Read-LeechInventoryIdentity([string]$Path, [uint32]$ExpectedPid,
    [string]$ExpectedInventoryHash, [string]$ExpectedBootstrapHash, [string]$ExpectedCompanionHash,
    [string]$ExpectedImagePath='', [string]$ExpectedCreation='') {
    $fields = New-Object 'Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if (!$line) { continue }
        $separator = $line.IndexOf('=')
        if ($separator -le 0) { throw 'Malformed runtime inventory line.' }
        $key = $line.Substring(0,$separator)
        if ($fields.ContainsKey($key)) { throw 'Duplicate runtime inventory key.' }
        $fields.Add($key,$line.Substring($separator+1))
    }
    $expected = @{
        'schema'='1'; 'mode'='runtime-inventory'; 'pid'=[string]$ExpectedPid; 'result'='pass';
        'tool_sha256'=$ExpectedInventoryHash; 'bootstrap_sha256'=$ExpectedBootstrapHash;
        'companion_sha256'=$ExpectedCompanionHash; 'observed_bootstrap_sha256'=$ExpectedBootstrapHash;
        'observed_companion_sha256'=$ExpectedCompanionHash; 'companion_kind'='companion-reporting';
        'process_image_path'='E%3A/rs2v_trainingsrv/Binaries/Win64/VNGame.exe';
        'host_sha256'='0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393';
        'recovery.snapshot_result'='Coherent'; 'recovery.schema'='1'; 'recovery.bytes'='256';
        'recovery.artifact_version'='459008'; 'recovery.pid'=[string]$ExpectedPid; 'recovery.header_ready'='1';
        'reporting.header_valid'='true'; 'reporting.artifact_version'='459008'; 'reporting.pid'=[string]$ExpectedPid;
        'reporting.current_ready'='true'
    }
    if($ExpectedImagePath) {
        $expected['process_image_path']=[Uri]::EscapeDataString($ExpectedImagePath.Replace('\','/')).Replace('%2F','/')
    }
    if($ExpectedCreation) {
        if($ExpectedCreation -cnotmatch '^[1-9][0-9]{0,18}$'){throw 'Invalid selected process creation identity.'}
        $expected['process_creation_filetime']=$ExpectedCreation
        $expected['reporting.process_creation']=$ExpectedCreation
    }
    foreach ($pair in $expected.GetEnumerator()) {
        if (!$fields.ContainsKey($pair.Key) -or $fields[$pair.Key] -cne $pair.Value) { throw "Runtime inventory identity rejected: $($pair.Key)" }
    }
    $recoveryKeys = @('snapshot_result','schema','bytes','artifact_version','pid','run_id','header_ready','owner_sequence') + $script:LeechPayloadNames
    $actualRecovery = @($fields.Keys | Where-Object { $_.StartsWith('recovery.',[StringComparison]::Ordinal) })
    if ($actualRecovery.Count -ne 34) { throw 'Runtime recovery key set rejected.' }
    foreach ($key in $recoveryKeys) { if (!$fields.ContainsKey('recovery.'+$key)) { throw 'Runtime recovery key set rejected.' } }
    $run = $fields['recovery.run_id']
    if ($run -cnotmatch '^[0-9a-f]{32}$' -or $run -ceq ('0'*32) -or
        !$fields.ContainsKey('reporting.run_id') -or $fields['reporting.run_id'] -cne $run) { throw 'Run identity does not match immutable reporting identity.' }
    [uint64]$sequence = 0
    if ($fields['recovery.owner_sequence'] -cnotmatch '^[1-9][0-9]*$' -or
        ![uint64]::TryParse($fields['recovery.owner_sequence'],[ref]$sequence) -or ($sequence -band 1) -ne 0) { throw 'Recovery snapshot is not coherent.' }
    $initial=$fields['recovery.phase'] -ceq '1' -and $fields['recovery.flags'] -ceq '1' -and
        $fields['recovery.operation_sequence'] -ceq '0' -and $fields['recovery.transition_sequence'] -ceq '1'
    [uint64]$retryFlags=0; [uint64]$operation=0; [uint64]$transition=0; [uint64]$reason=0
    $retry=[uint64]::TryParse($fields['recovery.flags'],[ref]$retryFlags) -and
        [uint64]::TryParse($fields['recovery.operation_sequence'],[ref]$operation) -and $operation -gt 0 -and $operation -lt [uint64]::MaxValue -and
        [uint64]::TryParse($fields['recovery.transition_sequence'],[ref]$transition) -and $transition -gt 1 -and $transition -lt [uint64]::MaxValue -and
        $fields['recovery.phase'] -ceq '10' -and ($retryFlags -band 2097665) -eq 2097665 -and
        ($retryFlags -band (-bnot [uint64]3146241)) -eq 0 -and
        $fields['recovery.native_stage'] -ceq '0' -and $fields['recovery.resource_phase'] -ceq '0' -and
        $fields['recovery.exception_code'] -ceq '0' -and $fields['recovery.callback_result'] -ceq '0' -and
        $fields['recovery.outcome'] -cin @('1','4') -and [uint64]::TryParse($fields['recovery.reason'],[ref]$reason) -and
        $reason -gt 0 -and $reason -lt 83 -and $reason -notin 2,26
    if (!$initial -and !$retry) { throw 'Recovery is busy, spent, disabled, or not an explicitly retryable preflight rejection.' }
    return [pscustomobject]@{ Pid=$ExpectedPid; RunId=$run }
}
function New-LeechPipeMessage($Identity,$Permission=$null) {
    if (!$Identity.Pid -or $Identity.RunId -cnotmatch '^[0-9a-f]{32}$' -or
        $Identity.RunId -ceq ('0'*32)) { throw 'Invalid request identity.' }
    $schema=if($null -eq $Permission){1}else{[int]$Permission.Schema}
    $root=if($null -eq $Permission){$script:LeechTrainingRoot}else{[string]$Permission.Root}
    Assert-LeechRoot $root
    if($schema -notin 1,2 -or ($schema -eq 1 -and $root -cne $script:LeechTrainingRoot)){throw 'Unsupported request scope.'}
    $request = [ordered]@{ schema=$schema; action='finish-recreate'; pid=[uint32]$Identity.Pid; run_id=$Identity.RunId }
    $request[$(if($schema -eq 1){'training_root'}else{'server_root'})]=$root
    $bytes = [Text.Encoding]::ASCII.GetBytes(($request | ConvertTo-Json -Compress))
    if (!$bytes.Length -or $bytes.Length -gt 512) { throw 'Request exceeds fixed byte bound.' }
    return [pscustomobject]@{
        Path='\\.\pipe\RS2LeechRecovery.'+[string]$Identity.Pid+'.'+$Identity.RunId
        Bytes=$bytes
    }
}
function Invoke-LeechRecoveryRequest {
    if (!$ProcessId) { throw 'Supply the already identified server PID.' }
    $root=if($TargetRoot){$TargetRoot}else{$script:LeechTrainingRoot}
    Assert-LeechRoot $root
    $bin=[IO.Path]::Combine($root,'Binaries\Win64')
    $drive=$root.Substring(0,3)
    if((New-Object IO.DriveInfo($drive)).DriveType -ne [IO.DriveType]::Fixed){throw 'Selected server root is not on a fixed drive.'}
    foreach ($digest in @($InventorySha256,$BootstrapSha256,$CompanionSha256)) {
        if ($digest -cnotmatch '^[0-9A-F]{64}$') { throw 'Supply matching trial artifact SHA256 values in uppercase.' }
    }
    if (!$EvidenceDirectory -or !(Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) { throw 'Supply an existing evidence directory outside the selected server root.' }
    $evidenceRoot = [IO.Path]::GetFullPath($EvidenceDirectory).TrimEnd('\')
    if ($evidenceRoot.Equals($root,[StringComparison]::OrdinalIgnoreCase) -or $evidenceRoot.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Evidence must be outside the selected server root.' }
    if (!$RuntimeInventory -or !$GenuineManifest) { throw 'Supply the matching runtime inventory tool and qualified genuine manifest.' }
    $inventoryPath = [IO.Path]::GetFullPath($RuntimeInventory)
    if ($inventoryPath.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or
        (Get-FileHash -LiteralPath $inventoryPath -Algorithm SHA256).Hash -cne $InventorySha256 -or
        [Diagnostics.FileVersionInfo]::GetVersionInfo($inventoryPath).FileVersion -cne '0.7.1.0') { throw 'Inventory tool identity/version rejected.' }
    $permission = Read-LeechPermission ([IO.Path]::Combine($bin,'RS2LeechRecovery.ini')) $root
    if($permission.Schema -eq 2 -and !$TargetRoot){throw 'Pilot requests require an explicit -TargetRoot.'}
    $operator = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if ($operator.User.Value -cne $permission.OperatorSid -or (Get-LeechAdministratorSid) -cne $permission.OperatorSid) {
            throw 'Use the exact approved Administrator account that started this server.'
        }
    } finally { $operator.Dispose() }
    $pins = New-Object 'Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]'
    $directoryEvidence = @()
    $processLease=$null
    try {
        $processLease=New-Object RS2LeechManual.ProcessLease($ProcessId)
        if($processLease.OwnerSid -cne $permission.OperatorSid -or
            ![IO.Path]::GetDirectoryName($processLease.Path).Equals($bin,[StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($processLease.Path) -cnotmatch '^[A-Za-z0-9_.-]{1,128}\.exe$') { throw 'Selected process owner/image does not match the explicit server scope.' }
        foreach ($directory in @($drive,$root,[IO.Path]::Combine($root,'Binaries'),$bin,$evidenceRoot)) {
            $pin = [RS2LeechManual.Files]::Open($directory,$true,$false); $pins.Add($pin)
            $metadata = [RS2LeechManual.Files]::Describe($pin)
            if ($directory -ceq $drive) {
                if (!$metadata.Path.Equals($directory,[StringComparison]::OrdinalIgnoreCase) -or ($metadata.Attributes -band 1024) -ne 0) { throw 'Drive path rejected.' }
            } else { Assert-LeechMetadata $metadata $directory $true $permission.OperatorSid $false $false }
            $directoryEvidence += [pscustomobject]@{ Path=$directory; Sddl=$metadata.Sddl }
        }
        $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
        $report = [IO.Path]::Combine($evidenceRoot,'leech-request-inventory-'+$stamp+'.txt')
        & $inventoryPath --pid ([string]$ProcessId) --target-root $root --expect proxy-pass --mode active --expected-recon corrected --companion-kind companion-reporting --bootstrap-sha256 $BootstrapSha256 --companion-sha256 $CompanionSha256 --genuine-manifest $GenuineManifest --report $report
        if ($LASTEXITCODE -ne 0) { throw 'Matching read-only runtime inventory failed; preserved report is not request permission.' }
        $identity = Read-LeechInventoryIdentity $report $ProcessId $InventorySha256 $BootstrapSha256 $CompanionSha256 $processLease.Path ([string]$processLease.Creation)
        $message = New-LeechPipeMessage $identity $permission
        $securityEvidence = [ordered]@{ schema=1; inventory_report=$report; pid=$identity.Pid; run_id=$identity.RunId;
            control_transport='local-authenticated-pipe'; operator_sid=$permission.OperatorSid; endpoint=$message.Path;
            permission_schema=$permission.Schema; target_root=$root; process_creation_filetime=[string]$processLease.Creation;
            permission_sddl=$permission.Sddl; directories=$directoryEvidence; observed_utc=[DateTime]::UtcNow.ToString('o') }
        $evidencePath = [IO.Path]::Combine($evidenceRoot,'leech-request-security-'+$stamp+'.json')
        $evidence = New-Object IO.FileStream($evidencePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try { $raw=[Text.Encoding]::UTF8.GetBytes(($securityEvidence | ConvertTo-Json -Depth 5)); $evidence.Write($raw,0,$raw.Length); $evidence.Flush($true) } finally { $evidence.Dispose() }
        Initialize-LeechFileApi
        $processLease.Verify()
        [RS2LeechManual.PipeSender]::Send($message.Path,$identity.Pid,$message.Bytes)
        Write-Output ('Request transmitted: '+$message.Path)
        Write-Output ('Inventory/security evidence: '+$report+' ; '+$evidencePath)
        Write-Output 'Authenticated transmission is not admission, native completion, or browser repair. Inventory/security evidence is preserved.'
    } finally { if($null -ne $processLease){$processLease.Dispose()};foreach ($pin in $pins) { $pin.Dispose() } }
}
# Dot sourcing exposes only bounded fixture-test functions; invoking the helper
# pins the exact explicitly approved scope. It starts no game/server process.
if ($MyInvocation.InvocationName -ne '.') { Invoke-LeechRecoveryRequest }
