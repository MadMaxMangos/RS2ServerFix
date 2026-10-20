param(
    [uint32]$ProcessId = 0,
    [string]$RuntimeInventory,
    [string]$InventorySha256,
    [string]$BootstrapSha256,
    [string]$CompanionSha256,
    [string]$GenuineManifest,
    [string]$EvidenceDirectory
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
    if ('RS2LeechManual.Files' -as [type]) { return }
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
}
'@
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
function Read-LeechPermission([string]$Path) {
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
        if ($fields.Count -ne 4 -or @('schema','permission','training_root','operator_sid' | Where-Object { !$fields.ContainsKey($_) }).Count -or
            $fields['schema'] -cne '1' -or $fields['permission'] -cne 'training-finish-recreate' -or
            $fields['training_root'] -cne $script:LeechTrainingRoot) { throw 'Explicit training permission is absent or unsupported.' }
        $sid = New-Object Security.Principal.SecurityIdentifier($fields['operator_sid'])
        if ($sid.Value -cne $fields['operator_sid'] -or $sid.Value -cin @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-7')) {
            throw 'Operator SID is not a canonical explicit approved identity.'
        }
        return [pscustomobject]@{ OperatorSid=$sid.Value; Sddl=$metadata.Sddl }
    } finally { $handle.Dispose() }
}
function Read-LeechInventoryIdentity([string]$Path, [uint32]$ExpectedPid,
    [string]$ExpectedInventoryHash, [string]$ExpectedBootstrapHash, [string]$ExpectedCompanionHash) {
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
        'recovery.artifact_version'='393728'; 'recovery.pid'=[string]$ExpectedPid; 'recovery.header_ready'='1';
        'reporting.header_valid'='true'; 'reporting.artifact_version'='393728'; 'reporting.pid'=[string]$ExpectedPid;
        'reporting.current_ready'='true'
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
    # This channel must be startup idle; a prior request/operation is absorbing.
    if ($fields['recovery.phase'] -cne '1' -or $fields['recovery.flags'] -cne '1') { throw 'Recovery is not armed under explicit training permission.' }
    if ($fields['recovery.operation_sequence'] -cne '0' -or $fields['recovery.transition_sequence'] -cne '1') {
        throw 'This run already has a recovery operation or fault.'
    }
    return [pscustomobject]@{ Pid=$ExpectedPid; RunId=$run }
}
function New-LeechPipeMessage($Identity) {
    if (!$Identity.Pid -or $Identity.RunId -cnotmatch '^[0-9a-f]{32}$' -or
        $Identity.RunId -ceq ('0'*32)) { throw 'Invalid request identity.' }
    $request = [ordered]@{ schema=1; action='finish-recreate'; pid=[uint32]$Identity.Pid;
        run_id=$Identity.RunId; training_root=$script:LeechTrainingRoot }
    $bytes = [Text.Encoding]::ASCII.GetBytes(($request | ConvertTo-Json -Compress))
    if (!$bytes.Length -or $bytes.Length -gt 512) { throw 'Request exceeds fixed byte bound.' }
    return [pscustomobject]@{
        Path='\\.\pipe\RS2LeechRecovery.'+[string]$Identity.Pid+'.'+$Identity.RunId
        Bytes=$bytes
    }
}
function Invoke-LeechRecoveryRequest {
    if (!$ProcessId) { throw 'Supply the already identified training server PID.' }
    foreach ($digest in @($InventorySha256,$BootstrapSha256,$CompanionSha256)) {
        if ($digest -cnotmatch '^[0-9A-F]{64}$') { throw 'Supply matching trial artifact SHA256 values in uppercase.' }
    }
    if (!$EvidenceDirectory -or !(Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) { throw 'Supply an existing evidence directory outside the training root.' }
    $evidenceRoot = [IO.Path]::GetFullPath($EvidenceDirectory).TrimEnd('\')
    if ($evidenceRoot.StartsWith($script:LeechTrainingRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Evidence must be outside the training root.' }
    if (!$RuntimeInventory -or !$GenuineManifest) { throw 'Supply the matching runtime inventory tool and qualified genuine manifest.' }
    $inventoryPath = [IO.Path]::GetFullPath($RuntimeInventory)
    if ($inventoryPath.StartsWith($script:LeechTrainingRoot,[StringComparison]::OrdinalIgnoreCase) -or
        (Get-FileHash -LiteralPath $inventoryPath -Algorithm SHA256).Hash -cne $InventorySha256 -or
        [Diagnostics.FileVersionInfo]::GetVersionInfo($inventoryPath).FileVersion -cne '0.6.2.0') { throw 'Inventory tool identity/version rejected.' }
    $permission = Read-LeechPermission ([IO.Path]::Combine($script:LeechExecutableDirectory,'RS2LeechRecovery.ini'))
    $operator = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if ($operator.User.Value -cne $permission.OperatorSid) {
            throw 'Use the exact approved account that started the training server.'
        }
    } finally { $operator.Dispose() }
    $pins = New-Object 'Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]'
    $directoryEvidence = @()
    try {
        foreach ($directory in @('E:\',$script:LeechTrainingRoot,'E:\rs2v_trainingsrv\Binaries',$script:LeechExecutableDirectory)) {
            $pin = [RS2LeechManual.Files]::Open($directory,$true,$false); $pins.Add($pin)
            $metadata = [RS2LeechManual.Files]::Describe($pin)
            if ($directory -ceq 'E:\') {
                if (!$metadata.Path.Equals($directory,[StringComparison]::OrdinalIgnoreCase) -or ($metadata.Attributes -band 1024) -ne 0) { throw 'Drive path rejected.' }
            } else { Assert-LeechMetadata $metadata $directory $true $permission.OperatorSid $false $false }
            $directoryEvidence += [pscustomobject]@{ Path=$directory; Sddl=$metadata.Sddl }
        }
        $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
        $report = [IO.Path]::Combine($evidenceRoot,'leech-request-inventory-'+$stamp+'.txt')
        & $inventoryPath --pid ([string]$ProcessId) --target-root $script:LeechTrainingRoot --expect proxy-pass --mode active --expected-recon corrected --companion-kind companion-reporting --bootstrap-sha256 $BootstrapSha256 --companion-sha256 $CompanionSha256 --genuine-manifest $GenuineManifest --report $report
        if ($LASTEXITCODE -ne 0) { throw 'Matching read-only runtime inventory failed; preserved report is not request permission.' }
        $identity = Read-LeechInventoryIdentity $report $ProcessId $InventorySha256 $BootstrapSha256 $CompanionSha256
        $message = New-LeechPipeMessage $identity
        $securityEvidence = [ordered]@{ schema=1; inventory_report=$report; pid=$identity.Pid; run_id=$identity.RunId;
            control_transport='local-authenticated-pipe'; operator_sid=$permission.OperatorSid; endpoint=$message.Path;
            permission_sddl=$permission.Sddl; directories=$directoryEvidence; observed_utc=[DateTime]::UtcNow.ToString('o') }
        $evidencePath = [IO.Path]::Combine($evidenceRoot,'leech-request-security-'+$stamp+'.json')
        $evidence = New-Object IO.FileStream($evidencePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try { $raw=[Text.Encoding]::UTF8.GetBytes(($securityEvidence | ConvertTo-Json -Depth 5)); $evidence.Write($raw,0,$raw.Length); $evidence.Flush($true) } finally { $evidence.Dispose() }
        Initialize-LeechFileApi
        [RS2LeechManual.PipeSender]::Send($message.Path,$identity.Pid,$message.Bytes)
        Write-Output ('Request transmitted: '+$message.Path)
        Write-Output ('Inventory/security evidence: '+$report+' ; '+$evidencePath)
        Write-Output 'Authenticated transmission is not admission, native completion, or browser repair. Inventory/security evidence is preserved.'
    } finally { foreach ($pin in $pins) { $pin.Dispose() } }
}
# Dot sourcing exposes only bounded fixture-test functions; invoking the helper
# always pins the exact approved training root. It starts no game/server process.
if ($MyInvocation.InvocationName -ne '.') { Invoke-LeechRecoveryRequest }
