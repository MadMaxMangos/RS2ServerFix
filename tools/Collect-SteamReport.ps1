param(
    [uint32]$ProcessId = 0,
    [string]$TargetRoot,
    [string]$ReportingRunDirectory,
    [string]$ReportRoot,
    [string]$MarkerPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Numerics
$script:ReportHostHash = '0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393'
$script:ReportSdkHash = 'A44E5537939AE4EEBC69000589AA9B2437A667813A1657CC779198BAE9B815A9'
$script:ReportClientHash = '8165D2A8E82753E5CD5AD985D6D08C2379E0AA8D0340669BCF05890584F51ACE'
$script:ReportPackageFiles = @(
    'dlls/X3DAudio1_7.dll','dlls/RS2ServerFix.dll','config/RS2SteamObserve.ini','config/RS2SteamReport.ini',
    'config/qualified_x3audio_genuine.manifest','tools/rs2_runtime_inventory.exe',
    'tools/rs2_deployment_preflight.exe','tools/rs2_pe_contract.exe',
    'tools/Collect-SteamReport.ps1','tools/Run-SteamReport.cmd','README.md','LICENSE')

# File/path/handle custody helpers are mechanically reused from the existing
# observer collector. This sibling is self-contained; it never loads that script
# or includes the observer private-key directory in its package/evidence allowlist.
function Test-ReportWithin([string]$Root, [string]$Path) {
    return $Path.Equals($Root, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Resolve-ReportPlain([string]$Path, [bool]$Directory) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -cnotmatch '^[A-Za-z]:\\' -or
        $Path.Substring(2).Contains(':') -or $Path -match '[\x00-\x1F"<>|?*/]') {
        throw 'Use a full local drive path, without streams, wildcards or device paths.'
    }
    foreach ($part in $Path.Substring(3).TrimEnd('\').Split('\')) {
        if (!$part -or $part -eq '.' -or $part -eq '..' -or $part.EndsWith('.') -or $part.EndsWith(' ')) {
            throw 'Ambiguous path component.'
        }
    }
    $plain = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $item = Get-Item -LiteralPath $plain -Force
    if ([bool]$item.PSIsContainer -ne $Directory) { throw 'Path has the wrong file type.' }
    $cursor = $item
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse paths are not accepted.' }
        if ($cursor -is [IO.FileInfo]) { $cursor = $cursor.Directory } else { $cursor = $cursor.Parent }
    }
    return $plain
}

function Initialize-ReportFileReader {
    if ('RS2ReportCollection.Files' -as [type]) { return }
    # This helper reads file handles only. Process identity/memory inspection is
    # deliberately left to the existing native runtime inventory executable.
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using Microsoft.Win32.SafeHandles;
namespace RS2ReportCollection {
public sealed class Prefix {
    public long InitialLength, FinalLength, CopiedLength;
    public string Identity;
    public bool PartialTail;
}
public static class Files {
    [StructLayout(LayoutKind.Sequential)] struct Info {
        public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh,
            Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint capacity, uint flags);
    static Info CheckedInfo(FileStream stream, string expected) {
        Info info;
        if (!GetFileInformationByHandle(stream.SafeFileHandle, out info) || (info.Attributes & 0x410) != 0)
            throw new IOException("File identity unavailable or not a plain file.");
        var path = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandleW(stream.SafeFileHandle, path, (uint)path.Capacity, 0);
        if (length == 0 || length >= path.Capacity ||
            !String.Equals(path.ToString(), @"\\?\" + expected, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Opened file does not match the expected resolved path.");
        return info;
    }
    static long Length(Info info) { return ((long)info.SizeHigh << 32) | info.SizeLow; }
    static string Identity(Info info) { return info.Volume + ":" + info.IndexHigh + ":" + info.IndexLow; }
    public static FileStream Open(string path, bool growing) {
        // OPEN_REPARSE_POINT plus final-handle validation closes the path-check/open gap.
        var handle = CreateFileW(path, 0x80000000, growing ? 3U : 1U, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); throw new IOException("Cannot open evidence input: " + Marshal.GetLastWin32Error()); }
        FileStream stream = null;
        try { stream = new FileStream(handle, FileAccess.Read); CheckedInfo(stream, path); return stream; }
        catch { if (stream != null) stream.Dispose(); else handle.Dispose(); throw; }
    }
    public static Prefix CopyPrefix(FileStream source, string sourcePath, string destination) {
        Info first = CheckedInfo(source, sourcePath);
        long initial = Length(first);
        if (initial < 0 || initial > 1024L * 1024 * 1024) throw new IOException("Report log exceeds its bound.");
        source.Position = 0;
        var result = new Prefix { InitialLength = initial, Identity = Identity(first) };
        byte last = 10;
        using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) {
            byte[] buffer = new byte[65536];
            while (result.CopiedLength < initial) {
                int got = source.Read(buffer, 0, (int)Math.Min(buffer.Length, initial - result.CopiedLength));
                if (got == 0) throw new IOException("Source shortened during bounded-prefix collection.");
                output.Write(buffer, 0, got); last = buffer[got-1]; result.CopiedLength += got;
            }
            output.Flush(true);
        }
        Info after = CheckedInfo(source, sourcePath);
        result.FinalLength = Length(after); result.PartialTail = initial != 0 && last != 10;
        if (Identity(after) != result.Identity || result.FinalLength < initial)
            throw new IOException("Source changed identity or shrank during collection.");
        return result;
    }
    public static IEnumerable<string> CompleteLines(string path) {
        // Only LF-terminated records are decoded. An incomplete final UTF-8 code
        // point remains in the copied evidence instead of being silently replaced.
        using (var input = Open(path, false)) {
            byte[] chunk = new byte[65536], line = new byte[131072]; int used = 0, got;
            var utf8 = new UTF8Encoding(false, true);
            while ((got = input.Read(chunk, 0, chunk.Length)) != 0) {
                for (int i = 0; i < got; ++i) {
                    if (chunk[i] == 10) { yield return utf8.GetString(line, 0, used); used = 0; }
                    else { if (used == line.Length) throw new IOException("JSONL line exceeds metadata bound."); line[used++] = chunk[i]; }
                }
            }
        }
    }
    public static void VerifyPrefix(string before, string after) {
        using (var left = Open(before, false)) using (var right = Open(after, false)) {
            if (right.Length < left.Length) throw new IOException("Collected log shortened.");
            byte[] a = new byte[65536], b = new byte[65536];
            int count;
            while ((count = left.Read(a, 0, a.Length)) != 0) {
                int total = 0;
                while (total < count) {
                    int got = right.Read(b, total, count-total);
                    if (got == 0) throw new IOException("Short second prefix.");
                    total += got;
                }
                for (int i = 0; i < count; ++i)
                    if (a[i] != b[i]) throw new IOException("Earlier log prefix was rewritten.");
            }
        }
    }
}
}
'@
}

function Get-ReportHash([IO.FileStream]$Stream) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $Stream.Position = 0; $digest = $hash.ComputeHash($Stream); $Stream.Position = 0
        return [BitConverter]::ToString($digest).Replace('-', '') } finally { $hash.Dispose() }
}

function Read-ReportText([IO.FileStream]$Stream, [int]$Limit) {
    if ($Stream.Length -le 0 -or $Stream.Length -gt $Limit) { throw 'Input exceeds its byte bound or is empty.' }
    $Stream.Position = 0
    $reader = New-Object IO.StreamReader($Stream, (New-Object Text.UTF8Encoding($false, $true)), $false, 4096, $true)
    try { $text = $reader.ReadToEnd(); $Stream.Position = 0; return $text } finally { $reader.Dispose() }
}

function Save-ReportText([string]$Path, [string]$Text) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Text); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Read-ReportFields([string]$Text) {
    $fields = New-Object 'Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    if (!$Text.EndsWith("`r`n") -or $Text -match '(?<!\r)\n|\r(?!\n)') { throw 'Evidence has malformed line endings.' }
    foreach ($line in $Text.Substring(0, $Text.Length - 2).Split(@("`r`n"), [StringSplitOptions]::None)) {
        $split = $line.IndexOf('=')
        if ($split -le 0) { throw 'Malformed evidence field.' }
        $key = $line.Substring(0, $split)
        if ($fields.ContainsKey($key) -or $key -cnotmatch '^[a-z][A-Za-z0-9_.]*$') { throw 'Duplicate or malformed evidence field.' }
        $fields.Add($key, $line.Substring($split + 1))
    }
    return ,$fields
}

function Assert-ReportFields($Fields, $Required) {
    foreach ($key in $Required.Keys) { if (!$Fields.ContainsKey($key) -or $Fields[$key] -cne [string]$Required[$key]) { throw "Evidence field mismatch: $key." } }
}

function Read-ReportPackage([string]$Root, $Locks) {
    $sumPath = Resolve-ReportPlain (Join-Path $Root 'SHA256SUMS') $false
    $sumStream = [RS2ReportCollection.Files]::Open($sumPath, $false); $Locks.Add($sumStream)
    $text = Read-ReportText $sumStream 16384
    $files = New-Object 'Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    foreach ($line in ($text.TrimEnd("`r", "`n") -split '\r?\n')) {
        if ($line -cnotmatch '^([0-9A-F]{64})  ([A-Za-z0-9_./-]+)$') { throw 'Malformed SHA256SUMS.' }
        $digest = $Matches[1]; $relative = $Matches[2]
        if (($relative -cnotin $script:ReportPackageFiles -and $relative -cnotin @('timing-calibration.json','performance-assessment.json')) -or $files.ContainsKey($relative)) { throw 'Unapproved or duplicate package entry.' }
        $files.Add($relative, $digest)
    }
    foreach ($required in $script:ReportPackageFiles) { if (!$files.ContainsKey($required)) { throw 'Package file set is incomplete.' } }
    foreach ($relative in $files.Keys) {
        $path = Resolve-ReportPlain (Join-Path $Root $relative.Replace('/', '\')) $false
        $stream = [RS2ReportCollection.Files]::Open($path, $false); $Locks.Add($stream)
        if ((Get-ReportHash $stream) -cne $files[$relative]) { throw "Package SHA-256 mismatch: $relative." }
    }
    # A package inventory is allowed; server evidence collection below is NOT recursive.
    $stack = New-Object 'Collections.Generic.Stack[string]'; $stack.Push($Root); $seen = 0
    while ($stack.Count) {
        foreach ($item in Get-ChildItem -LiteralPath $stack.Pop() -Force) {
            if (++$seen -gt 64 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unsafe package tree.' }
            if ($item.PSIsContainer) { $stack.Push($item.FullName); continue }
            $relative = $item.FullName.Substring($Root.Length + 1).Replace('\', '/')
            if ($relative -cne 'SHA256SUMS' -and !$files.ContainsKey($relative)) { throw 'Unlisted package file.' }
        }
    }
    return @{ Files = $files; ManifestHash = (Get-ReportHash $sumStream) }
}

function Get-ReportUInt($Value, [switch]$RawBits) {
    $text = [string]$Value; [uint64]$number = 0
    if ($text -cnotmatch '^(0|[1-9][0-9]{0,19})$' -or ![uint64]::TryParse($text, [ref]$number)) { throw 'Invalid unsigned scalar.' }
    if (!$RawBits -and $number -eq [uint64]::MaxValue) { throw 'Saturated/overflow scalar cannot qualify.' }
    return $number
}

function Get-ReportScalar($Fields, [string]$Key) {
    if (!$Fields.ContainsKey($Key)) { throw "Missing reporting field: $Key." }
    return Get-ReportUInt $Fields[$Key]
}

function Read-ReportJson([string]$Line) {
    # The pinned writer emits flat canonical scalar objects, with exactly one
    # optional four-object durations array. Preserve decimal lexemes: PS5 JSON
    # numeric conversion must not round u64 counters, and duplicate keys reject.
    if ($Line.Length -gt 131072 -or !$Line.StartsWith('{') -or !$Line.EndsWith('}')) { throw 'Invalid reporting JSON object.' }
    $durations = $null; $needle = ',"durations":['; $arrayAt = $Line.IndexOf($needle, [StringComparison]::Ordinal)
    if ($arrayAt -ge 0) {
        if (!$Line.EndsWith(']}')) { throw 'Malformed durations tail.' }
        $body = $Line.Substring($arrayAt + $needle.Length, $Line.Length - $arrayAt - $needle.Length - 2)
        $objects = [regex]::Matches($body, '\{[^{}]*\}')
        if ($objects.Count -ne 4 -or (($objects | ForEach-Object { $_.Value }) -join ',') -cne $body) { throw 'Invalid duration object set.' }
        $durations = @($objects | ForEach-Object { Read-ReportJson $_.Value })
        $Line = $Line.Substring(0, $arrayAt) + '}'
    }
    $result = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $pattern = '\G\s*"(?<key>[A-Za-z_][A-Za-z0-9_]*)"\s*:\s*(?<value>"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9A-Fa-f]{4})*"|true|false|0|[1-9][0-9]*)(?<end>\s*[,}])'
    $regex = New-Object Text.RegularExpressions.Regex($pattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(1))
    $position = 1
    while ($position -lt $Line.Length) {
        # \G is start-position anchored; use an explicit Regex.Match(startat).
        $match = $regex.Match($Line, $position)
        if (!$match.Success -or $match.Index -ne $position) { throw 'Unsupported/noncanonical reporting JSON.' }
        $key = $match.Groups['key'].Value; $token = $match.Groups['value'].Value
        if ($result.ContainsKey($key)) { throw 'Duplicate reporting JSON key.' }
        if ($token.StartsWith('"')) { $value = $token | ConvertFrom-Json }
        elseif ($token -ceq 'true') { $value = $true }
        elseif ($token -ceq 'false') { $value = $false }
        else { $value = Get-ReportUInt $token -RawBits:($key -cin @('native_schedule_anchor_bits','native_interval_units','native_interval_override_bits','native_retry_override_bits')) }
        $result.Add($key, $value); $position += $match.Length
        if ($match.Groups['end'].Value.Trim() -ceq '}') {
            if ($position -ne $Line.Length) { throw 'Trailing JSON bytes.' }; break
        }
    }
    if ($position -ne $Line.Length -or !$result.Count) { throw 'Incomplete reporting JSON.' }
    if ($null -ne $durations) { if ($result.ContainsKey('durations')) { throw 'Duplicate durations.' }; $result.Add('durations', $durations) }
    return ,$result
}

function Assert-ReportShape($Record, [string[]]$Keys) {
    if ($Record.Count -ne $Keys.Count) { throw 'Unexpected reporting record fields.' }
    foreach ($key in $Keys) { if (!$Record.ContainsKey($key)) { throw "Missing record field: $key." } }
}

function Read-ReportConfiguration([string]$Text, [bool]$Reporting) {
    if (!$Text.Length -or $Text.Length -gt 4096 -or $Text -match '[^\x01-\x7f]|[\x01-\x08\x0b\x0c\x0e-\x1f]') { throw 'Invalid bounded ASCII configuration.' }
    $values = New-Object 'Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    foreach ($line in ($Text -split '\n')) {
        $clean = $line
        if ($clean.EndsWith("`r")) { $clean=$clean.Substring(0,$clean.Length-1) }
        $clean=$clean.Trim(' ', "`t")
        if (!$clean) { continue }
        if ($clean -cnotmatch '^([a-z_]+)[ \t]*=[ \t]*([^\r\n]+)$') { throw 'Malformed configuration line.' }
        if ($values.ContainsKey($Matches[1])) { throw 'Duplicate configuration key.' }
        $values.Add($Matches[1], $Matches[2])
    }
    if ($Reporting) {
        Assert-ReportFields $values @{ schema='2' }
        if ($values.Count -ne 2 -or !$values.ContainsKey('mode') -or $values['mode'] -cnotin @('disabled','observe','repair')) { throw 'Unsupported reporting configuration.' }
        return @{ mode=$values['mode']; quota_mib=0 }
    }
    Assert-ReportFields $values @{ enabled='1' }
    if ($values.Count -gt 2 -or ($values.Count -eq 2 -and !$values.ContainsKey('max_log_mib'))) { throw 'Unknown observer prerequisite key.' }
    [uint32]$quota=512
    if ($values.ContainsKey('max_log_mib') -and ($values['max_log_mib'] -cnotmatch '^[0-9]{1,10}$' -or
        ![uint32]::TryParse($values['max_log_mib'],[ref]$quota))) { throw 'Invalid logging quota.' }
    if ($quota -lt 16 -or $quota -gt 1024) { throw 'Invalid logging quota.' }
    return @{ mode='enabled'; quota_mib=$quota }
}

function Invoke-ReportInventory([string]$Package, $Files, [string]$ServerRoot, [uint32]$SelectedId, [string]$Report) {
    $arguments = @('--pid',[string]$SelectedId,'--target-root',$ServerRoot,'--expect','proxy-pass',
        '--mode','active','--expected-recon','corrected','--companion-kind','companion-reporting',
        '--bootstrap-sha256',$Files['dlls/X3DAudio1_7.dll'],'--companion-sha256',$Files['dlls/RS2ServerFix.dll'],
        '--genuine-manifest',(Join-Path $Package 'config\qualified_x3audio_genuine.manifest'),'--report',$Report)
    $begin = [Diagnostics.Stopwatch]::GetTimestamp()
    & (Join-Path $Package 'tools\rs2_runtime_inventory.exe') @arguments | Out-Host
    $code = $LASTEXITCODE; $end = [Diagnostics.Stopwatch]::GetTimestamp()
    # Even rejected/no-writer status must be retained before asking for any log.
    if (!(Test-Path -LiteralPath $Report)) { throw "Inventory produced no bounded evidence ($code); no bypass." }
    $stream = [RS2ReportCollection.Files]::Open($Report, $false)
    try { $fields = Read-ReportFields (Read-ReportText $stream (8MB)) } finally { $stream.Dispose() }
    Assert-ReportFields $fields @{ schema='1'; mode='runtime-inventory'; pid=[string]$SelectedId;
        companion_kind='companion-reporting'; bootstrap_sha256=$Files['dlls/X3DAudio1_7.dll'];
        companion_sha256=$Files['dlls/RS2ServerFix.dll']; tool_sha256=$Files['tools/rs2_runtime_inventory.exe'];
        manifest_sha256=$Files['config/qualified_x3audio_genuine.manifest'] }
    return @{ fields=$fields; command_start_qpc=[uint64]$begin; command_end_qpc=[uint64]$end; exit_code=$code; path=$Report }
}

function Test-ReportReady($Snapshot) {
    $f = $Snapshot.fields
    return $Snapshot.exit_code -eq 0 -and $f.ContainsKey('reporting.current_ready') -and
        $f['reporting.current_ready'] -ceq 'true' -and $f['reporting.captured'] -ceq 'true' -and
        $f['reporting.header_valid'] -ceq 'true' -and $f['reporting.owner_valid'] -ceq 'true' -and
        $f['reporting.identity_complete'] -ceq 'true' -and $f['recon_artifact_result'] -ceq 'pass'
}

function Assert-ReportSnapshot($Snapshot, $First) {
    $f = $Snapshot.fields; $initial = $First.fields
    foreach ($key in @('process_creation_filetime','process_image_path','host_sha256','sdk_sha256','steamclient_sha256',
        'observed_bootstrap_sha256','observed_companion_sha256','reporting.run_id','reporting.mode','reporting.qpc_frequency')) {
        if (!$f.ContainsKey($key) -or !$initial.ContainsKey($key) -or $f[$key] -cne $initial[$key]) { throw "Current process/run identity changed: $key." }
    }
    Assert-ReportFields $f @{ host_sha256=$script:ReportHostHash; sdk_sha256=$script:ReportSdkHash;
        steamclient_sha256=$script:ReportClientHash; 'reporting.schema'='2'; 'reporting.bytes'='1288';
        'reporting.artifact_version'='262656'; 'reporting.header_validity'='31';
        'reporting.pid'=$f['pid'];'reporting.process_creation'=$f['process_creation_filetime'];
        observed_bootstrap_sha256=$f['bootstrap_sha256'];observed_companion_sha256=$f['companion_sha256'];
        expect='proxy-pass';deployment_mode='active';expected_recon='corrected';observed_recon='corrected';
        recon_sha256='F402D3262D39EC73E9B33E14CC4F74B06EC981ECDE94D59ADF67D905CC1DA2D5';constant_match='true';finding_count='0';result='pass' }
    $frequency = Get-ReportScalar $f 'reporting.qpc_frequency'
    if ($frequency -ne [uint64][Diagnostics.Stopwatch]::Frequency) { throw 'Collector and target QPC frequencies differ.' }
    $lower = Get-ReportScalar $f 'reporting.lastOwnerQpc'; $upper = Get-ReportScalar $f 'reporting.observed_qpc'
    if (!$lower -or $lower -gt $upper -or $upper -gt $Snapshot.command_end_qpc -or
        $upper -lt $Snapshot.command_start_qpc -or ([System.Numerics.BigInteger]$upper - $lower) -gt (2 * [System.Numerics.BigInteger]$frequency)) {
        throw 'Current-status time bounds invalid or stale.'
    }
    $accounted = Get-ReportScalar $f 'reporting.timingAccountedThroughQpc'
    if ($accounted -gt $lower) { throw 'Completed timing watermark is newer than owner publication.' }
    # A live owner can still have no completed root, or a long unfinished one.
    # Do not impose the liveness width on this deliberately older timing range.
    return @{ coverage_range=@{ lower=$lower; upper=$upper };
        timing_range=$(if ($accounted) { @{ lower=$accounted; upper=$upper } } else { $null }) }
}

function Read-ReportNativeSchedule($Record) {
    $fields=@('native_schedule_valid','native_schedule_anchor_bits','native_errors_bits','native_throttles_bits',
        'native_expedite','native_retry_limit','native_interval_units','native_interval_override_bits',
        'native_retry_override_bits','native_delay_units','native_tier')
    if($Record['native_schedule_valid'] -gt 1 -or $Record['native_task_state'] -notin 0,2,3,4,5) { throw 'Invalid native scheduler validity/state.' }
    if(!$Record['native_schedule_valid']) {
        foreach($key in $fields) { if($Record[$key] -ne 0) { throw 'Unavailable native schedule contains stale scalars.' } }
    } else {
        if($Record['native_task_state'] -notin 2,3,4,5 -or
            $Record['native_errors_bits'] -gt [uint32]::MaxValue -or $Record['native_throttles_bits'] -gt [uint32]::MaxValue -or
            $Record['native_expedite'] -gt 255 -or $Record['native_retry_limit'] -gt 65535 -or $Record['native_tier'] -gt 6) { throw 'Unsupported native scheduler scalar width/value.' }
        $tier=0;[uint64]$delay=0
        if($Record['native_interval_units'] -eq 30000 -and $Record['native_retry_limit'] -eq 3 -and
            !$Record['native_interval_override_bits'] -and !$Record['native_retry_override_bits']) {
            if($Record['native_task_state'] -eq 2) { $tier=1;$delay=30000 }
            elseif($Record['native_task_state'] -eq 3 -and $Record['native_errors_bits'] -le [int32]::MaxValue -and $Record['native_throttles_bits'] -le [int32]::MaxValue) {
                $tier=2;$delay=2000
                if($Record['native_errors_bits'] -ge 3 -or $Record['native_throttles_bits'] -gt 5) { $tier=3;$delay=30000 }
                if($Record['native_errors_bits'] -ge 6) { $tier=4;$delay=60000 }
                if($Record['native_errors_bits'] -ge 9) { $tier=5;$delay=300000 }
                if($Record['native_errors_bits'] -ge 12) { $tier=6;$delay=1800000 }
            }
        }
        if($Record['native_tier'] -ne $tier -or $Record['native_delay_units'] -ne $delay) { throw 'Native scheduler tier contradicts its observed state/defaults.' }
    }
    $out=@{qpc=[string]$Record['qpc'];source_epoch=[string]$Record['source_epoch'];binding_epoch=[string]$Record['binding_epoch'];
        native_task_state=[string]$Record['native_task_state'];observation='historical';next_eligibility='unknown';
        due_state='unknown';proves_preventing_backoff=$false}
    foreach($key in $fields) { $out[$key]=[string]$Record[$key] }
    if($Record['native_schedule_valid'] -eq 1 -and $Record['native_task_state'] -in 2,3 -and $Record['native_expedite'] -ne 0) { $out.due_state='expedite-pending' }
    return $out
}

function Read-ReportLog([string]$Path, $Identity, [string]$RunDirectory, [uint64]$QuotaBytes, [uint64]$StartQpc, [uint64]$EndQpc, $Snapshots=@()) {
    $common = @('type','schema','run_id','pid','sequence','qpc','source_epoch','binding_epoch','kind','reason','flags','thread_id')
    $stateKeys = @('phase','request_sequence','witness_sequence','build_sequence','pending_since_qpc','fresh_since_qpc',
        'qualification_flags','native_task_state','client_qualification_ms','mode','classification','pi','bots','maximum','pending','fresh','bound',
        'native_schedule_valid','native_schedule_anchor_bits','native_errors_bits','native_throttles_bits','native_expedite',
        'native_retry_limit','native_interval_units','native_interval_override_bits','native_retry_override_bits','native_delay_units','native_tier')
    $requestKeys = @('request_sequence','witness_sequence','staged_qpc','previous_sample_qpc','observed_qpc','fresh_since_qpc',
        'source_age_ticks','pi','bots','maximum','staged_bots','human_players','world_bots','classification','pending')
    $buildKeys = @('build_sequence','request_sequence','witness_sequence','source_age_ticks','probe_elapsed_ticks','classification_elapsed_ticks',
        'original_elapsed_ticks','entry_qpc','return_qpc','pi','bots','maximum','classification','selected','result','pending','fresh')
    $anchorKeys = @('normal_attempts','full_selected','selected_true','normal_returns','false_returns','native_unwinds',
        'request_sequence','witness_sequence','build_sequence','distinct_selected_witnesses','durations')
    $startupKeys = @('type','schema','artifact','version','artifact_version','run_id','pid','process_start_filetime','qpc_frequency',
        'utc_filetime','qpc','mode','configured_mode','header_validity','host_sha256','qualified_steam_api_sha256',
        'qualified_steamclient_sha256','max_log_bytes','record_bytes','ring_capacity','batch_limit','authentication_changed',
        'verbose_observer_trace','termination_may_lose_tail','directory')
    $types = @('','state','request','witness','builder-enter','builder-return','builder-unwind','anchor')
    $startup = $null; $anchor = $null; [uint64]$sequence = 0; [uint64]$lastQpc = 0; [uint64]$lastBuild = 0
    $openBuild = $null; $pairs = New-Object 'Collections.Generic.List[object]'; $requests = @{}; $witnesses = @{}
    $schedulerSamples=New-Object 'Collections.Generic.List[object]'
    $count = 0; $windowRequests = 0; $windowSelections = 0; $sourceChanges = $false; $firstEpoch = $null
    $epochBaseline = $null
    $totals=@{normal_attempts=[uint64]0;full_selected=[uint64]0;selected_true=[uint64]0;normal_returns=[uint64]0;
        false_returns=[uint64]0;native_unwinds=[uint64]0;request_sequence=[uint64]0;witness_sequence=[uint64]0;
        build_sequence=[uint64]0;distinct_selected_witnesses=[uint64]0}
    $mapping=@{normal_attempts='normalAttempts';full_selected='fullSelected';selected_true='selectedTrue';normal_returns='normalReturns';
        false_returns='falseReturns';native_unwinds='nativeUnwinds';request_sequence='requestSequence';witness_sequence='witnessSequence';
        build_sequence='buildSequence';distinct_selected_witnesses='distinctSelectedWitnesses'}
    [uint64]$lastSelectedWitness=0; $populationSamples=0; $humanObserved=$false; $watermarks=@{}
    foreach ($snapshot in $Snapshots) {
        $f=$snapshot.fields
        if ($f.ContainsKey('reporting.owner_valid') -and $f['reporting.owner_valid'] -ceq 'true' -and
            $f['reporting.run_id'] -ceq $Identity['reporting.run_id']) {
            $mark=[string](Get-ReportScalar $f 'reporting.reportSequence')
            if (!$watermarks.ContainsKey($mark)) { $watermarks[$mark]=New-Object 'Collections.Generic.List[object]' }
            $watermarks[$mark].Add($snapshot)
        }
    }
    foreach ($line in [RS2ReportCollection.Files]::CompleteLines($Path)) {
        if (++$count -gt 2000000) { throw 'Reporting log record bound exceeded.' }
        $r = Read-ReportJson $line
        if ($r['type'] -ceq 'startup') {
            Assert-ReportShape $r $startupKeys
            foreach ($key in @('schema','artifact_version','pid','process_start_filetime','qpc_frequency','utc_filetime','qpc',
                'configured_mode','header_validity','max_log_bytes','record_bytes','ring_capacity','batch_limit')) {
                if ($r[$key] -isnot [uint64]) { throw 'Startup numeric field has wrong JSON type.' }
            }
            if ($null -ne $startup -or $count -ne 1) { throw 'Duplicate/misplaced reporting startup.' }
            Assert-ReportFields $r @{ schema='2'; artifact='RS2ServerFix-steam-reporting'; version='0.4.2.0'; artifact_version='262656';
                run_id=$Identity['reporting.run_id']; pid=$Identity['pid']; process_start_filetime=$Identity['process_creation_filetime'];
                qpc_frequency=$Identity['reporting.qpc_frequency']; configured_mode=$Identity['reporting.mode']; header_validity='31';
                record_bytes='256'; ring_capacity='256'; batch_limit='32'; max_log_bytes=[string]$QuotaBytes }
            if ($r['authentication_changed'] -isnot [bool] -or $r['authentication_changed'] -or
                $r['verbose_observer_trace'] -isnot [bool] -or $r['verbose_observer_trace'] -or
                $r['termination_may_lose_tail'] -isnot [bool] -or !$r['termination_may_lose_tail'] -or
                !([string]$r['directory']).Equals($RunDirectory,[StringComparison]::OrdinalIgnoreCase) -or
                !([IO.Path]::GetFileName($RunDirectory)).EndsWith('-PID' + $Identity['pid'] + '-' + $r['run_id'],[StringComparison]::Ordinal) -or
                ([string]$r['host_sha256']).ToUpperInvariant() -cne $script:ReportHostHash -or
                ([string]$r['qualified_steam_api_sha256']).ToUpperInvariant() -cne $script:ReportSdkHash -or
                ([string]$r['qualified_steamclient_sha256']).ToUpperInvariant() -cne $script:ReportClientHash -or
                $r['utc_filetime'] -lt (Get-ReportScalar $Identity 'process_creation_filetime') -or
                $r['utc_filetime'] -gt [uint64][DateTime]::UtcNow.ToFileTimeUtc()) { throw 'Reporting startup identity mismatch.' }
            $expectedMode = if ($Identity['reporting.mode'] -ceq '2') { 'observe' } else { 'repair' }
            if ($r['mode'] -cne $expectedMode) { throw 'Startup mode mismatch.' }
            $startup = $r; continue
        }
        if ($null -eq $startup) { throw 'Missing reporting startup.' }
        $kind = Get-ReportScalar $r 'kind'
        if ($kind -lt 1 -or $kind -gt 7 -or $r['type'] -cne $types[$kind]) { throw 'Unknown reporting record kind.' }
        $extra = switch ($kind) { 1 { $stateKeys }; { $_ -in 2,3 } { $requestKeys }; { $_ -in 4,5,6 } { $buildKeys }; 7 { $anchorKeys } }
        Assert-ReportShape $r ($common + $extra)
        Assert-ReportFields $r @{ schema='2'; run_id=$Identity['reporting.run_id']; pid=$Identity['pid'];thread_id=$Identity['reporting.ownerThreadId'];flags='0' }
        foreach ($key in $r.Keys) { if ($key -cnotin @('type','run_id','durations') -and $r[$key] -isnot [uint64]) { throw 'Record numeric field has wrong JSON type.' } }
        if ([System.Numerics.BigInteger]$r['sequence'] -ne ([System.Numerics.BigInteger]$sequence + 1) -or $r['qpc'] -lt $lastQpc -or $r['reason'] -ge 59 -or !$r['thread_id']) { throw 'Reporting sequence/time/reason invalid.' }
        $sequence = $r['sequence']; $lastQpc = $r['qpc']
        foreach ($boolean in @('selected','result','pending','fresh','bound')) {
            if ($r.ContainsKey($boolean) -and $r[$boolean] -gt 1) { throw 'Invalid boolean scalar.' }
        }
        $inWindow = $r['qpc'] -ge $StartQpc -and $r['qpc'] -lt $EndQpc
        $epoch = [string]$r['source_epoch'] + ':' + [string]$r['binding_epoch']
        if ($r['qpc'] -lt $StartQpc -and $kind -in 1,7) {
            # Use the last owner State/Anchor BEFORE the fixed window. Taking
            # the first in-window epoch as baseline can hide a rebind at score.
            $epochBaseline = $epoch; $firstEpoch = $epoch
        } elseif ($inWindow) {
            if ($null -eq $firstEpoch) { $firstEpoch = $epoch } elseif ($firstEpoch -cne $epoch) { $sourceChanges = $true }
        }
        if ($kind -eq 1) {
            $schedule=Read-ReportNativeSchedule $r
            if($inWindow) { $schedulerSamples.Add($schedule) }
        } elseif ($kind -eq 2) {
            $id = [string]$r['request_sequence']
            if ([System.Numerics.BigInteger]$r['request_sequence'] -ne [System.Numerics.BigInteger]$totals.request_sequence+1 -or $requests.ContainsKey($id)) { throw 'Duplicate/gapped producer request.' }
            $totals.request_sequence=$r['request_sequence']
            $requests[$id] = @($r['source_epoch'],$r['binding_epoch'])
            if ($requests.Count -gt 65536) { throw 'Request history bound exceeded.' }
            if ($inWindow) { ++$windowRequests }
        } elseif ($kind -eq 3) {
            $id = [string]$r['witness_sequence']; $request = [string]$r['request_sequence']
            if ([System.Numerics.BigInteger]$r['witness_sequence'] -ne [System.Numerics.BigInteger]$totals.witness_sequence+1 -or $witnesses.ContainsKey($id) -or !$requests.ContainsKey($request) -or
                $requests[$request][0] -ne $r['source_epoch'] -or $requests[$request][1] -ne $r['binding_epoch']) { throw 'Witness has no matching request/epoch.' }
            $witnesses[$id] = @($r['request_sequence'],$r['source_epoch'],$r['binding_epoch'])
            $totals.witness_sequence=$r['witness_sequence']
            if ($witnesses.Count -gt 65536) { throw 'Witness history bound exceeded.' }
        } elseif ($kind -eq 4) {
            if ($null -ne $openBuild -or [System.Numerics.BigInteger]$r['build_sequence'] -ne [System.Numerics.BigInteger]$lastBuild+1 -or
                $r['classification'] -ne 2 -or $r['selected'] -ne 0 -or $r['result'] -ne 0 -or $r['return_qpc'] -ne 0 -or
                $r['entry_qpc'] -ne $r['qpc']) { throw 'Invalid/nested builder enter.' }
            $openBuild = $r; $lastBuild = $r['build_sequence']
            ++$totals.normal_attempts; $totals.build_sequence=$lastBuild
        } elseif ($kind -in 5,6) {
            if ($null -eq $openBuild) { throw 'Builder completion without enter.' }
            foreach ($key in @('build_sequence','request_sequence','witness_sequence','source_epoch','binding_epoch','entry_qpc','classification','pi','bots','maximum')) {
                if ($r[$key] -ne $openBuild[$key]) { throw 'Builder completion linkage mismatch.' }
            }
            if ($r['return_qpc'] -lt $r['entry_qpc'] -or $r['return_qpc'] -gt $r['qpc'] -or $r['result'] -gt 1) { throw 'Builder return time/result invalid.' }
            # Enter is deliberately emitted before final write admission, and
            # always has selected=0. Only Return/Unwind says if the store occurred.
            if ($r['selected'] -eq 1) {
                $w=[string]$r['witness_sequence']
                if (!$witnesses.ContainsKey($w) -or $witnesses[$w][0] -ne $r['request_sequence'] -or
                    $witnesses[$w][1] -ne $r['source_epoch'] -or $witnesses[$w][2] -ne $r['binding_epoch']) { throw 'Selection has no matching producer witness.' }
                ++$totals.full_selected
                if ($lastSelectedWitness -ne $r['witness_sequence']) { ++$totals.distinct_selected_witnesses; $lastSelectedWitness=$r['witness_sequence'] }
                if ($inWindow) { ++$windowSelections }
            }
            if ($kind -eq 5) {
                ++$totals.normal_returns
                if (!$r['result']) { ++$totals.false_returns }
                if ($r['selected'] -and $r['result']) { ++$totals.selected_true }
            } else { ++$totals.native_unwinds }
            if ($openBuild['entry_qpc'] -ge $StartQpc -and $r['return_qpc'] -lt $EndQpc) {
                $pairs.Add(@{ entry=$openBuild['entry_qpc']; returned=$r['return_qpc']; selected=$r['selected']; result=$r['result'];
                    witness=$r['witness_sequence']; unwind=($kind -eq 6);
                    entry_reason=$openBuild['reason'];return_reason=$r['reason'] })
            }
            $openBuild = $null
        } elseif ($kind -eq 7) {
            for ($i=0;$i -lt 4;++$i) {
                $d = $r['durations'][$i]
                Assert-ReportShape $d @('class','calls','elapsed_ticks','maximum_ticks','over_five_milliseconds')
                if ((Get-ReportScalar $d 'class') -ne $i) { throw 'Duration class mismatch.' }
                foreach ($key in $d.Keys) { if ($d[$key] -isnot [uint64]) { throw 'Duration field has wrong JSON type.' } }
                if ($d['over_five_milliseconds'] -gt $d['calls'] -or $d['maximum_ticks'] -gt $d['elapsed_ticks']) { throw 'Invalid duration counters.' }
            }
            foreach ($key in $totals.Keys) { if ($r[$key] -ne $totals[$key]) { throw "Anchor/event counter mismatch: $key." } }
            if ($null -ne $anchor) {
                foreach ($key in $anchorKeys) { if ($key -cne 'durations' -and $r[$key] -lt $anchor[$key]) { throw 'Anchor counters decreased.' } }
                for ($i=0;$i -lt 4;++$i) { foreach ($key in @('calls','elapsed_ticks','maximum_ticks','over_five_milliseconds')) {
                    if ($r['durations'][$i][$key] -lt $anchor['durations'][$i][$key]) { throw 'Anchor timing counters decreased.' }
                } }
            }
            $anchor = $r
        }
        if ($inWindow -and $kind -in 2,3) { ++$populationSamples; if ($r['human_players'] -gt 0) { $humanObserved=$true } }
        if ($watermarks.ContainsKey([string]$sequence)) {
            foreach ($snapshot in $watermarks[[string]$sequence]) {
                foreach ($key in $totals.Keys) {
                    if ((Get-ReportScalar $snapshot.fields ('reporting.'+$mapping[$key])) -ne $totals[$key]) { throw "DATA/event watermark mismatch: $key." }
                }
            }
        }
    }
    if ($null -eq $startup) { throw 'Empty/no-startup reporting log.' }
    return @{ startup=$startup; last_sequence=$sequence; last_qpc=$lastQpc; latest_anchor=$anchor;
        pairs=@($pairs.ToArray()); open_builder=$openBuild; source_changes=$sourceChanges; window_requests=$windowRequests; window_selections=$windowSelections;
        epoch_baseline_available=($null -ne $epochBaseline); epoch_baseline=$epochBaseline;
        population_samples=$populationSamples; human_observed=$humanObserved; counters=$totals;
        scheduler_samples=@($schedulerSamples.ToArray()) }
}

function Find-ReportBoundary($Snapshots, [uint64]$Target, [ValidateSet('coverage','timing')][string]$Family='coverage') {
    $before = $null; $after = $null
    $rangeKey=$Family+'_range'
    foreach ($s in $Snapshots) {
        if (!$s.ContainsKey($rangeKey) -or $null -eq $s[$rangeKey]) { continue }
        if ($s[$rangeKey].upper -le $Target -and ($null -eq $before -or $s[$rangeKey].upper -gt $before[$rangeKey].upper)) { $before = $s }
        if ($s[$rangeKey].lower -ge $Target -and ($null -eq $after -or $s[$rangeKey].lower -lt $after[$rangeKey].lower)) { $after = $s }
    }
    return @{ family=$Family; target=$Target; before=$before; after=$after; complete=($null -ne $before -and $null -ne $after) }
}

function Get-ReportDifference($End, $Begin, [string]$Key) {
    $difference = [System.Numerics.BigInteger](Get-ReportScalar $End.fields $Key) - [System.Numerics.BigInteger](Get-ReportScalar $Begin.fields $Key)
    if ($difference -lt 0) { throw "Cumulative counter decreased: $Key." }
    return $difference
}

function Get-ReportEnvelope($Begin, $End, [string]$Key) {
    $maximum = Get-ReportDifference $End.after $Begin.before $Key
    # Brackets may overlap when inventory is slow. That gives a zero lower
    # bound, not evidence that the actual monotonic counters went backwards.
    $minimum = [System.Numerics.BigInteger](Get-ReportScalar $End.before.fields $Key) - [System.Numerics.BigInteger](Get-ReportScalar $Begin.after.fields $Key)
    if ($minimum -lt 0) { $minimum = [System.Numerics.BigInteger]0 }
    if ($maximum -lt $minimum) { throw 'Counter envelope inverted.' }
    return @{ minimum=$minimum; maximum=$maximum }
}

function Read-ReportTimingCalibration($Files, [string]$Package) {
    # Only a reviewed fixture-produced file owned by the verified package can
    # supply calibration. There is no CLI self-attestation or guessed allowance.
    if (!$Files.ContainsKey('timing-calibration.json')) {
        return @{ qualified=$false; integrity_valid=$false; companion_sha256=$Files['dlls/RS2ServerFix.dll'];
            reason='artifact-bound-final-epilogue-measurement-not-yet-qualified'; frequency=[uint64]0;
            class_floors=@() }
    }
    $path=Resolve-ReportPlain (Join-Path $Package 'timing-calibration.json') $false
    $stream=[RS2ReportCollection.Files]::Open($path,$false)
    try {
        if ((Get-ReportHash $stream) -cne $Files['timing-calibration.json']) { throw 'Calibration package hash mismatch.' }
        $r=Read-ReportJson ((Read-ReportText $stream 8192).TrimEnd("`r","`n"))
    } finally { $stream.Dispose() }
    $numeric=@('schema','qpc_frequency','pump_sample_count','main_pump_sample_count','main_management_sample_count',
        'builder_sample_count','builder_selected_count')
    $keys=$numeric+@('measurement_id','protocol_id','companion_sha256','fixture_sha256','source_inventory_sha256',
        'compiler','configuration','floor_ledger_sha256','scope','limitation','coverage_pass')
    for($i=0;$i -lt 4;++$i) {
        foreach($suffix in @('sample_count','residual_sum_ticks','current_maximum_missing_ticks','floor_ticks')) {
            $key='class'+$i+'_'+$suffix;$keys+=$key;$numeric+=$key
        }
        $keys+='class'+$i+'_eligible'
    }
    Assert-ReportShape $r $keys
    foreach ($key in $numeric) {
        if ($r[$key] -isnot [uint64]) { throw 'Calibration numeric field has wrong type.' }
    }
    Assert-ReportFields $r @{schema='3';companion_sha256=$Files['dlls/RS2ServerFix.dll'];
        measurement_id='rs2-wrapper-own-deferred-v2';protocol_id='rs2-deferred-v2-fixed6000-1024';configuration='Release-AMD64';
        scope='outer-wrapper-minus-recorded-own-minus-inner-original';limitation='fixture-measured-not-hard-real-time'}
    foreach($key in @('fixture_sha256','source_inventory_sha256','floor_ledger_sha256')) {
        if ($r[$key] -isnot [string] -or $r[$key] -cnotmatch '^[0-9A-F]{64}$') { throw 'Invalid calibration custody digest.' }
    }
    if ($r['compiler'] -isnot [string] -or $r['compiler'] -cnotmatch '^[\x20-\x7e]{1,256}$' -or
        !$r['qpc_frequency'] -or [System.Numerics.BigInteger]$r['qpc_frequency'] -gt
            [System.Numerics.BigInteger]::Divide([System.Numerics.BigInteger][int64]::MaxValue,45) -or
        $r['coverage_pass'] -isnot [bool] -or $r['pump_sample_count'] -ne 7024 -or $r['main_pump_sample_count'] -ne 6000 -or
        $r['builder_sample_count'] -ne 1024 -or $r['builder_selected_count'] -ne 1024 -or
        $r['main_management_sample_count'] -gt 6000 -or
        $r['coverage_pass'] -ne ($r['main_management_sample_count'] -ge 64)) { throw 'Invalid fixed-protocol calibration evidence.' }
    $classes=@()
    for($i=0;$i -lt 4;++$i) {
        $prefix='class'+$i+'_';$count=$r[$prefix+'sample_count'];$sum=$r[$prefix+'residual_sum_ticks']
        $maximum=$r[$prefix+'current_maximum_missing_ticks'];$floor=$r[$prefix+'floor_ticks'];$eligible=$r[$prefix+'eligible']
        # Eligibility describes the immutable same-domain ledger, not only this
        # run. A previously observed class can have no current samples, including
        # a genuine zero-valued historical maximum; zero alone proves nothing.
        if ($eligible -isnot [bool] -or ($count -gt 0 -and !$eligible) -or $maximum -gt $sum -or $floor -lt $maximum -or
            [System.Numerics.BigInteger]$sum -gt [System.Numerics.BigInteger]$count*$maximum -or
            (!$eligible -and ($sum -or $maximum -or $floor))) { throw 'Invalid class calibration arithmetic/eligibility.' }
        $classes+=@{class=$i;sample_count=$count;residual_sum_ticks=$sum;current_maximum_missing_ticks=$maximum;
            floor_ticks=$floor;eligible=$eligible}
    }
    if ([System.Numerics.BigInteger]$classes[0].sample_count+$classes[1].sample_count -ne 7024 -or
        $classes[2].sample_count -ne 0 -or $classes[2].eligible -or $classes[3].sample_count -ne 1024 -or
        $r['main_management_sample_count'] -gt $classes[1].sample_count) { throw 'Calibration classes disagree with the fixed protocol.' }
    return @{qualified=$r['coverage_pass'];integrity_valid=$true;companion_sha256=$r['companion_sha256'];fixture_sha256=$r['fixture_sha256'];
        frequency=$r['qpc_frequency'];measurement_id=$r['measurement_id'];protocol_id=$r['protocol_id'];
        source_inventory_sha256=$r['source_inventory_sha256'];floor_ledger_sha256=$r['floor_ledger_sha256'];
        compiler=$r['compiler'];configuration=$r['configuration'];class_floors=$classes;
        pump_sample_count=$r['pump_sample_count'];main_pump_sample_count=$r['main_pump_sample_count'];
        main_management_sample_count=$r['main_management_sample_count'];coverage_pass=$r['coverage_pass'];
        builder_sample_count=$r['builder_sample_count'];builder_selected_count=$r['builder_selected_count'];
        reason=$(if($r['coverage_pass']){$r['limitation']}else{'fixed-protocol-management-coverage-insufficient'});
        calibration_sha256=$Files['timing-calibration.json']}
}

function Read-ReportPerformanceAssessment($Files, [string]$Package, $Calibration) {
    $policy='rs2-sustained-phase-mean-observe-v1'
    if (!$Files.ContainsKey('performance-assessment.json')) {
        return @{available=$false;qualified=$false;assessment_id=$policy;frequency=[uint64]0;
            class_coefficients=@();reason='performance-assessment-missing'}
    }
    # Optional absence is benign; a present but invalid model is a mis-built kit,
    # not permission to silently ignore a broken provenance/identity contract.
    if (!$Files.ContainsKey('timing-calibration.json') -or !$Calibration.ContainsKey('integrity_valid') -or
        !$Calibration.integrity_valid) { throw 'Assessment requires valid bound calibration.' }
    $path=Resolve-ReportPlain (Join-Path $Package 'performance-assessment.json') $false
    $stream=[RS2ReportCollection.Files]::Open($path,$false)
    try {
        $digest=Get-ReportHash $stream
        if ($digest -cne $Files['performance-assessment.json']) { throw 'Assessment package hash mismatch.' }
        $record=Read-ReportJson ((Read-ReportText $stream 8192).TrimEnd("`r","`n"))
    } finally { $stream.Dispose() }
    $keys=@('schema','assessment_id','measurement_id','protocol_id','scope','mean_rule','reference_frequency',
        'companion_sha256','timing_calibration_sha256','floor_ledger_sha256','source_inventory_sha256','model_provenance_sha256')
    $numeric=@('schema','reference_frequency')
    for($i=0;$i -lt 4;++$i){$key='class'+$i+'_coefficient_ticks';$keys+=$key;$numeric+=$key;$keys+='class'+$i+'_eligible'}
    Assert-ReportShape $record $keys
    foreach($key in $numeric){if($record[$key] -isnot [uint64]){throw 'Assessment numeric field has wrong type.'};$null=Get-ReportUInt $record[$key]}
    foreach($key in @('companion_sha256','timing_calibration_sha256','floor_ledger_sha256','source_inventory_sha256','model_provenance_sha256')){
        if($record[$key] -isnot [string] -or $record[$key] -cnotmatch '^[0-9A-F]{64}$'){throw 'Invalid assessment custody digest.'}
    }
    Assert-ReportFields $record @{schema='1';assessment_id=$policy;measurement_id='rs2-wrapper-own-deferred-v2';
        protocol_id='rs2-deferred-v2-fixed6000-1024';scope='post-capture-isolated-observe-only';
        mean_rule='max-all-run-phase-means-ceil';reference_frequency='10000000';companion_sha256=$Files['dlls/RS2ServerFix.dll'];
        timing_calibration_sha256=$Calibration.calibration_sha256;floor_ledger_sha256=$Calibration.floor_ledger_sha256;
        source_inventory_sha256=$Calibration.source_inventory_sha256}
    if($Calibration.companion_sha256 -cne $record['companion_sha256'] -or
        $Calibration.measurement_id -cne $record['measurement_id'] -or $Calibration.protocol_id -cne $record['protocol_id'] -or
        $Calibration.calibration_sha256 -cne $Files['timing-calibration.json'] -or $Calibration.class_floors.Count -ne 4){throw 'Assessment/calibration identity mismatch.'}
    $frequency=[System.Numerics.BigInteger](Get-ReportUInt $Calibration.frequency)
    if($frequency -le 0){throw 'Assessment calibration clock unavailable.'}
    $classes=@()
    for($i=0;$i -lt 4;++$i){
        $coefficient=$record['class'+$i+'_coefficient_ticks'];$eligible=$record['class'+$i+'_eligible'];$floor=$Calibration.class_floors[$i]
        if($eligible -isnot [bool] -or $floor.class -ne $i -or $eligible -ne $floor.eligible -or
            (!$eligible -and $coefficient -ne 0)){throw 'Assessment class availability mismatch.'}
        $referenceFloor=[System.Numerics.BigInteger]::Divide(
            [System.Numerics.BigInteger](Get-ReportUInt $floor.floor_ticks)*10000000+$frequency-1,$frequency)
        if([System.Numerics.BigInteger]$coefficient -gt $referenceFloor){throw 'Assessment mean exceeds retained maximum.'}
        $classes+=@{class=$i;eligible=$eligible;ticks=$coefficient}
    }
    $result=@{available=$true;qualified=[bool]$Calibration.qualified;frequency=$record['reference_frequency'];
        class_coefficients=$classes;assessment_sha256=$digest;reason='empirical-model-not-true-cost-bound'}
    foreach($key in $keys){$result[$key]=$record[$key]}
    return $result
}

function New-ReportTrialAssessment([string]$Mode='') {
    $knownOther=$Mode -ceq 'repair'
    return @{schema=1;assessment_id='rs2-sustained-phase-mean-observe-v1';scope='post-capture-observe-pilot';
        verdict=$(if($knownOther){'NOT_APPLICABLE'}else{'INCONCLUSIVE'});
        reasons=@($(if($knownOther){'mode-not-observe'}else{'not-evaluated'}));
        model_state='UNAVAILABLE';latency_guard='INCONCLUSIVE';model=$null;model_identity=$null;
        legacy_maximum_verdict='INCONCLUSIVE';not_production_qualification=$true;
        pilot_start_authorized=$false;no_automatic_promotion=$true}
}

function Measure-ReportSustainedModel($Summary, [uint64]$Frequency, $Calibration, $Assessment, [string]$CompanionHash) {
    $result=@{available=$false;qualified=$false;state='UNAVAILABLE';reason='timing-or-performance-unavailable';
        projected_low_ticks=$null;projected_high_ticks=$null;window_ticks=$null;frequency=[string]$Frequency;
        classes=@();missing_called_classes=@();latency_guard='INCONCLUSIVE';management=$null;
        limitation='conditional-on-empirical-fixture-model-not-confidence-or-true-total-cost-bound'}
    if(!$Summary.ContainsKey('performance') -or !$Summary.performance.ContainsKey('classes') -or
        $Summary.performance.classes.Count -ne 4){return $result}
    # Reuse exactly the legacy per-class tail decisions. Its aggregate-MAX veto
    # is intentionally not a tail decision and remains untouched in old output.
    $guard='PASS'
    for($i=0;$i -lt 4;++$i){
        $entry=$Summary.performance.classes[$i]
        if($entry.class -ne $i){if($guard -cne 'FAIL'){$guard='INCONCLUSIVE'};break}
        if($entry.with_epilogue -ceq 'FAIL'){$guard='FAIL'}
        elseif($entry.with_epilogue -cne 'PASS' -and
            !($entry.with_epilogue -ceq 'UNOBSERVED' -and $i -in 0,2 -and $entry.calls_max -ceq '0')){
            if($guard -cne 'FAIL'){$guard='INCONCLUSIVE'}
        }
    }
    $result.latency_guard=$guard
    if(!$Summary.ContainsKey('scored_counters') -or !$Summary.scored_counters.timing.complete -or
        !$Summary.scored_counters.timing.ContainsKey('counters')){return $result}
    try {
        $window=[System.Numerics.BigInteger](Get-ReportUInt $Summary.end_qpc)-[System.Numerics.BigInteger](Get-ReportUInt $Summary.score_start_qpc)
        $limit=[System.Numerics.BigInteger][uint64]::MaxValue
        if(!$Frequency -or [System.Numerics.BigInteger]$Frequency -gt [System.Numerics.BigInteger]::Divide([int64]::MaxValue,45) -or
            $window -le 0 -or $window -ge $limit){throw 'Invalid model clock/window.'}
        $result.window_ticks=[string]$window
        $usable=$Assessment.available -and $Assessment.qualified -and
            $Calibration.ContainsKey('integrity_valid') -and $Calibration.integrity_valid -and $Calibration.qualified -and
            $Calibration.companion_sha256 -ceq $CompanionHash -and $Assessment.companion_sha256 -ceq $CompanionHash -and
            $Assessment.frequency -eq 10000000 -and $Assessment.class_coefficients.Count -eq 4 -and
            $Assessment.timing_calibration_sha256 -ceq $Calibration.calibration_sha256
        $lower=[System.Numerics.BigInteger]0;$upper=[System.Numerics.BigInteger]0;$missing=@()
        $counters=$Summary.scored_counters.timing.counters
        for($i=0;$i -lt 4;++$i){
            $calls=$counters['reporting.duration.'+$i+'.calls'];$own=$counters['reporting.duration.'+$i+'.elapsed_ticks']
            $n=[System.Numerics.BigInteger](Get-ReportUInt $calls.minimum);$count=[System.Numerics.BigInteger](Get-ReportUInt $calls.maximum)
            $lo=[System.Numerics.BigInteger](Get-ReportUInt $own.minimum);$hi=[System.Numerics.BigInteger](Get-ReportUInt $own.maximum)
            if($n -gt $count -or $lo -gt $hi -or ($count -eq 0 -and $hi -ne 0) -or
                [string]$n -cne $Summary.performance.classes[$i].calls_min -or [string]$count -cne $Summary.performance.classes[$i].calls_max){throw 'Inconsistent model envelopes.'}
            $charge=[System.Numerics.BigInteger]0;$eligible=$false
            if($usable){
                $coefficient=$Assessment.class_coefficients[$i]
                if($coefficient.class -ne $i -or $Calibration.class_floors[$i].class -ne $i){throw 'Model class order mismatch.'}
                $eligible=$coefficient.eligible -and $Calibration.class_floors[$i].eligible
                if($eligible){
                    $charge=[System.Numerics.BigInteger]::Divide([System.Numerics.BigInteger](Get-ReportUInt $coefficient.ticks)*$Frequency+9999999,10000000)
                    if($charge -ge $limit){throw 'Converted model allowance exceeds range.'}
                }
            }
            if($count -gt 0 -and !$eligible){$missing+=$i}
            $lower+=$lo+$n*$charge;$upper+=$hi+$count*$charge
            if($lower -ge $limit -or $upper -ge $limit){throw 'Projected model total exceeds range.'}
            $result.classes+=@{class=$i;calls_min=[string]$n;calls_max=[string]$count;own_min_ticks=[string]$lo;own_max_ticks=[string]$hi;
                coefficient_available=$eligible;runtime_coefficient_ticks=$(if($eligible){[string]$charge}else{$null})}
            if($i -eq 1){
                # Ratios are display context, never gates or inferred lane state.
                $result.management=@{gating=$false;native_lane='not-inferred';calls_min=[string]$n;calls_max=[string]$count;
                    own_min_ticks=[string]$lo;own_max_ticks=[string]$hi;window_ticks=[string]$window;
                    calls_per_second=@{lower_numerator=[string]($n*$Frequency);upper_numerator=[string]($count*$Frequency);denominator=[string]$window};
                    own_ms_per_second=@{lower_numerator=[string]($lo*1000);upper_numerator=[string]($hi*1000);denominator=[string]$window};
                    own_us_per_call=$(if($n -gt 0){@{lower_numerator=[string]($lo*1000000);lower_denominator=[string]($count*$Frequency);
                        upper_numerator=[string]($hi*1000000);upper_denominator=[string]($n*$Frequency)}}else{$null})}
            }
        }
        $result.missing_called_classes=$missing
        if(!$usable){$result.reason='assessment-or-calibration-unavailable';return $result}
        if($missing.Count){$result.reason='called-class-not-calibrated';return $result}
        $result.available=$true;$result.qualified=$true;$result.projected_low_ticks=[string]$lower;$result.projected_high_ticks=[string]$upper
        $result.state=if($upper*1000 -lt $window){'WITHIN_MODEL'}elseif($lower*1000 -ge $window){'ABOVE_MODEL'}else{'STRADDLES'}
        $result.reason='empirical-model-not-true-cost-bound'
    } catch {
        $result.available=$false;$result.qualified=$false;$result.state='UNAVAILABLE';$result.reason='model-numeric-or-envelope-invalid'
        $result.projected_low_ticks=$null;$result.projected_high_ticks=$null
    }
    return $result
}

function Complete-ReportTrialAssessment($Summary, $Model, $Assessment, [string]$Mode='', [switch]$Finalized) {
    $result=New-ReportTrialAssessment $Mode
    if($Summary.ContainsKey('local_performance')){$result.legacy_maximum_verdict=$Summary.local_performance}
    $result.model=$Model;$result.model_state=$Model.state;$result.latency_guard=$Model.latency_guard
    if($Assessment.available){
        $result.model_identity=@{}
        foreach($key in @('assessment_sha256','companion_sha256','timing_calibration_sha256','floor_ledger_sha256','source_inventory_sha256','model_provenance_sha256')){
            $result.model_identity[$key]=$Assessment[$key]
        }
    }
    if($Mode -ceq 'repair'){return $result}
    if($Mode -cne 'observe'){$result.reasons=@('mode-unknown');return $result}
    $failures=@()
    foreach($key in @('local_safety','local_coverage')){if($Summary.ContainsKey($key) -and $Summary[$key] -ceq 'FAIL'){$failures+=$key+'-fail'}}
    if($Summary.ContainsKey('performance') -and $Summary.performance.ContainsKey('measured') -and $Summary.performance.measured -ceq 'FAIL'){$failures+='measured-performance-fail'}
    if($Model.latency_guard -ceq 'FAIL'){$failures+='calibrated-latency-fail'}
    if($failures.Count){$result.verdict='NOT_SUPPORTED';$result.reasons=$failures;return $result}
    $missing=@()
    if(!$Finalized){$missing+='finalization-incomplete'}
    foreach($key in @('local_safety','local_coverage')){if(!$Summary.ContainsKey($key) -or $Summary[$key] -cne 'PASS'){$missing+=$key+'-incomplete'}}
    if(!$Summary.ContainsKey('final_safety') -or $Summary.final_safety -cne 'AVAILABLE'){$missing+='final-safety-unavailable'}
    if(!$Summary.ContainsKey('collection_stop') -or $null -ne $Summary.collection_stop){$missing+='collection-incomplete'}
    if(!$Summary.ContainsKey('performance') -or !$Summary.performance.ContainsKey('measured') -or $Summary.performance.measured -cne 'PASS'){$missing+='measured-performance-incomplete'}
    if(!$Model.available -or !$Model.qualified){$missing+=$Model.reason}
    if($Model.latency_guard -cne 'PASS'){$missing+='calibrated-latency-incomplete'}
    if($missing.Count){$result.reasons=$missing;return $result}
    switch -CaseSensitive ($Model.state){
        'WITHIN_MODEL' {$result.verdict='SUPPORTED_OBSERVE_ONLY';$result.reasons=@('empirical-observe-support-only')}
        'ABOVE_MODEL' {$result.verdict='NOT_SUPPORTED';$result.reasons=@('empirical-model-budget-above')}
        'STRADDLES' {$result.reasons=@('empirical-model-budget-straddles')}
        default {$result.reasons=@('empirical-model-unavailable')}
    }
    return $result
}

function Measure-ReportPerformance($Begin, $End, [uint64]$WindowTicks, [uint64]$Frequency, $Calibration, [string]$CompanionHash) {
    if (!$Begin.complete -or !$End.complete) { return @{ verdict='INCONCLUSIVE'; measured='INCONCLUSIVE'; reason='boundary-brackets-missing' } }
    $classes = @(); $totalUpper = [System.Numerics.BigInteger]0; $rawUpper = [System.Numerics.BigInteger]0
    $rawLower = [System.Numerics.BigInteger]0; $measured = 'PASS'; $calibrated = 'PASS'; $pooledVerdict='PASS'
    $pooledUpper=[System.Numerics.BigInteger]0;$legacyUpper=[System.Numerics.BigInteger]0
    $floorDataValid=$Calibration.ContainsKey('integrity_valid') -and $Calibration.integrity_valid -and
        $Calibration.companion_sha256 -ceq $CompanionHash -and $Calibration.frequency -gt 0
    $qualified = $Calibration.qualified -and $floorDataValid
    $available=$floorDataValid;$missingClasses=@();$floors=@();$pooled=@([System.Numerics.BigInteger]0,[System.Numerics.BigInteger]0)
    if ($floorDataValid) {
        if ($Calibration.class_floors.Count -ne 4) { throw 'Missing class-floor vector.' }
        $fixtureFrequency=[System.Numerics.BigInteger](Get-ReportUInt $Calibration.frequency)
        for($i=0;$i -lt 4;++$i) {
            $entry=$Calibration.class_floors[$i]
            if ($entry.class -ne $i) { throw 'Class-floor order mismatch.' }
            $converted=[System.Numerics.BigInteger]0
            if ($entry.eligible) {
                $missing=[System.Numerics.BigInteger](Get-ReportUInt $entry.floor_ticks)
                $converted=[System.Numerics.BigInteger]::Divide(($missing*[System.Numerics.BigInteger]$Frequency+$fixtureFrequency-1),$fixtureFrequency)
                $group=if($i -lt 2){0}else{1}
                if($converted -gt $pooled[$group]) { $pooled[$group]=$converted }
            }
            $floors+=@{eligible=$entry.eligible;ticks=$converted}
        }
    }
    for ($i=0;$i -lt 4;++$i) {
        $base = 'reporting.duration.' + $i
        $calls = Get-ReportEnvelope $Begin $End ($base + '.calls')
        $elapsed = Get-ReportEnvelope $Begin $End ($base + '.elapsed_ticks')
        $over = Get-ReportEnvelope $Begin $End ($base + '.over_five_ms')
        if ($over.maximum -gt $calls.maximum) { throw 'Overrun count exceeds calls.' }
        $verdict = 'PASS'; $withEpilogue = 'PASS'
        if ($calls.maximum -eq 0) {
            $verdict = if ($i -in 1,3) { 'INCONCLUSIVE' } else { 'UNOBSERVED' }
            $withEpilogue = $verdict
        } elseif ($i -lt 2) {
            if (100*$over.maximum -le $calls.minimum) { $verdict='PASS' }
            elseif (100*$over.minimum -gt $calls.maximum) { $verdict='FAIL' }
            else { $verdict='INCONCLUSIVE' }
        } else {
            if ($over.maximum -eq 0) { $verdict='PASS' }
            elseif ($over.minimum -gt 0) { $verdict='FAIL' }
            else { $verdict='INCONCLUSIVE' }
        }
        if ($calls.maximum -gt 0 -and $calls.minimum -eq 0 -and $verdict -ceq 'PASS') { $verdict='INCONCLUSIVE' }
        $epilogue = [System.Numerics.BigInteger]0;$poolCharge=[System.Numerics.BigInteger]0;$pooledClass=$withEpilogue
        $classEligible=$floorDataValid -and $floors[$i].eligible
        if ($classEligible -and $calls.maximum -gt 0) {
            $epilogue=$floors[$i].ticks;$group=if($i -lt 2){0}else{1};$poolCharge=$pooled[$group]
            $cumulativeMax = [System.Numerics.BigInteger](Get-ReportScalar $End.after.fields ($base + '.maximum_ticks'))
            # Cumulative maxima cannot be subtracted. Use them only as an upper
            # bound; a pre-window outlier is never called a window failure.
            if (($cumulativeMax+$epilogue)*1000 -le 5*[System.Numerics.BigInteger]$Frequency) { $withEpilogue=$verdict }
            elseif ($epilogue -eq 0) { $withEpilogue=$verdict }
            else { $withEpilogue = if ($verdict -ceq 'FAIL') { 'FAIL' } else { 'INCONCLUSIVE' } }
            $pooledClass=$verdict
            if ($poolCharge -ne 0 -and ($cumulativeMax+$poolCharge)*1000 -gt 5*[System.Numerics.BigInteger]$Frequency -and $verdict -cne 'FAIL') {
                $pooledClass='INCONCLUSIVE'
            }
        } elseif ($calls.maximum -gt 0) {
            # A zero lower bound is not proof of no calls. Do not borrow another
            # class's floor, even for the pooled sensitivity diagnostic.
            $available=$false;$missingClasses+=$i;$withEpilogue='INCONCLUSIVE';$pooledClass='INCONCLUSIVE'
        } elseif (!$floorDataValid) { $withEpilogue='INCONCLUSIVE';$pooledClass='INCONCLUSIVE' }
        $totalUpper += $elapsed.maximum + $calls.maximum*$epilogue
        $pooledUpper += $elapsed.maximum + $calls.maximum*$poolCharge
        $legacyFloor=[System.Numerics.BigInteger]$(if($i -lt 2){1259}else{180})
        $legacyTicks=[System.Numerics.BigInteger]::Divide(($legacyFloor*[System.Numerics.BigInteger]$Frequency+9999999),10000000)
        $legacyUpper += $elapsed.maximum + $calls.maximum*$legacyTicks
        $rawUpper += $elapsed.maximum; $rawLower += $elapsed.minimum
        if ($verdict -ceq 'FAIL') { $measured='FAIL' } elseif ($verdict -ceq 'INCONCLUSIVE' -and $measured -cne 'FAIL') { $measured='INCONCLUSIVE' }
        if ($withEpilogue -ceq 'FAIL') { $calibrated='FAIL' } elseif ($withEpilogue -ceq 'INCONCLUSIVE' -and $calibrated -cne 'FAIL') { $calibrated='INCONCLUSIVE' }
        if ($pooledClass -ceq 'FAIL') { $pooledVerdict='FAIL' } elseif ($pooledClass -ceq 'INCONCLUSIVE' -and $pooledVerdict -cne 'FAIL') { $pooledVerdict='INCONCLUSIVE' }
        $classes += @{ class=$i; calls_min=[string]$calls.minimum; calls_max=[string]$calls.maximum;
            elapsed_max=[string]$elapsed.maximum; over_five_min=[string]$over.minimum; over_five_max=[string]$over.maximum;
            measured=$verdict; with_epilogue=$withEpilogue; calibration_eligible=$classEligible;
            epilogue_ticks_per_call=$(if($classEligible){[string]$epilogue}else{$null});
            pooled_ticks_per_call=$(if($classEligible){[string]$poolCharge}else{$null}) }
    }
    $sumPass = $available -and $totalUpper*1000 -lt [System.Numerics.BigInteger]$WindowTicks
    $pooledSumPass=$available -and $pooledUpper*1000 -lt [System.Numerics.BigInteger]$WindowTicks
    if ($rawLower*1000 -ge [System.Numerics.BigInteger]$WindowTicks) { $measured='FAIL'; $calibrated='FAIL';$pooledVerdict='FAIL' }
    elseif (!$sumPass -and $calibrated -ceq 'PASS') { $calibrated='INCONCLUSIVE' }
    if (!$pooledSumPass -and $pooledVerdict -ceq 'PASS') { $pooledVerdict='INCONCLUSIVE' }
    if ($rawUpper*1000 -ge [System.Numerics.BigInteger]$WindowTicks -and $measured -ceq 'PASS') { $measured='INCONCLUSIVE' }
    if ($measured -ceq 'FAIL') { $calibrated='FAIL';$pooledVerdict='FAIL' }
    # Coverage failures do not erase integrity-valid maxima or their arithmetic,
    # but those diagnostics cannot qualify a candidate. Raw failure wins.
    if (!$qualified -and $calibrated -cne 'FAIL') { $calibrated='INCONCLUSIVE' }
    if (!$qualified -and $pooledVerdict -cne 'FAIL') { $pooledVerdict='INCONCLUSIVE' }
    return @{ verdict=$calibrated; measured=$measured; classes=$classes;
        measurement_id='rs2-wrapper-own-deferred-v2';raw_lower_ticks=[string]$rawLower;raw_upper_ticks=[string]$rawUpper;
        summed_upper_ticks=$(if($available){[string]$totalUpper}else{$null});
        whole_window_ticks=[string]$WindowTicks; summed_upper_below_one_ms_per_second=$sumPass;
        epilogue_qualified=($available -and $qualified); bound_available=$available;diagnostic_only=(!$qualified);
        epilogue_constraint=$Calibration.reason; missing_called_classes=$missingClasses;
        pooled_sensitivity=@{available=$available;verdict=$pooledVerdict;same_floor_vector=$true;
            diagnostic_only=(!$qualified);
            summed_upper_ticks=$(if($available){[string]$pooledUpper}else{$null});
            summed_upper_below_one_ms_per_second=$pooledSumPass;
            split_only_reduction_ticks=$(if($available){[string]($pooledUpper-$totalUpper)}else{$null})};
        pass_depends_on_class_split=($calibrated -ceq 'PASS' -and $pooledVerdict -cne 'PASS');
        legacy_stress=@{qualification_gate=$false;frequency='10000000';pump_floor_ticks='1259';builder_floor_ticks='180';
            summed_upper_ticks=[string]$legacyUpper;below_one_ms_per_second=($legacyUpper*1000 -lt [System.Numerics.BigInteger]$WindowTicks);
            limitation='historical-v1-stress-may-double-charge-newly-measured-work'};
        attribution=@{entry_and_deferred_accounting='expected-to-include-previously-omitted-work';
            raw_measured_direction_all_else_equal='increase';causal_ticks_versus_r6='unknown';
            vm_activity_run_difference='unquantified';class_split='same-run-allowance-specificity-not-speedup';historical_results='not-regraded'};
        maxima_policy='never-subtracted';
        limitation='wrapper-own-only-not-added-native-producer-or-total-server-load' }
}

function Measure-ReportWindow($Snapshots, $Log, [uint64]$StartQpc, [uint64]$Frequency, [string]$Mode, $Calibration, [string]$CompanionHash) {
    $start = [System.Numerics.BigInteger]$StartQpc
    $score = $start + $(if ($Mode -ceq 'repair') { 120*[System.Numerics.BigInteger]$Frequency } else { 0 })
    $finish = $start+300*[System.Numerics.BigInteger]$Frequency
    if ($finish -ge [uint64]::MaxValue) { throw 'Qualification window QPC overflow.' }
    $a = Find-ReportBoundary $Snapshots ([uint64]$score); $b = Find-ReportBoundary $Snapshots ([uint64]$finish)
    $timingA=Find-ReportBoundary $Snapshots ([uint64]$score) 'timing'
    $timingB=Find-ReportBoundary $Snapshots ([uint64]$finish) 'timing'
    $result = @{ local_safety='PASS'; local_coverage='INCONCLUSIVE'; local_performance='INCONCLUSIVE';
        operator_smoke='UNVERIFIED'; backend_client_effect='UNVERIFIED'; outage_recovery='UNVERIFIED';
        mode=$Mode; start_qpc=[string]$start; score_start_qpc=[string]$score; end_qpc=[string]$finish;
        warmup_seconds=$(if ($Mode -ceq 'repair') {120}else{0}); score_seconds=$(if ($Mode -ceq 'repair') {180}else{300});
        reason='boundary-brackets-missing'; boundaries=@{coverage=@();timing=@()}; no_automatic_promotion=$true }
    $result.native_scheduler=@{scope='scored-window';observations=@();next_eligibility='unknown';backoff_coverage_exemption=$false}
    if($Log.ContainsKey('scheduler_samples')) { $result.native_scheduler.observations=@($Log.scheduler_samples) }
    foreach ($boundary in @($a,$b,$timingA,$timingB)) {
        $rangeKey=$boundary.family+'_range'
        $result.boundaries[$boundary.family] += @{ target=[string]$boundary.target; complete=$boundary.complete;
            range_family=$rangeKey;
            before=$(if ($null -ne $boundary.before) {$boundary.before[$rangeKey]}else{$null});
            after=$(if ($null -ne $boundary.after) {$boundary.after[$rangeKey]}else{$null}) }
    }
    # Preserve the complete denominator/skip history, including repair warmup.
    # Nothing is inferred from a few successful builder records alone.
    $result.scored_counters=@{coverage=@{range_family='coverage_range';complete=($a.complete -and $b.complete)};
        timing=@{range_family='timing_range';complete=($timingA.complete -and $timingB.complete)}}
    if ($a.complete -and $b.complete) { $result.scored_counters.coverage.counters=Get-ReportWindowCounters $a $b 'coverage' }
    if ($timingA.complete -and $timingB.complete) { $result.scored_counters.timing.counters=Get-ReportWindowCounters $timingA $timingB 'timing' }
    if ($Mode -ceq 'repair') {
        $warm=Find-ReportBoundary $Snapshots $StartQpc
        $warmTiming=Find-ReportBoundary $Snapshots $StartQpc 'timing'
        $result.warmup=@{complete=($warm.complete -and $a.complete -and $warmTiming.complete -and $timingA.complete);
            start_qpc=[string]$start;end_qpc=[string]$score;
            coverage=@{range_family='coverage_range';complete=($warm.complete -and $a.complete)};
            timing=@{range_family='timing_range';complete=($warmTiming.complete -and $timingA.complete)}}
        if ($warm.complete -and $a.complete) { $result.warmup.coverage.counters=Get-ReportWindowCounters $warm $a 'coverage' }
        if ($warmTiming.complete -and $timingA.complete) { $result.warmup.timing.counters=Get-ReportWindowCounters $warmTiming $timingA 'timing' }
    }
    foreach ($snapshot in $Snapshots) {
        $f=$snapshot.fields
        if (!$f.ContainsKey('reporting.revoke_reasons')) { $result.reason='status-unavailable'; return $result }
        if ((Get-ReportScalar $f 'reporting.revoke_reasons') -ne 0 -or (Get-ReportScalar $f 'reporting.loss_reasons') -ne 0) {
            $result.local_safety='FAIL'; $result.reason='sticky-loss-or-revocation'; return $result
        }
        if ((Get-ReportScalar $f 'reporting.stopping') -ne 0) { $result.reason='planned-or-observed-stop'; return $result }
    }
    if (!$a.complete -or !$b.complete) { return $result }
    if ($Log.source_changes) { $result.reason='source-or-binding-epoch-change'; return $result }
    if (!$Log.ContainsKey('epoch_baseline_available') -or !$Log.epoch_baseline_available) {
        $result.reason='pre-window-epoch-baseline-unavailable'; return $result
    }
    if ($Mode -ceq 'repair' -and $Log.population_samples -gt 0 -and !$Log.human_observed) { $result.reason='observed-no-human-test-population'; return $result }
    $attempts = Get-ReportEnvelope $a $b 'reporting.normalAttempts'
    $selected = Get-ReportEnvelope $a $b 'reporting.selectedTrue'
    $pump = Get-ReportEnvelope $a $b 'reporting.normalPumpClassifications'
    $result.attempts_min=[string]$attempts.minimum; $result.attempts_max=[string]$attempts.maximum
    $result.selected_true_min=[string]$selected.minimum; $result.selected_true_max=[string]$selected.maximum
    $pairs = @($Log.pairs | Where-Object { !$_.unwind -and $_.entry -ge $score -and $_.returned -lt $finish })
    $witnesses = New-Object 'Collections.Generic.HashSet[string]'
    $pairedSelected=0
    foreach ($pair in $pairs) { if ($pair.selected -eq 1 -and $pair.result -eq 1) { ++$pairedSelected; $null=$witnesses.Add([string]$pair.witness) } }
    $result.paired_returns=$pairs.Count; $result.paired_selected_true=$pairedSelected; $result.selected_witnesses=$witnesses.Count
    if ($Mode -ceq 'observe') {
        if ($Log.window_requests -or $Log.window_selections -or
            (Get-ReportEnvelope $a $b 'reporting.requestSequence').maximum -gt 0 -or
            (Get-ReportEnvelope $a $b 'reporting.witnessSequence').maximum -gt 0 -or
            (Get-ReportEnvelope $a $b 'reporting.fullSelected').maximum -gt 0) {
            $result.local_safety='FAIL'; $result.reason='observe-mutated-or-staged'; return $result
        }
        # A classified call proves reachability only if the entire prepared
        # schema was validated. Reason 48 specifically permits stable, supported
        # metadata with stale numbers; unavailable/malformed/limit failures do not.
        $qualifiedPairs=@($pairs | Where-Object { $_.entry_reason -in 0,48 -and $_.return_reason -in 0,48 })
        $bypasses=@{}
        foreach($pair in $pairs) {
            if($pair.entry_reason -notin 0,48 -or $pair.return_reason -notin 0,48) {
                $key=[string]$pair.entry_reason+':'+[string]$pair.return_reason
                if(!$bypasses.ContainsKey($key)){$bypasses[$key]=0};++$bypasses[$key]
            }
        }
        $result.observe_qualifying_pairs=$qualifiedPairs.Count
        $result.observe_bypassed_pairs=$pairs.Count-$qualifiedPairs.Count
        $result.observe_bypass_reasons=$bypasses
        $unsupported=@($pairs | Where-Object { $_.entry_reason -in 45,46,47 -or $_.return_reason -in 45,46,47 })
        $unsupportedMinimum=[System.Numerics.BigInteger]0;$unsupportedMaximum=[System.Numerics.BigInteger]0
        foreach($reason in @(45,46,47)) {
            $range=Get-ReportEnvelope $a $b ('reporting.reason_count.'+$reason)
            $unsupportedMinimum+=$range.minimum;$unsupportedMaximum+=$range.maximum
        }
        $result.observe_unsupported_pairs=$unsupported.Count
        $result.observe_unsupported_bypasses_min=[string]$unsupportedMinimum
        $result.observe_unsupported_bypasses_max=[string]$unsupportedMaximum
        $span = if ($qualifiedPairs.Count -ge 2) { [System.Numerics.BigInteger]$qualifiedPairs[-1].returned - $qualifiedPairs[0].entry } else { [System.Numerics.BigInteger]0 }
        if($unsupported.Count -gt 0 -or $unsupportedMinimum -gt 0) {
            $result.local_coverage='FAIL';$result.reason='observe-unsupported-prepared-schema'
        } elseif($unsupportedMaximum -gt 0) {
            $result.reason='observe-prepared-rejection-boundary-uncertainty'
        } elseif ($qualifiedPairs.Count -ge 3 -and $span -ge 60*[System.Numerics.BigInteger]$Frequency -and $pump.minimum -gt 0) {
            $result.local_coverage='PASS'; $result.reason='observe-local-reachability'
        } else { $result.reason='observe-coverage-insufficient' }
    } else {
        if ($attempts.minimum -ge 4 -and $selected.minimum -ge 3 -and 4*$selected.minimum -ge 3*$attempts.maximum -and
            $pairedSelected -ge 3 -and 4*[System.Numerics.BigInteger]$pairedSelected -ge 3*$attempts.maximum -and $witnesses.Count -ge 2 -and $pump.minimum -gt 0) {
            $result.local_coverage='PASS'; $result.reason='repair-local-coverage'
        } elseif ($attempts.maximum -lt 4 -or $selected.maximum -lt 3 -or 4*$selected.maximum -lt 3*$attempts.minimum) {
            $result.local_coverage='FAIL'; $result.reason='healthy-repair-coverage-insufficient'
        } else { $result.reason='boundary-uncertainty-or-witness-coverage-insufficient' }
    }
    $result.performance=Measure-ReportPerformance $timingA $timingB ([uint64]($finish-$score)) $Frequency $Calibration $CompanionHash
    $result.local_performance=$result.performance.verdict
    return $result
}

function Get-ReportWindowCounters($Begin, $End, [ValidateSet('coverage','timing')][string]$Family) {
    $out=@{}
    $keys=@()
    if ($Family -ceq 'coverage') {
        $keys=@('normalAttempts','fullSelected','selectedTrue','normalReturns','falseReturns','nativeUnwinds','managementCalls',
        'normalPumpClassifications','normalBuilderClassifications','requestSequence','witnessSequence','buildSequence','distinctSelectedWitnesses') |
        ForEach-Object { 'reporting.'+$_ }
        for ($i=0;$i -lt 64;++$i) { $keys+='reporting.reason_count.'+$i }
    } else {
        for ($i=0;$i -lt 4;++$i) {
            foreach ($suffix in @('calls','elapsed_ticks','over_five_ms')) { $keys+='reporting.duration.'+$i+'.'+$suffix }
            for ($bucket=0;$bucket -lt 6;++$bucket) { $keys+='reporting.duration.'+$i+'.bucket.'+$bucket }
        }
    }
    foreach ($key in $keys) { $value=Get-ReportEnvelope $Begin $End $key; $out[$key]=@{minimum=[string]$value.minimum;maximum=[string]$value.maximum} }
    return $out
}

function Assert-ReportCounterProgress($Earlier, $Later) {
    $keys=@('normalAttempts','fullSelected','selectedTrue','normalReturns','falseReturns','nativeUnwinds','managementCalls',
        'normalPumpClassifications','normalBuilderClassifications','requestSequence','witnessSequence','buildSequence',
        'reportSequence','distinctSelectedWitnesses') | ForEach-Object { 'reporting.' + $_ }
    for ($i=0;$i -lt 64;++$i) { $keys += 'reporting.reason_count.' + $i }
    for ($i=0;$i -lt 4;++$i) {
        foreach ($suffix in @('calls','elapsed_ticks','maximum_ticks','over_five_ms')) { $keys += 'reporting.duration.' + $i + '.' + $suffix }
        for ($n=0;$n -lt 6;++$n) { $keys += 'reporting.duration.' + $i + '.bucket.' + $n }
    }
    foreach ($key in $keys) { $null=Get-ReportDifference $Later $Earlier $key }
    $null=Get-ReportDifference $Later $Earlier 'reporting.timingAccountedThroughQpc'
}

function Assert-ReportPrefix([string]$Before, [string]$After) {
    [RS2ReportCollection.Files]::VerifyPrefix($Before,$After)
}

function Read-ReportMarker([string]$Path, [string]$Executable, [uint32]$SelectedId, [uint64]$Created, $Locks) {
    $plain=Resolve-ReportPlain $Path $false
    if (![IO.Path]::GetFileName($plain).Equals("RS2ServerFix.loader.$SelectedId.log",[StringComparison]::OrdinalIgnoreCase)) { throw 'Loader marker PID filename mismatch.' }
    $stream=[RS2ReportCollection.Files]::Open($plain,$false); $Locks.Add($stream)
    $text=Read-ReportText $stream 8192; $fields=Read-ReportFields $text
    $required=@{schema='3';version='0.4.2.0';pid=[string]$SelectedId;executable=[IO.Path]::GetFileName($Executable);
        executable_size=[string](Get-Item -LiteralPath $Executable).Length;sha256=$script:ReportHostHash;build_identity='current-full-dump';
        bootstrap='X3DAudio1_7.dll';bootstrap_beside_executable='true';companion='RS2ServerFix.dll';companion_beside_executable='true';
        genuine_module='system32';genuine_initialize_present='true';genuine_calculate_present='true';trigger='exe-crt-initialize';
        mode='active';fix='recon-exclusive-scale-v1';qualification='ready';recon='active';reason='none';initialize_result='0';completion='complete'}
    Assert-ReportFields $fields $required
    if ($fields.Count -ne $required.Count+2 -or !$fields.ContainsKey('utc') -or !$fields.ContainsKey('primary_write_error')) { throw 'Unexpected loader marker fields.' }
    $primary=[IO.Path]::GetDirectoryName($plain).Equals([IO.Path]::GetDirectoryName($Executable),[StringComparison]::OrdinalIgnoreCase)
    $errorCode=Get-ReportScalar $fields 'primary_write_error'
    if ($errorCode -gt [uint32]::MaxValue -or $primary -ne ($errorCode -eq 0)) { throw 'Marker fallback/primary state mismatch.' }
    $time=[DateTime]::ParseExact($fields['utc'],"yyyy-MM-dd'T'HH:mm:ss.fff'Z'",[Globalization.CultureInfo]::InvariantCulture,
        ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal))
    if ($time -lt [DateTime]::FromFileTimeUtc([long]$Created) -or $time -gt [DateTime]::UtcNow) { throw 'Stale loader marker.' }
    return $text
}

function Get-ReportCollectorQpc { return [uint64][Diagnostics.Stopwatch]::GetTimestamp() }

function Get-ReportPollingStop($Budget, [uint64]$ObservedQpc, [int]$Attempts) {
    if ($Attempts -ge 72) { return 'measurement-attempt-limit' }
    $now=Get-ReportCollectorQpc
    if ($now -lt $Budget.collector_start) { return 'collector-clock-regressed' }
    if ([System.Numerics.BigInteger]$now -ge $Budget.collector_deadline -or
        [System.Numerics.BigInteger]$ObservedQpc -ge $Budget.observed_deadline) { return 'boundary-catch-up-deadline' }
    return $null
}

function Test-ReportOperatorAbort {
    if (![Console]::IsInputRedirected -and [Console]::KeyAvailable) {
        return [Console]::ReadKey($true).Key -eq [ConsoleKey]::Q
    }
    return $false
}

function Invoke-SteamReportCollection {
    Initialize-ReportFileReader
    if (![Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell.' }
    $locks=New-Object 'Collections.Generic.List[IO.FileStream]'; $resultDirectory=$null; $eventStream=$null
    $first=$null;$final=$null;$snapshots=$null
    try {
        if (!$ProcessId) { $entered=Read-Host 'PID of the already running reporting-enabled server';
            if ($entered -cnotmatch '^[1-9][0-9]{0,9}$' -or ![uint32]::TryParse($entered,[ref]$ProcessId)) { throw 'Invalid selected PID.' } }
        if (!$TargetRoot) { $TargetRoot=Read-Host 'Full server root directory' }
        $server=Resolve-ReportPlain $TargetRoot $true
        $package=Resolve-ReportPlain ([IO.Path]::GetDirectoryName($PSScriptRoot)) $true
        if ((Test-ReportWithin $server $package) -or (Test-ReportWithin $package $server)) { throw 'Package must be outside server tree.' }
        $verified=Read-ReportPackage $package $locks
        if (!$ReportRoot) { $ReportRoot=Join-Path ([IO.Path]::GetDirectoryName($package)) 'reports' }
        if (!(Test-Path -LiteralPath $ReportRoot)) {
            $parent=Resolve-ReportPlain ([IO.Path]::GetDirectoryName($ReportRoot)) $true; $leaf=[IO.Path]::GetFileName($ReportRoot)
            if ($leaf -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') { throw 'Invalid evidence folder leaf.' }
            $candidate=Join-Path $parent $leaf
            if ((Test-ReportWithin $server $candidate) -or (Test-ReportWithin $package $candidate)) { throw 'Evidence must be outside server/package.' }
            $null=[IO.Directory]::CreateDirectory($candidate)
        }
        $reportBase=Resolve-ReportPlain $ReportRoot $true
        if ((Test-ReportWithin $server $reportBase) -or (Test-ReportWithin $package $reportBase)) { throw 'Evidence must be outside server/package.' }
        $resultDirectory=Join-Path $reportBase ('SteamReport-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+[Guid]::NewGuid().ToString('N'))
        if (Test-Path -LiteralPath $resultDirectory) { throw 'Evidence output collision.' }
        $null=[IO.Directory]::CreateDirectory($resultDirectory); Write-Host "Evidence folder: $resultDirectory"
        $first=Invoke-ReportInventory $package $verified.Files $server $ProcessId (Join-Path $resultDirectory 'inventory-0000.txt')
        if (!(Test-ReportReady $first)) {
            $diagnostic=@{ status_file='inventory-0000.txt'; status_first=$true; log_requested=$false;
                local_safety='UNVERIFIED';local_coverage='INCONCLUSIVE';local_performance='INCONCLUSIVE';
                trial_assessment=(New-ReportTrialAssessment);
                operator_smoke='UNVERIFIED';backend_client_effect='UNVERIFIED';outage_recovery='UNVERIFIED';
                reason='initial-current-status-not-ready';package_manifest_sha256=$verified.ManifestHash;private_keys_collected=$false }
            if ($first.fields.ContainsKey('reporting.loss_reasons') -and
                ((Get-ReportScalar $first.fields 'reporting.loss_reasons') -ne 0 -or (Get-ReportScalar $first.fields 'reporting.revoke_reasons') -ne 0)) { $diagnostic.local_safety='FAIL' }
            Save-ReportText (Join-Path $resultDirectory 'collection.json') (($diagnostic|ConvertTo-Json -Depth 8)+"`r`n")
            Write-Host 'Preserved current rejection/not-ready evidence. No log path or private keys required.'; return
        }
        $collectorStart=Get-ReportCollectorQpc
        $ranges=Assert-ReportSnapshot $first $first
        $first.coverage_range=$ranges.coverage_range;$first.timing_range=$ranges.timing_range
        $modeNumber=Get-ReportScalar $first.fields 'reporting.mode'
        if ($modeNumber -notin 2,3) { throw 'Ready status has unsupported configured mode.' }
        $mode=if ($modeNumber -eq 2) {'observe'}else{'repair'}
        $frequency=Get-ReportScalar $first.fields 'reporting.qpc_frequency'
        $start=Get-ReportScalar $first.fields 'reporting.observed_qpc'
        $finishBig=[System.Numerics.BigInteger]$start+300*[System.Numerics.BigInteger]$frequency
        if ($finishBig -ge [uint64]::MaxValue) { throw 'Window QPC overflow.' }; $finish=[uint64]$finishBig
        $budget=@{collector_start=$collectorStart;
            collector_deadline=([System.Numerics.BigInteger]$collectorStart+330*[System.Numerics.BigInteger]$frequency);
            observed_deadline=($finishBig+30*[System.Numerics.BigInteger]$frequency)}
        $score=[uint64]([System.Numerics.BigInteger]$start+$(if($mode -ceq 'repair'){120*[System.Numerics.BigInteger]$frequency}else{0}))
        $executable=Resolve-ReportPlain ([Uri]::UnescapeDataString($first.fields['process_image_path']).Replace('/','\')) $false
        $exeDirectory=[IO.Path]::GetDirectoryName($executable); $configuration=@{}
        foreach ($name in @('RS2SteamObserve.ini','RS2SteamReport.ini')) {
            $path=Resolve-ReportPlain (Join-Path $exeDirectory $name) $false
            $stream=[RS2ReportCollection.Files]::Open($path,$false); $locks.Add($stream)
            $text=Read-ReportText $stream 4096; $parsed=Read-ReportConfiguration $text ($name -ceq 'RS2SteamReport.ini')
            $configuration[$name]=@{parsed=$parsed;sha256=(Get-ReportHash $stream);stream=$stream;
                package_template_sha256=$verified.Files['config/'+$name]}
            Save-ReportText (Join-Path $resultDirectory $name) $text
        }
        if ($configuration['RS2SteamReport.ini'].parsed.mode -cne $mode) { throw 'Installed configuration mode differs from immutable status.' }
        $quotaBytes=[uint64]$configuration['RS2SteamObserve.ini'].parsed.quota_mib*1MB
        $reportParent=Resolve-ReportPlain (Join-Path $exeDirectory 'RS2SteamReport') $true
        if (!$ReportingRunDirectory) {
            # One known reporting directory, not a recursive server scan. Never
            # enumerate the separate legacy observer/key tree.
            $children=@(Get-ChildItem -LiteralPath $reportParent -Directory -Force | Select-Object -First 1025)
            if ($children.Count -gt 1024) { throw 'Reporting run directory bound exceeded; supply the exact path.' }
            $suffix='-PID'+$ProcessId+'-'+$first.fields['reporting.run_id']
            $matches=@($children|Where-Object { $_.Name.EndsWith($suffix,[StringComparison]::Ordinal) })
            if ($matches.Count -ne 1) { throw 'Cannot uniquely locate the DATA-bound reporting run; supply its exact directory.' }
            $ReportingRunDirectory=$matches[0].FullName
        }
        $run=Resolve-ReportPlain $ReportingRunDirectory $true
        if (![IO.Path]::GetDirectoryName($run).Equals($reportParent,[StringComparison]::OrdinalIgnoreCase)) { throw 'Reporting run is not beside this EXE.' }
        if (!$MarkerPath) { $MarkerPath=Join-Path $exeDirectory "RS2ServerFix.loader.$ProcessId.log" }
        $marker=Read-ReportMarker $MarkerPath $executable $ProcessId (Get-ReportScalar $first.fields 'process_creation_filetime') $locks
        Save-ReportText (Join-Path $resultDirectory 'startup-marker.log') $marker
        $events=Resolve-ReportPlain (Join-Path $run 'events.jsonl') $false
        $eventStream=[RS2ReportCollection.Files]::Open($events,$true)
        $prefixBefore=[RS2ReportCollection.Files]::CopyPrefix($eventStream,$events,(Join-Path $resultDirectory 'events-before.jsonl'))
        $snapshots=New-Object 'Collections.Generic.List[object]'; $snapshots.Add($first)
        $previous=$first; $interruption=$null; $index=0; $completed=$false; $observed=$start
        Write-Host "Collecting fixed $mode window: 300 seconds plus at most 30 seconds boundary catch-up; Q stops without qualification."
        while ($true) {
            $interruption=Get-ReportPollingStop $budget $observed $index
            if ($null -ne $interruption) { break }
            if (Test-ReportOperatorAbort) { $interruption='operator-aborted';break }
            ++$index
            $next=Invoke-ReportInventory $package $verified.Files $server $ProcessId (Join-Path $resultDirectory ('inventory-{0:D4}.txt' -f $index))
            $snapshots.Add($next)
            if (!(Test-ReportReady $next)) { $interruption='current-readiness-lost'; break }
            $ranges=Assert-ReportSnapshot $next $first
            $next.coverage_range=$ranges.coverage_range;$next.timing_range=$ranges.timing_range
            Assert-ReportCounterProgress $previous $next
            $previous=$next
            $observed=$next.coverage_range.upper
            $interruption=Get-ReportPollingStop $budget $observed $index
            if ($null -ne $interruption) { break }
            if (Test-ReportOperatorAbort) { $interruption='operator-aborted';break }
            $coverageEnd=Find-ReportBoundary $snapshots.ToArray() $finish 'coverage'
            $timingEnd=Find-ReportBoundary $snapshots.ToArray() $finish 'timing'
            if ($coverageEnd.complete -and $timingEnd.complete) { $completed=$true;break }
            # Native inventory latency remains part of each saved bracket. No
            # shifting of start/score/end targets to make the counters pass.
            Write-Host ('Mode {0}; samples {1}; observed seconds {2}; completed timing QPC {3}; target {4}.' -f $mode,$snapshots.Count,
                (([System.Numerics.BigInteger]$observed-$start)/$frequency),$next.fields['reporting.timingAccountedThroughQpc'],$finish)
            $interruption=Get-ReportPollingStop $budget $observed $index
            if ($null -ne $interruption) { break }
            Start-Sleep -Seconds 5
        }
        # A stopped/expired collection retains its prefixes but never invokes a
        # new helper merely to manufacture final safety evidence.
        if ($completed -and $null -eq (Get-ReportPollingStop $budget $observed $index)) {
            Start-Sleep -Seconds 1 # Ordinary writer progress only.
        }
        $prefixAfter=[RS2ReportCollection.Files]::CopyPrefix($eventStream,$events,(Join-Path $resultDirectory 'events-after.jsonl'))
        Assert-ReportPrefix (Join-Path $resultDirectory 'events-before.jsonl') (Join-Path $resultDirectory 'events-after.jsonl')
        $final=$null; $finalSafety='UNAVAILABLE'
        if ($completed) {
            $interruption=Get-ReportPollingStop $budget $observed $index
            if (Test-ReportOperatorAbort) { $interruption='operator-aborted' }
            if ($null -eq $interruption) {
                $final=Invoke-ReportInventory $package $verified.Files $server $ProcessId (Join-Path $resultDirectory 'inventory-final.txt')
                if (Test-ReportReady $final) {
                    $ranges=Assert-ReportSnapshot $final $first
                    $final.coverage_range=$ranges.coverage_range;$final.timing_range=$ranges.timing_range
                    Assert-ReportCounterProgress $previous $final
                    $finalSafety='AVAILABLE'
                    $interruption=Get-ReportPollingStop $budget $final.coverage_range.upper $index
                } else { $interruption='final-current-readiness-lost';$finalSafety='INCOMPLETE' }
            }
        }
        # Final read is safety verification, NOT a replacement measurement boundary.
        # Windows PowerShell 5.1 cannot reliably array-wrap Generic.List[object].
        $all=$snapshots.ToArray()
        if ($null -ne $final) { $all+=@($final) }
        $log=Read-ReportLog (Join-Path $resultDirectory 'events-after.jsonl') $first.fields $run $quotaBytes $score $finish $all
        $calibration=Read-ReportTimingCalibration $verified.Files $package
        $assessment=Read-ReportPerformanceAssessment $verified.Files $package $calibration
        $summary=Measure-ReportWindow ($snapshots.ToArray()) $log $start $frequency $mode $calibration $verified.Files['dlls/RS2ServerFix.dll']
        $sustained=Measure-ReportSustainedModel $summary $frequency $calibration $assessment $verified.Files['dlls/RS2ServerFix.dll']
        foreach ($s in $all) {
            if ($s.fields.ContainsKey('reporting.loss_reasons') -and ((Get-ReportScalar $s.fields 'reporting.loss_reasons') -ne 0 -or
                (Get-ReportScalar $s.fields 'reporting.revoke_reasons') -ne 0)) { $summary.local_safety='FAIL'; $summary.reason='sticky-loss-or-revocation' }
        }
        if ($finalSafety -cne 'AVAILABLE' -and $summary.local_safety -cne 'FAIL') { $summary.local_safety='UNVERIFIED' }
        $summary.final_safety=$finalSafety
        $summary.measurement_attempts=$index
        $summary.collection_stop=$interruption
        $summary.collection_limits=@{measurement_attempts=72;catch_up_seconds=30;
            collector_start_qpc=[string]$collectorStart;collector_deadline_qpc=[string]$budget.collector_deadline;
            observed_deadline_qpc=[string]$budget.observed_deadline;in_flight_helper_timeout=$false}
        $requiredWatermark=Get-ReportScalar $previous.fields 'reporting.reportSequence'
        if ($log.last_sequence -lt $requiredWatermark -or $prefixAfter.PartialTail -or $null -eq $log.latest_anchor) {
            $summary.local_coverage='INCONCLUSIVE'
            if ($summary.local_safety -cne 'FAIL') { $summary.reason='incomplete-required-log-prefix' }
        }
        if ($null -ne $interruption -and $summary.local_safety -cne 'FAIL') { $summary.local_coverage='INCONCLUSIVE'; $summary.reason=$interruption }
        $summary.overall_qualified=$finalSafety -ceq 'AVAILABLE' -and $null -eq $interruption -and
            $summary.local_safety -ceq 'PASS' -and $summary.local_coverage -ceq 'PASS' -and $summary.local_performance -ceq 'PASS'
        foreach ($name in $configuration.Keys) {
            $configuration[$name].after_sha256=Get-ReportHash $configuration[$name].stream
            if ($configuration[$name].after_sha256 -cne $configuration[$name].sha256) { throw 'Held configuration changed.' }
            $configuration[$name].Remove('stream')
        }
        $summary.configurations=$configuration; $summary.package_manifest_sha256=$verified.ManifestHash
        $summary.run_id=$first.fields['reporting.run_id']; $summary.pid=$ProcessId
        $summary.process_creation=$first.fields['process_creation_filetime']; $summary.prefix_before=$prefixBefore; $summary.prefix_after=$prefixAfter
        $summary.required_log_sequence=[string]$requiredWatermark; $summary.copied_last_sequence=[string]$log.last_sequence
        $summary.unpaired_final_builder=$(if($null -ne $log.open_builder){[string]$log.open_builder['build_sequence']}else{$null})
        $summary.timing_calibration=$calibration
        $summary.private_keys_collected=$false; $summary.status_scope='independent-DATA-not-last-log-anchor'
        $summary.samples=@($all|ForEach-Object { @{file=[IO.Path]::GetFileName($_.path);command_start_qpc=[string]$_.command_start_qpc;
            command_end_qpc=[string]$_.command_end_qpc;exit_code=$_.exit_code;
            measurement=([IO.Path]::GetFileName($_.path) -cne 'inventory-final.txt');
            coverage_range=$(if($_.ContainsKey('coverage_range')){$_.coverage_range}else{$null});
            timing_range=$(if($_.ContainsKey('timing_range')){$_.timing_range}else{$null})} })
        # All final-safety, prefix, stop and held-configuration checks have now
        # completed. Never attach provisional support earlier in the collection.
        $summary.trial_assessment=Complete-ReportTrialAssessment $summary $sustained $assessment $mode -Finalized
        Save-ReportText (Join-Path $resultDirectory 'collection.json') (($summary|ConvertTo-Json -Depth 18)+"`r`n")
        Write-Host ('Local safety {0}; coverage {1}; performance {2}. Operator/browser/outage effect remains separate.' -f
            $summary.local_safety,$summary.local_coverage,$summary.local_performance)
        Write-Host ('Empirical observe-trial support: {0}; legacy maximum-gap performance: {1}; not production qualification or pilot-start permission.' -f
            $summary.trial_assessment.verdict,$summary.local_performance)
    } catch {
        if ($resultDirectory) {
            $failure=$_.Exception.Message
            try {
                Save-ReportText (Join-Path $resultDirectory 'collection-failure.txt') ('Incomplete/unqualified collection: '+$failure+"`r`nFinal safety unavailable/incomplete; overall qualification forbidden.`r`n")
                $retained=@()
                if ($null -ne $snapshots) { $retained=$snapshots.ToArray() }
                elseif ($null -ne $first) { $retained=@($first) }
                if ($null -ne $final) { $retained+=@($final) }
                $incomplete=@{overall_qualified=$false;final_safety='INCOMPLETE';local_safety='UNVERIFIED';
                    local_coverage='INCONCLUSIVE';local_performance='INCONCLUSIVE';reason=$failure;samples=@();
                    trial_assessment=(New-ReportTrialAssessment)}
                foreach($sample in $retained) {
                    if ($sample.fields.ContainsKey('reporting.loss_reasons') -and $sample.fields.ContainsKey('reporting.revoke_reasons') -and
                        ((Get-ReportScalar $sample.fields 'reporting.loss_reasons') -ne 0 -or
                         (Get-ReportScalar $sample.fields 'reporting.revoke_reasons') -ne 0)) { $incomplete.local_safety='FAIL' }
                    $incomplete.samples+=@{file=[IO.Path]::GetFileName($sample.path);exit_code=$sample.exit_code;
                        command_start_qpc=$(if($sample.ContainsKey('command_start_qpc')){[string]$sample.command_start_qpc}else{$null});
                        command_end_qpc=$(if($sample.ContainsKey('command_end_qpc')){[string]$sample.command_end_qpc}else{$null})}
                }
                Save-ReportText (Join-Path $resultDirectory 'collection-incomplete.json') (($incomplete|ConvertTo-Json -Depth 8)+"`r`n")
            } catch { }
            Write-Host "Preserve incomplete evidence: $resultDirectory"
        }
        throw
    } finally { if ($null -ne $eventStream) { $eventStream.Dispose() }; foreach ($stream in $locks) { $stream.Dispose() } }
}

# Inert tests dot-source helpers only. No process inventory or launch on import.
if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-SteamReportCollection } catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
