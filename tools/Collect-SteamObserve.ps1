param(
    [uint32]$ProcessId = 0,
    [string]$TargetRoot,
    [string]$ObserverRunDirectory,
    [string]$ReportRoot,
    [string]$MarkerPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ObserverHostHash = '0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393'
$script:ObserverSdkHash = 'A44E5537939AE4EEBC69000589AA9B2437A667813A1657CC779198BAE9B815A9'
$script:ObserverPackageFiles = @(
    'dlls/X3DAudio1_7.dll', 'dlls/RS2ServerFix.dll', 'config/RS2SteamObserve.ini',
    'config/qualified_x3audio_genuine.manifest', 'tools/rs2_runtime_inventory.exe',
    'tools/rs2_deployment_preflight.exe', 'tools/rs2_pe_contract.exe',
    'tools/Collect-SteamObserve.ps1', 'tools/Run-SteamObserve.cmd', 'README.md', 'LICENSE')

function Test-ObserverWithin([string]$Root, [string]$Path) {
    return $Path.Equals($Root, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Resolve-ObserverPlain([string]$Path, [bool]$Directory) {
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

function Initialize-ObserverFileReader {
    if ('RS2ObserveCollection.Files' -as [type]) { return }
    # This helper reads file handles only. Process identity/memory inspection is
    # deliberately left to the existing native runtime inventory executable.
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using Microsoft.Win32.SafeHandles;
namespace RS2ObserveCollection {
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
        if (initial < 0 || initial > 1024L * 1024 * 1024) throw new IOException("Observer log exceeds its bound.");
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
}
}
'@
}

function Get-ObserverHash([IO.FileStream]$Stream) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $Stream.Position = 0; $digest = $hash.ComputeHash($Stream); $Stream.Position = 0
        return [BitConverter]::ToString($digest).Replace('-', '') } finally { $hash.Dispose() }
}

function Read-ObserverText([IO.FileStream]$Stream, [int]$Limit) {
    if ($Stream.Length -le 0 -or $Stream.Length -gt $Limit) { throw 'Input exceeds its byte bound or is empty.' }
    $Stream.Position = 0
    $reader = New-Object IO.StreamReader($Stream, (New-Object Text.UTF8Encoding($false, $true)), $false, 4096, $true)
    try { $text = $reader.ReadToEnd(); $Stream.Position = 0; return $text } finally { $reader.Dispose() }
}

function Save-ObserverText([string]$Path, [string]$Text) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Text); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Read-ObserverFields([string]$Text) {
    $fields = New-Object 'Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    if (!$Text.EndsWith("`r`n") -or $Text -match '(?<!\r)\n|\r(?!\n)') { throw 'Evidence has malformed line endings.' }
    foreach ($line in $Text.Substring(0, $Text.Length - 2).Split(@("`r`n"), [StringSplitOptions]::None)) {
        $split = $line.IndexOf('=')
        if ($split -le 0) { throw 'Malformed evidence field.' }
        $key = $line.Substring(0, $split)
        if ($fields.ContainsKey($key) -or $key -cnotmatch '^[a-z][a-z0-9_.]*$') { throw 'Duplicate or malformed evidence field.' }
        $fields.Add($key, $line.Substring($split + 1))
    }
    return ,$fields
}

function Assert-ObserverFields($Fields, $Required) {
    foreach ($key in $Required.Keys) { if (!$Fields.ContainsKey($key) -or $Fields[$key] -cne [string]$Required[$key]) { throw "Evidence field mismatch: $key." } }
}

function Read-ObserverPackage([string]$Root, $Locks) {
    $sumPath = Resolve-ObserverPlain (Join-Path $Root 'SHA256SUMS') $false
    $sumStream = [RS2ObserveCollection.Files]::Open($sumPath, $false); $Locks.Add($sumStream)
    $text = Read-ObserverText $sumStream 16384
    $files = New-Object 'Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    foreach ($line in ($text.TrimEnd("`r", "`n") -split '\r?\n')) {
        if ($line -cnotmatch '^([0-9A-F]{64})  ([A-Za-z0-9_./-]+)$') { throw 'Malformed SHA256SUMS.' }
        $digest = $Matches[1]; $relative = $Matches[2]
        if ($relative -cnotin $script:ObserverPackageFiles -or $files.ContainsKey($relative)) { throw 'Unapproved or duplicate package entry.' }
        $files.Add($relative, $digest)
    }
    if ($files.Count -ne $script:ObserverPackageFiles.Count) { throw 'Package file set is incomplete.' }
    foreach ($relative in $script:ObserverPackageFiles) {
        $path = Resolve-ObserverPlain (Join-Path $Root $relative.Replace('/', '\')) $false
        $stream = [RS2ObserveCollection.Files]::Open($path, $false); $Locks.Add($stream)
        if ((Get-ObserverHash $stream) -cne $files[$relative]) { throw "Package SHA-256 mismatch: $relative." }
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
    return @{ Files = $files; ManifestHash = (Get-ObserverHash $sumStream) }
}

function Invoke-ObserverInventory([string]$Package, $Files, [string]$ServerRoot, [uint32]$SelectedId, [string]$Report) {
    $arguments = @('--pid', [string]$SelectedId, '--target-root', $ServerRoot, '--expect', 'proxy-pass',
        '--mode', 'active', '--expected-recon', 'corrected', '--companion-kind', 'companion-observer',
        '--bootstrap-sha256', $Files['dlls/X3DAudio1_7.dll'], '--companion-sha256', $Files['dlls/RS2ServerFix.dll'],
        '--genuine-manifest', (Join-Path $Package 'config\qualified_x3audio_genuine.manifest'), '--report', $Report)
    & (Join-Path $Package 'tools\rs2_runtime_inventory.exe') @arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Native inventory rejected the selected process ($LASTEXITCODE); no bypass." }
    $stream = [RS2ObserveCollection.Files]::Open($Report, $false)
    try { $fields = Read-ObserverFields (Read-ObserverText $stream (8MB)) } finally { $stream.Dispose() }
    Assert-ObserverFields $fields @{ schema='1'; mode='runtime-inventory'; pid=[string]$SelectedId; expect='proxy-pass';
        deployment_mode='active'; companion_kind='companion-observer'; expected_recon='corrected'; observed_recon='corrected';
        recon_sha256='F402D3262D39EC73E9B33E14CC4F74B06EC981ECDE94D59ADF67D905CC1DA2D5'; constant_match='true';
        host_sha256=$script:ObserverHostHash; sdk_sha256=$script:ObserverSdkHash; finding_count='0'; result='pass';
        bootstrap_sha256=$Files['dlls/X3DAudio1_7.dll']; companion_sha256=$Files['dlls/RS2ServerFix.dll'];
        observed_bootstrap_sha256=$Files['dlls/X3DAudio1_7.dll']; observed_companion_sha256=$Files['dlls/RS2ServerFix.dll'];
        tool_sha256=$Files['tools/rs2_runtime_inventory.exe']; manifest_sha256=$Files['config/qualified_x3audio_genuine.manifest'] }
    return ,$fields
}

function Read-ObserverLogSummary([string]$Path, [uint32]$SelectedId, [uint64]$Created, [string]$RunDirectory) {
    $startup = $null; $last = $null; $eventLines = 0L; $completeLines = 0L
    foreach ($line in [RS2ObserveCollection.Files]::CompleteLines($Path)) {
        ++$completeLines
        # Counter/startup records are the acceptance evidence. Ordinary events
        # remain byte-preserved; this collector does not reinterpret API payloads.
        if ($line -cmatch '^\{"type":"event",') { ++$eventLines; continue }
        $record = $line | ConvertFrom-Json
        if ($record.type -ceq 'startup') {
            if ($null -ne $startup -or $completeLines -ne 1) { throw 'Duplicate or misplaced observer startup record.' }
            if ($record.schema -ne 1 -or $record.version -cne '0.3.0.0' -or $record.pid -ne $SelectedId -or
                [uint64]$record.process_start_filetime -ne $Created -or $record.run_id -cnotmatch '^[0-9a-f]{32}$' -or
                !([string]$record.directory).Equals($RunDirectory, [StringComparison]::OrdinalIgnoreCase) -or
                !([IO.Path]::GetFileName($RunDirectory)).EndsWith('-' + $record.run_id, [StringComparison]::Ordinal) -or
                [uint64]$record.utc_filetime -lt $Created -or [uint64]$record.utc_filetime -gt [uint64][DateTime]::UtcNow.ToFileTimeUtc() -or
                $record.qpc_frequency -le 0 -or $record.max_log_bytes -lt 16MB -or $record.max_log_bytes -gt 1GB -or
                $record.armed -isnot [bool] -or !$record.armed) { throw 'Observer run identity/startup does not match native process evidence.' }
            $startup = $record
        } elseif ($record.type -cin @('anchor', 'footer')) {
            if ($null -eq $startup -or $record.run_id -cne $startup.run_id -or $record.pid -ne $SelectedId -or
                [uint64]$record.utc_filetime -lt $Created -or [uint64]$record.utc_filetime -gt [uint64][DateTime]::UtcNow.ToFileTimeUtc()) { throw 'Observer counter record belongs to another run or time.' }
            $last = $record
        } elseif ($record.type -ceq 'event') { ++$eventLines }
        else { throw 'Unknown observer record type.' }
    }
    $bound = $false; $ordinaryCalls = $false
    if ($null -ne $last) {
        $methods = New-Object 'Collections.Generic.HashSet[int]'
        foreach ($counter in $last.counters) {
            if (!$methods.Add([int]$counter.method) -or $counter.method -notin @(6,8,12,20,27,29,30,39,40,44,45,46) -or
                $counter.entered -lt 0 -or $counter.completed -lt 0) { throw 'Invalid observer counter set.' }
        }
        if ($methods.Count -ne 12 -or $last.status -cnotin @('recording','failed','truncated','stopped')) { throw 'Incomplete observer counter/status set.' }
        $bound = [uint64]$last.bindings_published -gt 0
        foreach ($counter in $last.counters) {
            if ($counter.method -in @(6,8,12,20,27,29,30,39,40) -and [uint64]$counter.completed -gt 0) { $ordinaryCalls = $true }
        }
    }
    return @{ startup=$startup; latest_anchor=$last; complete_lines=$completeLines; event_lines=$eventLines;
        bound=$bound; ordinary_calls=$ordinaryCalls; startup_complete=($null -ne $startup);
        event_payload_validation='not-performed-byte-preserved'; counter_snapshots_atomic=$false }
}

function Invoke-SteamObserveCollection {
    Initialize-ObserverFileReader
    if (![Environment]::Is64BitProcess) { throw 'Run in 64-bit Windows PowerShell.' }
    $locks = New-Object 'Collections.Generic.List[IO.FileStream]'; $resultDirectory = $null
    try {
        if (!$ProcessId) { $entered = Read-Host 'PID of the already running observer-enabled server';
            if ($entered -cnotmatch '^[1-9][0-9]{0,9}$' -or ![uint32]::TryParse($entered, [ref]$ProcessId)) { throw 'Invalid PID.' } }
        if (!$TargetRoot) { $TargetRoot = Read-Host 'Full server root directory' }
        $server = Resolve-ObserverPlain $TargetRoot $true
        $package = Resolve-ObserverPlain ([IO.Path]::GetDirectoryName($PSScriptRoot)) $true
        if ((Test-ObserverWithin $server $package) -or (Test-ObserverWithin $package $server)) { throw 'Keep package outside the server tree.' }
        $verified = Read-ObserverPackage $package $locks
        if (!$ReportRoot) { $ReportRoot = Join-Path ([IO.Path]::GetDirectoryName($package)) 'reports' }
        if (!(Test-Path -LiteralPath $ReportRoot)) {
            $parent = Resolve-ObserverPlain ([IO.Path]::GetDirectoryName($ReportRoot)) $true
            $leaf = [IO.Path]::GetFileName($ReportRoot)
            if ($leaf -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') { throw 'Invalid report folder name.' }
            $candidate = Join-Path $parent $leaf
            if ((Test-ObserverWithin $server $candidate) -or (Test-ObserverWithin $package $candidate)) { throw 'Reports must be outside server/package.' }
            $null = [IO.Directory]::CreateDirectory($candidate)
        }
        $reportBase = Resolve-ObserverPlain $ReportRoot $true
        if ((Test-ObserverWithin $server $reportBase) -or (Test-ObserverWithin $package $reportBase)) { throw 'Reports must be outside server/package.' }
        $resultDirectory = Join-Path $reportBase ('SteamObserve-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N'))
        if (Test-Path -LiteralPath $resultDirectory) { throw 'Output collision.' }
        $null = [IO.Directory]::CreateDirectory($resultDirectory)
        Write-Host "Evidence folder: $resultDirectory"
        $before = Invoke-ObserverInventory $package $verified.Files $server $ProcessId (Join-Path $resultDirectory 'inventory-before.txt')
        $executable = Resolve-ObserverPlain ([Uri]::UnescapeDataString($before['process_image_path']).Replace('/', '\')) $false
        $exeDirectory = [IO.Path]::GetDirectoryName($executable)
        if (!$ObserverRunDirectory) { $ObserverRunDirectory = Read-Host 'Full current run directory under RS2SteamObserve beside the EXE (match PID/run_id from the notice)' }
        $run = Resolve-ObserverPlain $ObserverRunDirectory $true
        $expectedParent = Join-Path $exeDirectory 'RS2SteamObserve'
        if (![IO.Path]::GetDirectoryName($run).Equals($expectedParent, [StringComparison]::OrdinalIgnoreCase)) { throw 'Observer run is not beside this process EXE.' }
        if (!$MarkerPath) { $MarkerPath = Join-Path $exeDirectory ("RS2ServerFix.loader.$ProcessId.log") }
        $marker = Resolve-ObserverPlain $MarkerPath $false
        if (![IO.Path]::GetFileName($marker).Equals("RS2ServerFix.loader.$ProcessId.log", [StringComparison]::OrdinalIgnoreCase)) { throw 'Marker filename does not match the selected PID.' }
        $primaryMarker = [IO.Path]::GetDirectoryName($marker).Equals($exeDirectory, [StringComparison]::OrdinalIgnoreCase)
        $markerStream = [RS2ObserveCollection.Files]::Open((Resolve-ObserverPlain $marker $false), $false); $locks.Add($markerStream)
        $markerText = Read-ObserverText $markerStream 8192
        Save-ObserverText (Join-Path $resultDirectory 'startup-marker.log') $markerText
        $fields = Read-ObserverFields $markerText
        Assert-ObserverFields $fields @{ schema='3'; version='0.3.0.0'; pid=[string]$ProcessId;
            executable=[IO.Path]::GetFileName($executable); executable_size=[string](Get-Item -LiteralPath $executable).Length;
            sha256=$script:ObserverHostHash; build_identity='current-full-dump';
            bootstrap='X3DAudio1_7.dll'; bootstrap_beside_executable='true'; companion='RS2ServerFix.dll'; companion_beside_executable='true';
            genuine_module='system32'; genuine_initialize_present='true'; genuine_calculate_present='true';
            trigger='exe-crt-initialize'; mode='active'; fix='recon-exclusive-scale-v1'; qualification='ready'; recon='active';
            reason='none'; initialize_result='0'; completion='complete' }
        if ($fields['primary_write_error'] -cnotmatch '^(0|[1-9][0-9]{0,9})$' -or [uint64]$fields['primary_write_error'] -gt [uint32]::MaxValue -or
            ($primaryMarker -ne ($fields['primary_write_error'] -ceq '0'))) { throw 'Marker location contradicts the primary write result.' }
        $created = [uint64]$before['process_creation_filetime']
        $markerTime = [DateTime]::ParseExact($fields['utc'], "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal))
        if ($markerTime -lt [DateTime]::FromFileTimeUtc([long]$created) -or $markerTime -gt [DateTime]::UtcNow) { throw 'Core marker is stale.' }
        # Fixed evidence allowlist: this is the ONLY server observer file copied.
        # Never enumerate the run directory or touch the sibling private key store.
        $events = Resolve-ObserverPlain (Join-Path $run 'events.jsonl') $false
        $eventStream = [RS2ObserveCollection.Files]::Open($events, $true)
        try { $prefix = [RS2ObserveCollection.Files]::CopyPrefix($eventStream, $events, (Join-Path $resultDirectory 'events.jsonl')) }
        finally { $eventStream.Dispose() }
        $summary = Read-ObserverLogSummary (Join-Path $resultDirectory 'events.jsonl') $ProcessId $created $run
        $after = Invoke-ObserverInventory $package $verified.Files $server $ProcessId (Join-Path $resultDirectory 'inventory-after.txt')
        foreach ($key in @('process_creation_filetime','process_image_path','host_sha256','sdk_sha256','observed_bootstrap_sha256','observed_companion_sha256')) {
            if ($before[$key] -cne $after[$key]) { throw 'Process/artifact identity changed during collection.' }
        }
        $summary.prefix = $prefix; $summary.package_manifest_sha256 = $verified.ManifestHash
        $summary.core_marker_location = if ($primaryMarker) { 'beside-executable' } else { 'operator-supplied-fallback' }
        $summary.private_keys_collected = $false; $summary.operator_smoke = 'not-verified'; $summary.capture = 'bounded-live-prefix-not-clean-shutdown'
        $summary.last_written_anchor_healthy = $null -ne $summary.latest_anchor -and $summary.latest_anchor.status -ceq 'recording' -and
            $summary.latest_anchor.error -eq 0 -and $summary.latest_anchor.coverage_reasons -eq 0 -and !$summary.latest_anchor.unknown_lifecycle -and
            $summary.latest_anchor.queue_dropped_contention -eq 0 -and $summary.latest_anchor.queue_dropped_full -eq 0 -and $summary.latest_anchor.queue_abandoned -eq 0
        $summary.status_scope = 'last-written-anchor-not-current-in-memory-writer-status'
        $summary.latest_anchor_age_seconds = if ($null -ne $summary.latest_anchor) {
            ([DateTime]::UtcNow - [DateTime]::FromFileTimeUtc([long]$summary.latest_anchor.utc_filetime)).TotalSeconds
        } else { $null }
        $summary.basic_observation_evidence_present = $summary.startup_complete -and $summary.bound -and $summary.ordinary_calls
        Save-ObserverText (Join-Path $resultDirectory 'collection.json') (($summary | ConvertTo-Json -Depth 12) + "`r`n")
        Write-Host 'Collected read-only evidence. Private keys excluded; authentication/recon/server state unchanged.'
        if (!$summary.basic_observation_evidence_present -or $prefix.PartialTail -or !$summary.last_written_anchor_healthy) {
            Write-Warning 'Evidence is incomplete, unbound, missing ordinary calls, partially written or records coverage loss. Do not treat it as complete incident coverage.'
        }
    } catch {
        if ($resultDirectory) {
            try { Save-ObserverText (Join-Path $resultDirectory 'collection-failure.txt') ('Incomplete collection: ' + $_.Exception.Message + "`r`n") } catch { }
            Write-Host "Preserve incomplete evidence: $resultDirectory"
        }
        throw
    } finally { foreach ($stream in $locks) { $stream.Dispose() } }
}

# Dot-sourcing exposes file/parser helpers to inert tests; it never queries a process.
if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-SteamObserveCollection } catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
