param([string]$Collector = (Join-Path $PSScriptRoot '..\tools\Collect-SteamObserve.ps1'))
$ErrorActionPreference = 'Stop'
. $Collector
Initialize-ObserverFileReader
$script:Checks = 0
function Check([bool]$Condition, [string]$Why) { ++$script:Checks; if (!$Condition) { throw $Why } }
function Reject([scriptblock]$Action, [string]$Why) {
    $rejected = $false
    try { $null = & $Action } catch { $rejected = $true }
    Check $rejected $Why
}

# A background writer uses exactly the sharing relation required by the real
# append-only logger. Only owned test files and threads are touched.
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Threading;
public sealed class RS2ObserverGrowingFixture : IDisposable {
    readonly FileStream writer; readonly Thread worker; int stop;
    public long Appends;
    public static void Seed(string path) {
        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) {
            byte[] buffer = new byte[1024 * 1024];
            for (int i=0; i<buffer.Length; ++i) buffer[i]=10;
            for (int i=0; i<64; ++i) file.Write(buffer, 0, buffer.Length);
        }
    }
    public RS2ObserverGrowingFixture(string path) {
        writer = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
        worker = new Thread(Run); worker.IsBackground = true; worker.Start();
    }
    void Run() {
        byte[] value = Encoding.UTF8.GetBytes("{\"fixture\":true}\n");
        while (Volatile.Read(ref stop) == 0) {
            writer.Write(value, 0, value.Length); writer.Flush(); Interlocked.Increment(ref Appends); Thread.Sleep(1);
        }
    }
    public void Dispose() { Interlocked.Exchange(ref stop, 1); worker.Join(); writer.Dispose(); }
}
'@
$temp = Join-Path ([IO.Path]::GetTempPath()) ('RS2ObserverCollectorTests-' + [Guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($temp)
Write-Host "Owned test artifacts: $temp"

$partial = Join-Path $temp 'partial.jsonl'; $partialCopy = Join-Path $temp 'partial-copy.jsonl'
$bytes = [Text.Encoding]::UTF8.GetBytes("{`"one`":true}`n") + [byte[]]@(0xE2, 0x82)
$stream = [IO.File]::Open($partial, [IO.FileMode]::CreateNew)
try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
$source = [RS2ObserveCollection.Files]::Open($partial, $true)
try { $prefix = [RS2ObserveCollection.Files]::CopyPrefix($source, $partial, $partialCopy) } finally { $source.Dispose() }
Check ($prefix.PartialTail -and $prefix.InitialLength -eq $bytes.Length -and $prefix.CopiedLength -eq $bytes.Length) 'Partial tail not reported/preserved.'
Check ((Get-FileHash -LiteralPath $partial).Hash -ceq (Get-FileHash -LiteralPath $partialCopy).Hash) 'Prefix bytes changed.'
$lines = @([RS2ObserveCollection.Files]::CompleteLines($partialCopy))
Check ($lines.Count -eq 1 -and $lines[0] -ceq '{"one":true}') 'Partial UTF-8 was decoded as a complete record.'
Reject { $source = [RS2ObserveCollection.Files]::Open($partial, $true); try {
    [RS2ObserveCollection.Files]::CopyPrefix($source, $partial, $partialCopy)
} finally { $source.Dispose() } } 'Existing evidence was overwritten.'

$growing = Join-Path $temp 'growing.jsonl'; $copy = Join-Path $temp 'growing-copy.jsonl'
[RS2ObserverGrowingFixture]::Seed($growing)
$writer = New-Object RS2ObserverGrowingFixture($growing)
try {
    $source = [RS2ObserveCollection.Files]::Open($growing, $true)
    try {
        $prefix = [RS2ObserveCollection.Files]::CopyPrefix($source, $growing, $copy)
        Check ($prefix.CopiedLength -eq $prefix.InitialLength) 'Collection chased growing EOF.'
        Check ((Get-Item -LiteralPath $copy).Length -eq $prefix.InitialLength) 'Copied length exceeds captured prefix.'
        Check ($writer.Appends -gt 0) 'Fake writer never appended.'
        Reject { [IO.File]::Move($growing, (Join-Path $temp 'renamed.jsonl')) } 'Live source allowed deletion/replacement.'
    } finally { $source.Dispose() }
} finally { $writer.Dispose() }
Check ((Get-Item -LiteralPath $growing).Length -ge $prefix.InitialLength) 'Source unexpectedly shortened.'
Reject { [RS2ObserveCollection.Files]::Open((Join-Path $temp '.\partial.jsonl'), $false) } 'Final opened path mismatch was accepted.'
Reject { Resolve-ObserverPlain (Join-Path $temp '..\outside') $true } 'Relative traversal was accepted.'

$runId = '0123456789abcdef0123456789abcdef'
$run = Join-Path $temp ('20260915T000000Z-123-' + $runId)
$created = [uint64]134000000000000000
$startup = @{ type='startup'; schema=1; version='0.3.0.0'; run_id=$runId; pid=123;
    process_start_filetime=$created; utc_filetime=$created; qpc_frequency=10000000; max_log_bytes=16MB; directory=$run; armed=$true }
$counters = @(6,8,12,20,27,29,30,39,40,44,45,46) | ForEach-Object { @{method=$_; entered=1; completed=1} }
$anchor = @{ type='anchor'; run_id=$runId; pid=123; utc_filetime=$created; status='recording'; bindings_published=1; counters=@($counters) }
$validLog = Join-Path $temp 'valid.jsonl'
Save-ObserverText $validLog (($startup | ConvertTo-Json -Compress) + "`n" + ($anchor | ConvertTo-Json -Depth 5 -Compress) + "`n")
$summary = Read-ObserverLogSummary $validLog 123 $created $run
Check ($summary.bound -and $summary.ordinary_calls -and $summary.startup_complete) 'Valid run/counter evidence rejected.'
Reject { Read-ObserverLogSummary $validLog 124 $created $run } 'Wrong process accepted.'
Reject { Read-ObserverLogSummary $validLog 123 ($created + 1) $run } 'Reused PID/stale start time accepted.'
Reject { Read-ObserverLogSummary $validLog 123 $created ($run + '-wrong') } 'Wrong run directory accepted.'
$empty = Join-Path $temp 'empty.jsonl'; $emptyStream = [IO.File]::Open($empty, [IO.FileMode]::CreateNew); $emptyStream.Dispose()
$summary = Read-ObserverLogSummary $empty 123 $created $run
Check (!$summary.startup_complete -and !$summary.bound -and !$summary.ordinary_calls) 'Empty/unarmed output was called complete.'
$duplicate = Join-Path $temp 'duplicate.jsonl'
Save-ObserverText $duplicate (($startup | ConvertTo-Json -Compress) + "`n" + ($startup | ConvertTo-Json -Compress) + "`n")
Reject { Read-ObserverLogSummary $duplicate 123 $created $run } 'Duplicate startup accepted.'
Reject { Read-ObserverFields "schema=1`r`nschema=2`r`n" } 'Duplicate core evidence key accepted.'

# Manifest entries are exactly allowlisted before opening any payload. A secret
# accidentally placed in the package cannot become a collectible input.
$badPackage = Join-Path $temp 'bad-package'; $null = [IO.Directory]::CreateDirectory($badPackage)
Save-ObserverText (Join-Path $badPackage 'SHA256SUMS') (('A' * 64) + "  RS2SteamObserveKeys/$runId.key`r`n")
$locks = New-Object 'Collections.Generic.List[IO.FileStream]'
try { Reject { Read-ObserverPackage $badPackage $locks } 'Private key package entry accepted.' }
finally { foreach ($locked in $locks) { $locked.Dispose() } }
Check ($script:ObserverPackageFiles -cnotcontains "RS2SteamObserveKeys/$runId.key") 'Private key entered collection allowlist.'

$package = Join-Path $temp 'package'; $null = [IO.Directory]::CreateDirectory($package)
$sums = @()
foreach ($relative in $script:ObserverPackageFiles) {
    $destination = Join-Path $package $relative.Replace('/', '\')
    $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
    Save-ObserverText $destination 'inert fixture - never executed'
    $sums += (Get-FileHash -LiteralPath $destination).Hash + '  ' + $relative
}
Save-ObserverText (Join-Path $package 'SHA256SUMS') (($sums -join "`r`n") + "`r`n")
$locks = New-Object 'Collections.Generic.List[IO.FileStream]'
try {
    $verified = Read-ObserverPackage $package $locks
    Check ($verified.Files.Count -eq 11 -and $locks.Count -eq 12) 'Exact package file verification failed.'
    Reject { [IO.File]::WriteAllText((Join-Path $package 'dlls\RS2ServerFix.dll'), 'replaced') } 'Verified package handle allowed replacement.'
} finally { foreach ($locked in $locks) { $locked.Dispose() } }
Save-ObserverText (Join-Path $package 'secret.key') 'not to be collected'
$locks = New-Object 'Collections.Generic.List[IO.FileStream]'
try { Reject { Read-ObserverPackage $package $locks } 'Unlisted package payload accepted.' }
finally { foreach ($locked in $locks) { $locked.Dispose() } }
Write-Host "checks=$script:Checks failures=0; artifacts retained in $temp"
