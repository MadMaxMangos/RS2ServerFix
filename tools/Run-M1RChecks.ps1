[CmdletBinding()]
param(
    [ValidateSet('Stopped', 'Control', 'Passive', 'Active')][string]$Stage = 'Stopped',
    [string]$ExePath,
    [uint32]$ProcessId = 0,
    [string]$TargetRoot,
    [string]$ReportRoot,
    [string]$MarkerPath,
    [ValidateSet('not-observed-yet', 'not-installed', 'not-enforced', 'allowed', 'alerted', 'blocked')]
    [string]$AvEdrDisposition = 'not-observed-yet',
    [ValidateSet('not-observed-yet', 'not-installed', 'not-enforced', 'allowed', 'alerted', 'blocked')]
    [string]$WdacDisposition = 'not-observed-yet',
    [ValidateSet('not-observed-yet', 'not-installed', 'not-enforced', 'allowed', 'alerted', 'blocked')]
    [string]$AppLockerDisposition = 'not-observed-yet',
    [ValidateSet('not-observed-yet', 'not-installed', 'not-enforced', 'allowed', 'alerted', 'blocked')]
    [string]$EacDisposition = 'not-observed-yet'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ExpectedHostHash = '0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393'
$script:ReconHashes = @{
    original = 'E58CE150747B01ED9A6BC21223061AA94F56430CEDD996D7D727B6310968BDEE'
    corrected = 'F402D3262D39EC73E9B33E14CC4F74B06EC981ECDE94D59ADF67D905CC1DA2D5'
}
$script:MarkerFields = @('schema', 'version', 'utc', 'pid', 'executable', 'executable_size',
    'sha256', 'build_identity', 'bootstrap', 'bootstrap_beside_executable', 'companion',
    'companion_beside_executable', 'genuine_module', 'genuine_initialize_present',
    'genuine_calculate_present', 'trigger', 'mode', 'fix', 'qualification', 'recon',
    'reason', 'initialize_result', 'primary_write_error', 'completion')

function Test-WithinRoot([string]$Root, [string]$Path) {
    return $Path.Equals($Root, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Resolve-PlainPath([string]$Path, [ValidateSet('File', 'Directory')][string]$Kind) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:\\' -or
        $Path.Substring(2).Contains(':') -or $Path.Contains('/') -or $Path -match '[\x00-\x1F"<>|?*]') {
        throw 'Use a full local drive path without wildcard, device, stream, or control characters.'
    }
    foreach ($part in $Path.Substring(3).Split('\')) {
        if ($part -eq '.' -or $part -eq '..' -or $part.EndsWith('.') -or $part.EndsWith(' ')) {
            throw 'Path contains a relative or ambiguous component.'
        }
    }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($full.Length -eq 2) { $full += '\' }
    if ($full.Length -ge 32768) { throw 'Path exceeds the supported bound.' }
    $item = Get-Item -LiteralPath $full -Force
    if (($Kind -eq 'Directory') -ne [bool]$item.PSIsContainer) { throw 'Path has the wrong file type.' }
    $cursor = $item
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Reparse points are not accepted in evidence or server paths.'
        }
        if ($cursor -is [IO.FileInfo]) { $cursor = $cursor.Directory } else { $cursor = $cursor.Parent }
    }
    return $full
}

function Open-LockedFile([string]$Path, [Collections.Generic.List[IO.FileStream]]$Locks) {
    $plain = Resolve-PlainPath $Path File
    $stream = [IO.File]::Open($plain, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $Locks.Add($stream)
    return $stream
}

function Read-BoundedStream([IO.FileStream]$Stream, [int]$Limit) {
    if ($Stream.Length -le 0 -or $Stream.Length -gt $Limit) { throw 'Evidence file is empty or exceeds its size bound.' }
    $Stream.Position = 0
    $bytes = New-Object byte[] ([int]$Stream.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $read = $Stream.Read($bytes, $offset, $bytes.Length - $offset)
        if ($read -le 0) { throw 'Evidence file ended during reading.' }
        $offset += $read
    }
    $Stream.Position = 0
    return ,$bytes
}

function Get-StreamSha256([IO.FileStream]$Stream) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $Stream.Position = 0
        $digest = $algorithm.ComputeHash($Stream)
        $Stream.Position = 0
        return [BitConverter]::ToString($digest).Replace('-', '')
    } finally { $algorithm.Dispose() }
}

function Convert-StrictUtf8([byte[]]$Bytes) {
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 239 -and $Bytes[1] -eq 187 -and $Bytes[2] -eq 191) {
        throw 'A UTF-8 BOM is not permitted in evidence files.'
    }
    $encoding = New-Object Text.UTF8Encoding($false, $true)
    $text = $encoding.GetString($Bytes)
    if ($text.Contains([string][char]0)) { throw 'Evidence contains a NUL byte.' }
    return $text
}

function Convert-StrictFields([byte[]]$Bytes, [string[]]$ExpectedOrder = @()) {
    $text = Convert-StrictUtf8 $Bytes
    if (-not $text.EndsWith("`r`n") -or $text -match '(?<!\r)\n|\r(?!\n)') {
        throw 'Evidence must have exact CRLF lines and a final CRLF.'
    }
    $lines = [regex]::Split($text.Substring(0, $text.Length - 2), '\r\n')
    if ($lines.Length -gt 262144) { throw 'Evidence field count exceeds its bound.' }
    if ($ExpectedOrder.Count -gt 0 -and $lines.Length -ne $ExpectedOrder.Count) { throw 'Marker field count is incorrect.' }
    $fields = New-Object 'Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    for ($index = 0; $index -lt $lines.Length; ++$index) {
        $split = $lines[$index].IndexOf('=')
        if ($split -le 0 -or $lines[$index] -match '[\x00-\x1F\x7F]') { throw 'Malformed evidence field.' }
        $key = $lines[$index].Substring(0, $split)
        $value = $lines[$index].Substring($split + 1)
        if ($key -cnotmatch '^[a-z][a-z0-9_.]*$' -or $fields.ContainsKey($key)) { throw 'Duplicate or malformed evidence key.' }
        if ($ExpectedOrder.Count -gt 0 -and $key -cne $ExpectedOrder[$index]) { throw 'Marker fields are missing, extra, or reordered.' }
        $fields.Add($key, $value)
    }
    return ,$fields
}

function Assert-Fields($Fields, $Expected) {
    foreach ($key in $Expected.Keys) {
        if (-not $Fields.ContainsKey($key) -or $Fields[$key] -cne [string]$Expected[$key]) {
            throw "Evidence did not satisfy required field: $key."
        }
    }
}

function Convert-Utc([string]$Value) {
    $date = [DateTime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTime]::TryParseExact($Value, "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
        [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$date)) { throw 'Malformed UTC timestamp.' }
    return $date
}

function Test-PassiveMarker([byte[]]$Bytes, [uint32]$ExpectedProcessId, [string]$ExeLeaf,
    [uint64]$ExeSize, [DateTime]$CreatedUtc, [DateTime]$ObservedUtc,
    [ValidateSet('Primary', 'Fallback')][string]$MarkerLocation = 'Primary',
    [ValidateSet('passive', 'active')][string]$ExpectedMode = 'passive') {
    # Retain the M1R helper name/default for existing callers; M2 must request active explicitly.
    if ($Bytes.Length -gt 8192) { throw 'Marker exceeds its size bound.' }
    $fields = Convert-StrictFields $Bytes $script:MarkerFields
    Assert-Fields $fields @{
        schema = '3'; version = '0.2.0.0'; pid = [string]$ExpectedProcessId; executable = $ExeLeaf
        executable_size = [string]$ExeSize; sha256 = $script:ExpectedHostHash
        build_identity = 'current-full-dump'; bootstrap = 'X3DAudio1_7.dll'
        bootstrap_beside_executable = 'true'; companion = 'RS2ServerFix.dll'
        companion_beside_executable = 'true'; genuine_module = 'system32'
        genuine_initialize_present = 'true'; genuine_calculate_present = 'true'
        trigger = 'exe-crt-initialize'; mode = $ExpectedMode; fix = 'recon-exclusive-scale-v1'
        qualification = 'ready'; recon = $ExpectedMode; reason = 'none'; initialize_result = '0'; completion = 'complete'
    }
    if ($fields['primary_write_error'] -cnotmatch '^(0|[1-9][0-9]{0,9})$' -or
        [uint64]$fields['primary_write_error'] -gt [uint32]::MaxValue) { throw 'Invalid primary marker write error.' }
    if (($MarkerLocation -eq 'Primary' -and $fields['primary_write_error'] -cne '0') -or
        ($MarkerLocation -eq 'Fallback' -and $fields['primary_write_error'] -ceq '0')) {
        throw 'Marker location contradicts its primary write error.'
    }
    $markerUtc = Convert-Utc $fields['utc']
    if ($ObservedUtc -lt $CreatedUtc -or $markerUtc -lt $CreatedUtc -or $markerUtc -gt $ObservedUtc) {
        throw 'Marker is stale or outside this process lifetime observation.'
    }
    return ,$fields
}

function Get-MarkerLocation([string]$ResolvedMarkerPath, [string]$ExeDirectory, [uint32]$ExpectedProcessId) {
    $expectedLeaf = "RS2ServerFix.loader.$ExpectedProcessId.log"
    if (-not [IO.Path]::GetFileName($ResolvedMarkerPath).Equals($expectedLeaf, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The marker filename does not match the selected PID.'
    }
    if ([IO.Path]::GetDirectoryName($ResolvedMarkerPath).Equals($ExeDirectory, [StringComparison]::OrdinalIgnoreCase)) {
        return 'Primary'
    }
    return 'Fallback'
}

function Get-StageContract([ValidateSet('Stopped', 'Control', 'Passive', 'Active')][string]$CheckStage,
    [ValidateSet('passive', 'active')][string]$PackageMode) {
    if (($CheckStage -eq 'Passive' -and $PackageMode -cne 'passive') -or
        ($CheckStage -eq 'Active' -and $PackageMode -cne 'active')) {
        throw 'The requested running check does not match the package deployment mode.'
    }
    $expectedRecon = if ($CheckStage -eq 'Active') { 'corrected' } else { 'original' }
    return @{
        Mode = $PackageMode
        Expectation = $(if ($CheckStage -eq 'Control') { 'system-control' } else { 'proxy-pass' })
        Recon = $expectedRecon
        ReconHash = $script:ReconHashes[$expectedRecon]
    }
}

function Get-PathSha256([string]$ResolvedPath) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($ResolvedPath.ToUpperInvariant())
        return [BitConverter]::ToString($algorithm.ComputeHash($bytes)).Replace('-', '')
    } finally { $algorithm.Dispose() }
}

function Assert-PackagePath([string]$Relative) {
    if ($Relative -cnotmatch '^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$' -or
        @($Relative.Split('/') | Where-Object { $_ -eq '.' -or $_ -eq '..' }).Count -gt 0) {
        throw 'Package contains an invalid relative path.'
    }
}

function Read-VerifiedPackage([string]$Root, [Collections.Generic.List[IO.FileStream]]$Locks) {
    $jsonStream = Open-LockedFile (Join-Path $Root 'package.json') $Locks
    $jsonHash = Get-StreamSha256 $jsonStream
    $jsonText = Convert-StrictUtf8 (Read-BoundedStream $jsonStream 65536)
    if (-not $jsonText.TrimStart().StartsWith('{')) { throw 'Package metadata must start with a JSON object.' }
    $package = $jsonText | ConvertFrom-Json
    if ($package -isnot [PSCustomObject]) { throw 'Package metadata must be one JSON object.' }
    $keys = @($package.PSObject.Properties.Name | Sort-Object)
    if (($keys -join '|') -cne 'bootstrap_sha256|companion_sha256|files|host_sha256|mode|schema|version') {
        throw 'Package metadata has missing or extra fields.'
    }
    if (($package.schema -isnot [int] -and $package.schema -isnot [long]) -or
        $package.schema -ne 1 -or $package.files -isnot [PSCustomObject]) { throw 'Package schema/files have invalid JSON types.' }
    foreach ($key in @('version', 'mode', 'host_sha256', 'bootstrap_sha256', 'companion_sha256')) {
        if ($package.$key -isnot [string]) { throw "Package field must be one JSON string: $key." }
    }
    foreach ($key in @('host_sha256', 'bootstrap_sha256', 'companion_sha256')) {
        if ($package.$key -cnotmatch '^[0-9A-F]{64}$') { throw "Package field is not an uppercase SHA-256: $key." }
    }
    if ($package.version -cne '0.2.0.0' -or $package.mode -cnotin @('passive', 'active') -or
        $package.host_sha256 -cne $script:ExpectedHostHash) { throw 'Package metadata is not an approved recon contract.' }
    $files = New-Object 'Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $package.files.PSObject.Properties) {
        Assert-PackagePath $entry.Name
        if ($entry.Value -isnot [string] -or $entry.Value -cnotmatch '^[0-9A-F]{64}$' -or $files.ContainsKey($entry.Name) -or
            $entry.Name -ieq 'package.json' -or $entry.Name -ieq 'SHA256SUMS') { throw 'Invalid package file hash entry.' }
        $files.Add($entry.Name, $entry.Value)
    }
    if ($files.Count -gt 128) { throw 'Package file count exceeds its bound.' }
    foreach ($required in @('dlls/X3DAudio1_7.dll', 'dlls/RS2ServerFix.dll', 'tools/rs2_deployment_preflight.exe',
        'tools/rs2_runtime_inventory.exe', 'tools/rs2_image_protection_probe.exe', 'tools/probe-input.exe',
        'tools/Run-M1RChecks.ps1', 'tools/Check-Stopped.cmd', 'tools/Check-Running-Control.cmd',
        'config/qualified_x3audio_genuine.manifest', 'README.md',
        $(if ($package.mode -ceq 'active') { 'tools/Check-Running-Active.cmd' } else { 'tools/Check-Running-Passive.cmd' }))) {
        if (-not $files.ContainsKey($required)) { throw "Required package file is absent: $required." }
    }
    if ($package.bootstrap_sha256 -cne $files['dlls/X3DAudio1_7.dll'] -or
        $package.companion_sha256 -cne $files['dlls/RS2ServerFix.dll']) { throw 'Deployment hashes disagree with the package file map.' }
    $sumStream = Open-LockedFile (Join-Path $Root 'SHA256SUMS') $Locks
    $sumText = Convert-StrictUtf8 (Read-BoundedStream $sumStream 65536)
    $sums = New-Object 'Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in [regex]::Split($sumText.TrimEnd("`r", "`n"), '\r?\n')) {
        if ($line -cnotmatch '^([0-9A-F]{64})  ([A-Za-z0-9_./-]+)$') { throw 'Malformed SHA256SUMS line.' }
        $digest = $Matches[1]; $relative = $Matches[2]
        Assert-PackagePath $relative
        if ($sums.ContainsKey($relative)) { throw 'Duplicate SHA256SUMS entry.' }
        $sums.Add($relative, $digest)
    }
    if ($sums.Count -ne $files.Count + 1 -or -not $sums.ContainsKey('package.json') -or
        $sums['package.json'] -cne $jsonHash) { throw 'SHA256SUMS does not bind this package.json and exact file set.' }
    foreach ($entry in $files.GetEnumerator()) {
        if (-not $sums.ContainsKey($entry.Key) -or $sums[$entry.Key] -cne $entry.Value) { throw 'Package manifests disagree.' }
        $stream = Open-LockedFile (Join-Path $Root $entry.Key.Replace('/', '\')) $Locks
        if ((Get-StreamSha256 $stream) -cne $entry.Value) { throw "Package hash mismatch: $($entry.Key)." }
    }
    $directories = New-Object 'Collections.Generic.Stack[IO.DirectoryInfo]'
    $directories.Push((Get-Item -LiteralPath $Root))
    $seen = 0
    while ($directories.Count -gt 0) {
        foreach ($entry in $directories.Pop().EnumerateFileSystemInfos()) {
            if (++$seen -gt 256 -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Package contains a reparse point or exceeds its inventory bound.'
            }
            if ($entry -is [IO.DirectoryInfo]) { $directories.Push($entry); continue }
            $relative = $entry.FullName.Substring($Root.Length + 1).Replace('\', '/')
            if (-not $files.ContainsKey($relative) -and $relative -cne 'package.json' -and $relative -cne 'SHA256SUMS') {
                throw "Unlisted file in package: $relative."
            }
        }
    }
    return @{ Metadata = $package; Files = $files; JsonHash = $jsonHash }
}

function Save-NewBytes([string]$Path, [byte[]]$Bytes) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}

function Save-NewText([string]$Path, [string]$Text) {
    $encoding = New-Object Text.UTF8Encoding($false)
    Save-NewBytes $Path $encoding.GetBytes($Text)
}

function Save-FailedCheckRecord([string]$Directory, [string]$CheckStage, [uint32]$SelectedProcessId,
    [string]$Operation, [string]$Message, [string]$RootHash, [string]$ExePathHash) {
    # Preserve a bounded reason without copying a potentially private filesystem path.
    $reason = [regex]::Replace($Message, '[\r\n\x00-\x1F\x7F]', ' ')
    $reason = [regex]::Replace($reason, '(?i)([A-Z]:\\|\\\\).*', '<path-redacted>')
    if ($reason.Length -gt 512) { $reason = $reason.Substring(0, 512) }
    Save-NewText (Join-Path $Directory 'check-failure.txt') (
        "schema=1`r`nstage=$($CheckStage.ToLowerInvariant())`r`npid=$SelectedProcessId`r`n" +
        "target_root_path_sha256=$RootHash`r`nexecutable_path_sha256=$ExePathHash`r`n" +
        "automated_evidence=failed_or_incomplete`r`nconsole_acceptance=not_verified`r`noperator_acceptance=pending`r`n" +
        "failure_operation=$Operation`r`nfailure_message=$reason`r`n")
}

function Invoke-EvidenceTool([string]$Tool, [string[]]$Arguments, [string]$LogPath) {
    $stream = [IO.File]::Open($LogPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    $writer = New-Object IO.StreamWriter($stream, (New-Object Text.UTF8Encoding($false)))
    $process = New-Object Diagnostics.Process
    try {
        $quoted = foreach ($argument in $Arguments) {
            if ($argument.Contains('"') -or $argument -match '[\x00-\x1F]') { throw 'Invalid native tool argument.' }
            '"' + [regex]::Replace($argument, '(\\+)$', '$1$1') + '"'
        }
        $process.StartInfo.FileName = $Tool
        $process.StartInfo.Arguments = $quoted -join ' '
        $process.StartInfo.WorkingDirectory = Resolve-PlainPath ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($LogPath))) Directory
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        Write-Host ('Running ' + [IO.Path]::GetFileName($Tool) + '...')
        if (-not $process.Start()) { throw 'Evidence tool could not start.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $code = $process.ExitCode
        foreach ($text in @($stdout.Result, $stderr.Result)) {
            $writer.Write($text)
            if ($text) { Write-Host $text.TrimEnd() }
        }
        $writer.WriteLine("exit_code=$code")
        $writer.Flush()
        $stream.Flush($true)
    } finally { $writer.Dispose(); $process.Dispose() }
    if ($code -ne 0) { throw "Evidence tool returned $code. Preserve this report folder and resolve the reported failure." }
}

function Invoke-M1RChecks {
    $locks = New-Object 'Collections.Generic.List[IO.FileStream]'
    $runDirectory = $null
    $rootPathHash = ''
    $exePathHash = ''
    $operation = 'validate_inputs_and_package'
    try {
        if (-not [Environment]::Is64BitProcess) { throw 'Run the checks in 64-bit Windows PowerShell.' }
        if (-not $ExePath) { $ExePath = Read-Host 'Full path of the full-dump-patched PR3 EXE (include the .exe filename)' }
        $executable = Resolve-PlainPath $ExePath File
        $exeDirectory = [IO.Path]::GetDirectoryName($executable)
        if (-not $TargetRoot) {
            $parent = Get-Item -LiteralPath $exeDirectory
            if ($parent.Name -ieq 'Win64' -and $parent.Parent.Name -ieq 'Binaries') { $TargetRoot = $parent.Parent.Parent.FullName }
            else { $TargetRoot = $exeDirectory }
        }
        $serverRoot = Resolve-PlainPath $TargetRoot Directory
        if ($serverRoot.Length -le 3) { throw 'Select the server directory, not an entire drive.' }
        if (-not (Test-WithinRoot $serverRoot $executable)) { throw 'The selected EXE is outside TargetRoot.' }
        $packageRoot = Resolve-PlainPath ([IO.Path]::GetDirectoryName($PSScriptRoot)) Directory
        if ((Test-WithinRoot $serverRoot $packageRoot) -or (Test-WithinRoot $packageRoot $serverRoot)) {
            throw 'Keep the complete recon test package outside the server tree.'
        }
        $verified = Read-VerifiedPackage $packageRoot $locks
        $metadata = $verified.Metadata
        $contract = Get-StageContract $Stage $metadata.mode
        $hostStream = Open-LockedFile $executable $locks
        if ((Get-StreamSha256 $hostStream) -cne $script:ExpectedHostHash) { throw 'The EXE is not the approved unchanged full-dump PR3 build.' }
        $hostSize = [uint64]$hostStream.Length
        if (-not $ReportRoot) { $ReportRoot = Join-Path ([IO.Path]::GetDirectoryName($packageRoot)) 'reports' }
        if (-not (Test-Path -LiteralPath $ReportRoot)) {
            $reportParent = Resolve-PlainPath ([IO.Path]::GetDirectoryName($ReportRoot)) Directory
            $leaf = [IO.Path]::GetFileName($ReportRoot)
            if ($leaf -notmatch '^[A-Za-z0-9_.-]+$' -or $leaf -eq '.' -or $leaf -eq '..') { throw 'Choose a plain report directory name.' }
            $candidate = Join-Path $reportParent $leaf
            if ((Test-WithinRoot $serverRoot $candidate) -or (Test-WithinRoot $packageRoot $candidate)) { throw 'Reports must stay outside the server and package trees.' }
            $null = [IO.Directory]::CreateDirectory($candidate)
        }
        $reportBase = Resolve-PlainPath $ReportRoot Directory
        if ((Test-WithinRoot $serverRoot $reportBase) -or (Test-WithinRoot $packageRoot $reportBase)) { throw 'Reports must stay outside the server and package trees.' }
        $stamp = [DateTime]::UtcNow.ToString("yyyyMMdd'T'HHmmssfff'Z'", [Globalization.CultureInfo]::InvariantCulture)
        $runDirectory = Join-Path $reportBase ($stamp + '-' + $Stage.ToLowerInvariant() + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        $null = [IO.Directory]::CreateDirectory($runDirectory)
        $rootPathHash = Get-PathSha256 $serverRoot
        $exePathHash = Get-PathSha256 $executable
        Write-Host "Server scan root: $serverRoot"
        Write-Host "Evidence folder: $runDirectory"
        $operation = 'save_package_verification'
        Save-NewText (Join-Path $runDirectory 'package-verification.txt') ("schema=1`r`nversion=0.2.0.0`r`nmode=$($metadata.mode)`r`nstage=$($Stage.ToLowerInvariant())`r`npackage_json_sha256=$($verified.JsonHash)`r`nhost_sha256=$script:ExpectedHostHash`r`ntarget_root_path_sha256=$rootPathHash`r`nexecutable_path_sha256=$exePathHash`r`npath_hash_encoding=normalized_uppercase_utf8`r`npackage_hashes=verified`r`n")
        $manifest = Join-Path $packageRoot 'config\qualified_x3audio_genuine.manifest'
        $report = Join-Path $runDirectory 'inventory.txt'
        if ($Stage -eq 'Stopped') {
            $operation = 'stopped_preflight'
            $arguments = @('--target-root', $serverRoot, '--bootstrap', (Join-Path $packageRoot 'dlls\X3DAudio1_7.dll'),
                '--bootstrap-sha256', $metadata.bootstrap_sha256, '--companion', (Join-Path $packageRoot 'dlls\RS2ServerFix.dll'),
                '--companion-sha256', $metadata.companion_sha256, '--genuine-manifest', $manifest, '--report', $report,
                '--mode', $contract.Mode, '--av-edr-disposition', $AvEdrDisposition, '--wdac-disposition', $WdacDisposition,
                '--applocker-disposition', $AppLockerDisposition, '--eac-disposition', $EacDisposition)
            Invoke-EvidenceTool (Join-Path $packageRoot 'tools\rs2_deployment_preflight.exe') $arguments (Join-Path $runDirectory 'preflight-console.txt')
            $operation = 'own_image_probe'
            $probeArguments = @('--image', (Join-Path $packageRoot 'tools\probe-input.exe'))
            Invoke-EvidenceTool (Join-Path $packageRoot 'tools\rs2_image_protection_probe.exe') $probeArguments (Join-Path $runDirectory 'image-probe.txt')
            Write-Host 'Stopped checks passed. Security states recorded as supplied; not-observed-yet remains unverified.'
        } else {
            $operation = 'identify_running_process'
            if ($ProcessId -eq 0) {
                $entered = Read-Host 'PID of the already running VNGame process'
                if ($entered -cnotmatch '^[1-9][0-9]{0,9}$' -or -not [uint32]::TryParse($entered, [ref]$ProcessId)) { throw 'Enter one nonzero decimal PID.' }
            }
            if ($ProcessId -gt [int]::MaxValue) { throw 'PID exceeds the supported process query range.' }
            $process = [Diagnostics.Process]::GetProcessById([int]$ProcessId)
            try {
                $created = $process.StartTime.ToUniversalTime()
                $livePath = Resolve-PlainPath $process.MainModule.FileName File
                if (-not $livePath.Equals($executable, [StringComparison]::OrdinalIgnoreCase)) { throw 'PID does not name the selected EXE path.' }
                $expectation = $contract.Expectation
                $arguments = @('--pid', [string]$ProcessId, '--target-root', $serverRoot, '--expect', $expectation,
                    '--mode', $contract.Mode, '--expected-recon', $contract.Recon, '--bootstrap-sha256', $metadata.bootstrap_sha256,
                    '--companion-sha256', $metadata.companion_sha256, '--genuine-manifest', $manifest, '--report', $report)
                $operation = 'runtime_inventory'
                Invoke-EvidenceTool (Join-Path $packageRoot 'tools\rs2_runtime_inventory.exe') $arguments (Join-Path $runDirectory 'runtime-console.txt')
                $operation = 'validate_runtime_report'
                $runtime = Convert-StrictFields (Read-BoundedStream (Open-LockedFile $report $locks) (64 * 1024 * 1024))
                Assert-Fields $runtime @{ schema = '1'; mode = 'runtime-inventory'; pid = [string]$ProcessId
                    process_creation_filetime = [string]$created.ToFileTimeUtc(); expect = $expectation; deployment_mode = $contract.Mode
                    host_sha256 = $script:ExpectedHostHash; expected_recon = $contract.Recon; observed_recon = $contract.Recon
                    recon_sha256 = $contract.ReconHash
                    constant_match = 'true'; finding_count = '0'; result = 'pass'
                    tool_sha256 = $verified.Files['tools/rs2_runtime_inventory.exe']
                    manifest_sha256 = $verified.Files['config/qualified_x3audio_genuine.manifest']
                    bootstrap_sha256 = $metadata.bootstrap_sha256; companion_sha256 = $metadata.companion_sha256 }
                $observed = Convert-Utc $runtime['observed_utc']
                if ($observed -lt $created -or $observed -gt [DateTime]::UtcNow) { throw 'Runtime observation timestamp is invalid.' }
                if ($Stage -eq 'Passive' -or $Stage -eq 'Active') {
                    $operation = 'validate_' + $Stage.ToLowerInvariant() + '_marker'
                    if (-not $MarkerPath) { $MarkerPath = Join-Path $exeDirectory ("RS2ServerFix.loader.$ProcessId.log") }
                    $resolvedMarkerPath = Resolve-PlainPath $MarkerPath File
                    $markerLocation = Get-MarkerLocation $resolvedMarkerPath $exeDirectory $ProcessId
                    $markerBytes = Read-BoundedStream (Open-LockedFile $resolvedMarkerPath $locks) 8192
                    Save-NewBytes (Join-Path $runDirectory 'startup-marker.log') $markerBytes
                    $null = Test-PassiveMarker $markerBytes $ProcessId ([IO.Path]::GetFileName($executable)) $hostSize $created $observed $markerLocation $metadata.mode
                    Assert-Fields $runtime @{ observed_bootstrap_sha256 = $metadata.bootstrap_sha256
                        observed_companion_sha256 = $metadata.companion_sha256 }
                }
                $operation = 'recheck_running_process'
                $process.Refresh()
                if ($process.HasExited -or $process.StartTime.ToUniversalTime() -ne $created) { throw 'Process exited or changed during collection.' }
                Write-Host "$Stage automated evidence passed. Console visibility, client join, recon, travel, and shutdown remain operator checks."
            } finally { $process.Dispose() }
        }
        $operation = 'save_check_result'
        Save-NewText (Join-Path $runDirectory 'check-result.txt') ("schema=1`r`nstage=$($Stage.ToLowerInvariant())`r`npid=$ProcessId`r`ntarget_root_path_sha256=$rootPathHash`r`nexecutable_path_sha256=$exePathHash`r`nautomated_evidence=passed`r`nautomated_evidence_scope=package_and_stage_checks_excluding_console`r`nconsole_acceptance=not_verified`r`noperator_acceptance=pending`r`n")
    } catch {
        $failure = $_
        if ($runDirectory) {
            try { Save-FailedCheckRecord $runDirectory $Stage $ProcessId $operation $failure.Exception.Message $rootPathHash $exePathHash }
            catch { Write-Warning 'Could not save check-failure.txt; preserve the existing reports and terminal error.' }
            Write-Host "Incomplete or failed evidence remains in: $runDirectory"
        }
        throw $failure
    } finally {
        foreach ($stream in $locks) { $stream.Dispose() }
    }
}

# Dot-sourcing exposes only the pure parser/path helpers for local own-code tests.
if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-M1RChecks } catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
