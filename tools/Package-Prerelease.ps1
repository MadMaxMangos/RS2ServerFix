param(
    [Parameter(Mandatory=$true)][string]$BuildDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit,
    [Parameter(Mandatory=$true)][string]$RunUrl
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$buildRoot = (Resolve-Path -LiteralPath $BuildDirectory -ErrorAction Stop).Path
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outputRoot) { throw 'Use a new, empty output destination.' }
# Never package a native-enabled reporting build, even if it has the same version.
$cache = Get-Content -LiteralPath (Join-Path $buildRoot 'CMakeCache.txt')
if (@($cache | Where-Object { $_ -ceq 'RS2_RECOVERY_GUARD_PROBE:BOOL=ON' }).Count -ne 1) {
    throw 'Packaging requires the guard-probe build option ON.'
}
$configuredSource = @($cache | Where-Object { $_ -clike 'CMAKE_HOME_DIRECTORY:INTERNAL=*' })
if ($configuredSource.Count -ne 1 -or
    [IO.Path]::GetFullPath($configuredSource[0].Substring('CMAKE_HOME_DIRECTORY:INTERNAL='.Length)) -ine $sourceRoot) {
    throw 'Build directory belongs to a different source tree.'
}
$generatorEntry = @($cache | Where-Object { $_ -clike 'CMAKE_GENERATOR:INTERNAL=*' })
if ($generatorEntry.Count -ne 1) { throw 'Missing build generator identity.' }
$buildGenerator = $generatorEntry[0].Substring('CMAKE_GENERATOR:INTERNAL='.Length)
$guardDll = Join-Path $buildRoot 'diagnostic/guard-probe/Release/RS2ServerFix.dll'
$reconDll = Join-Path $buildRoot 'production/active/Release/RS2ServerFix.dll'
$bootstrap = Join-Path $buildRoot 'production/bootstrap/Release/X3DAudio1_7.dll'
$shortCommit = $Commit.Substring(0,12)
$stage = Join-Path $buildRoot ('prerelease-stage-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage,$outputRoot -ErrorAction Stop | Out-Null

function Copy-PackageFile([string]$From, [string]$Root, [string]$Relative) {
    $dest = Join-Path $Root $Relative
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($dest)) | Out-Null
    Copy-Item -LiteralPath $From -Destination $dest -ErrorAction Stop
}
function Write-Utf8([string]$Path, [string]$Value) {
    [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
}
function Hash([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }

$versions = @{}
foreach ($variant in @('recon','guard-probe')) {
    $dll = if ($variant -eq 'recon') { $reconDll } else { $guardDll }
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($dll).FileVersion
    if ($version -notmatch '^\d+\.\d+\.\d+\.\d+$') { throw 'Missing DLL version.' }
    $versions[$variant] = $version
    $name = "RS2ServerFix-$variant-$version-win64-$shortCommit"
    $package = Join-Path $stage $name
    New-Item -ItemType Directory -Path $package | Out-Null
    Copy-PackageFile $bootstrap $package 'dlls/X3DAudio1_7.dll'
    Copy-PackageFile $dll $package 'dlls/RS2ServerFix.dll'
    Copy-PackageFile (Join-Path $sourceRoot 'LICENSE') $package 'LICENSE'
    Copy-PackageFile (Join-Path $sourceRoot 'config/qualified_x3audio_genuine.manifest') $package 'config/qualified_x3audio_genuine.manifest'
    foreach ($tool in @('rs2_runtime_inventory.exe','rs2_deployment_preflight.exe','rs2_pe_contract.exe')) {
        Copy-PackageFile (Join-Path $buildRoot "Release/$tool") $package "tools/$tool"
    }
    $detail = 'Recon-only active correction. No reporting or Leech recovery functionality is included.'
    if ($variant -eq 'guard-probe') {
        foreach ($leaf in @('RS2SteamReport.ini','RS2LeechRecovery.ini')) {
            Copy-PackageFile (Join-Path $sourceRoot "config/$leaf") $package "config/$leaf"
        }
        $reportConfig = Get-Content -LiteralPath (Join-Path $package 'config/RS2SteamReport.ini') -Raw
        $recoveryConfig = Get-Content -LiteralPath (Join-Path $package 'config/RS2LeechRecovery.ini') -Raw
        if ($reportConfig.Replace("`r`n","`n").Trim() -cne "schema=3`nmode=observe`ndiagnostics=normal") { throw 'Unsafe reporting default.' }
        if ($recoveryConfig.Replace("`r`n","`n").Trim() -cne "schema=1`npermission=disabled`ntraining_root=E:\rs2v_trainingsrv`noperator_sid=none") { throw 'Unsafe recovery default.' }
        foreach ($tool in @('Collect-SteamReport.ps1','Run-SteamReport.cmd','Request-LeechRecovery.ps1','Collect-RS2CountProbe.ps1','RS2CountProbe.cs','Run-RS2CountProbe.cmd')) {
            Copy-PackageFile (Join-Path $sourceRoot "tools/$tool") $package "tools/$tool"
        }
        # This legacy helper pins concrete artifacts. Re-pin only the package copy
        # to the actual outputs; never relax the host/SDK identity requirements.
        $probePath = Join-Path $package 'tools/Collect-RS2CountProbe.ps1'
        $probe = Get-Content -LiteralPath $probePath -Raw
        $pins = @{
            tool = Hash (Join-Path $package 'tools/rs2_runtime_inventory.exe')
            manifest = Hash (Join-Path $package 'config/qualified_x3audio_genuine.manifest')
            bootstrap = Hash (Join-Path $package 'dlls/X3DAudio1_7.dll')
            companion = Hash (Join-Path $package 'dlls/RS2ServerFix.dll')
        }
        foreach ($key in $pins.Keys) {
            $pattern = "(?m)^(\s*$key=)'[0-9A-F]{64}'"
            if ([regex]::Matches($probe,$pattern).Count -ne 1) { throw "Cannot re-pin $key." }
            $probe = [regex]::Replace($probe,$pattern,('${1}' + "'" + $pins[$key] + "'"))
        }
        Write-Utf8 $probePath $probe
        $detail = @'
EXPERIMENTAL READ-ONLY GUARD PROBE. The recovery native calls are compiled out.
Reporting is observe/normal; manual recovery is disabled. Do not enable recovery
or deploy to production from this automated build. This does not establish Steam
outage recovery, browser-count repair, performance or production qualification.
The manual diagnostic remains restricted to E:\rs2v_trainingsrv and requires a
separately authorized test with its configured elevated operator SID.
Keep this extracted kit and its evidence reports outside the server tree.
Run-SteamReport.cmd needs the unchanged complete kit and -AllowedLogRoot when
Launch.log lives outside the server tree. No timing
calibration is supplied, so performance qualification remains inconclusive.
The legacy Run-RS2CountProbe.cmd and Collect-RS2CountProbe.ps1 files are retained
only to satisfy the collector's existing package contract. They are NOT supported
in place in this kit: do not run them, move the manifest, or create reports here.
Use tools/Run-SteamReport.cmd for collection instead.
'@
    }
    $readme = @"
# RS2ServerFix $variant - automated prerelease

DLL version: $version
Source commit: $Commit
Build run: $RunUrl
Build generator: $buildGenerator, x64 Release
Build configuration: guard-probe ON (does not add recovery to recon-only DLLs)

$detail

This is a CI download, not a qualified deployment kit. DLLs are not Authenticode
signed. SHA256SUMS identifies the exact files in this package; the release also
contains SHA256SUMS for the ZIPs. Build versions can repeat, so retain the commit
and file hashes. Never mix files from different packages or overwrite a running
server. Preserve the previous working package for rollback.

For an explicitly approved test only: stop the selected server first; put both
files from dlls beside VNGame.exe. For the guard probe, put RS2SteamReport.ini and
RS2LeechRecovery.ini from config beside the EXE too, not in a config subfolder.
Keep tools and the genuine-module manifest inside this kit. The genuine Windows
X3DAudio1_7.dll and the already qualified game/Steam DLLs must exist separately.
Do not replace system DLLs. Rollback requires stopping the server and restoring
its previous DLLs/configs; hot unloading is not supported.

Cloud checks: recon_transaction, observer_core, reporting_collector,
recovery_control_helper, and bootstrap/active-recon/guard-probe PE contracts.
reporting_core and production-byte/full qualification checks require preserved
proprietary input and are NOT run in cloud CI. No game/Steam DLL, game EXE,
operator evidence, performance calibration or runtime approval is bundled.
ADF crash mitigation is separate and is not included.

Source and full documentation: https://github.com/MadMaxMangos/RS2ServerFix/tree/$Commit
License: GPL-3.0-or-later; see LICENSE.
"@
    Write-Utf8 (Join-Path $package 'README.md') $readme
    $sums = @(Get-ChildItem -LiteralPath $package -File -Recurse | ForEach-Object {
        (Hash $_.FullName) + '  ' + $_.FullName.Substring($package.Length+1).Replace('\','/')
    } | Sort-Object)
    Write-Utf8 (Join-Path $package 'SHA256SUMS') (($sums -join "`n") + "`n")
    Compress-Archive -LiteralPath $package -DestinationPath (Join-Path $outputRoot "$name.zip") -ErrorAction Stop
}
$zipSums = @(Get-ChildItem -LiteralPath $outputRoot -Filter '*.zip' -File | Sort-Object Name | ForEach-Object {
    (Hash $_.FullName) + '  ' + $_.Name
})
Write-Utf8 (Join-Path $outputRoot 'SHA256SUMS') (($zipSums -join "`n") + "`n")
Write-Utf8 (Join-Path $outputRoot 'release-notes.md') @"
Automated Windows x64 prerelease for source commit $Commit.
Build and test log: $RunUrl

- Recon-only DLL: $($versions['recon']).
- Experimental read-only guard-probe DLL: $($versions['guard-probe']).
- Reporting defaults to observe; manual recovery disabled; native-enabled recovery is NOT published.
- Separate ZIPs contain DLLs, matching configs/tools, instructions, license and file checksums.
- Proprietary game/Steam DLLs and private evidence are excluded.
- Public CI runs seven independent checks. reporting_core and production-byte qualification remain local because they require preserved proprietary input.
- Not production qualification, deployment permission, or proof of outage/browser-count recovery. ADF mitigation is separate.
- Verify the ZIP SHA-256 against the attached SHA256SUMS; versions alone do not identify the build.
"@
Write-Host "Packaged two prerelease ZIPs in $outputRoot"
