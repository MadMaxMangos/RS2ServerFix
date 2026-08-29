# RS2 Stage 0 Disposable-Server Test and Rollback

Status: operator procedure only. Codex has not copied either DLL to a game or
server directory and has not launched a server. Stage 0 is a passive loader
proof; it contains no game hook, ADF change, deliberate crash, or anti-cheat
bypass.

Use only a stopped, disposable server copy with no public players. Do not use a
production server or a client machine.

## Files under test

The only deployable files are the exact Release artifacts that passed the full
offline suite:

- `faultrep.dll` — bootstrap and `ReportFault` forwarder.
- `RS2ServerFix.dll` — passive Stage 0 companion and marker writer.

Do not rename, rebuild, edit, sign, compress, or substitute either file between
offline verification and this test. Record their hashes before continuing:

```powershell
$ArtifactRoot = 'D:\Documents\RisingStorm2\RS2ServerFix\.worktrees\two-dll-stage0\build-verify\Release'
$BootstrapSource = Join-Path $ArtifactRoot 'faultrep.dll'
$CompanionSource = Join-Path $ArtifactRoot 'RS2ServerFix.dll'

Get-FileHash -Algorithm SHA256 -LiteralPath $BootstrapSource, $CompanionSource |
    Format-Table Path, Hash -AutoSize
Get-AuthenticodeSignature -LiteralPath $BootstrapSource, $CompanionSource |
    Format-Table Path, Status, StatusMessage -AutoSize
```

The expected signing disposition is whatever was recorded during review. If
AV/EDR, WDAC, AppLocker, or another security control blocks or quarantines an
artifact, stop. Preserve the alert and policy evidence; do not disable or evade
the control and do not add an exclusion merely to force the test through.

## Operator variables and evidence directory

Set these for the disposable copy. `$ServerExe` must name the executable that
will actually be launched; the two DLLs are placed beside it. Keep the evidence
directory outside the server tree.

```powershell
$ServerExe = 'E:\serverone\Binaries\Win64\VNGame\_pr1.exe'
$ExeDir = Split-Path -Parent $ServerExe
$ConfigRoot = 'D:\Documents\RisingStorm2\Server1\Config'
$Preflight = 'D:\Documents\RisingStorm2\RS2ServerFix\.worktrees\two-dll-stage0\build-verify\Release\rs2_deployment_preflight.exe'
$EvidenceRoot = Join-Path 'D:\Documents\RisingStorm2\Stage0-Evidence' (Get-Date -Format 'yyyyMMdd-HHmmss')
$ObservationMinutes = 10 # agree and record this before the control run

New-Item -ItemType Directory -Path $EvidenceRoot -ErrorAction Stop | Out-Null
$LocalBootstrap = Join-Path $ExeDir 'faultrep.dll'
$LocalCompanion = Join-Path $ExeDir 'RS2ServerFix.dll'

if ([IO.Path]::GetExtension($ServerExe) -ine '.exe') {
    throw 'ServerExe must identify the actual PE executable, including .exe'
}
```

If the disposable VM uses a different root or executable name, change only the
variables. Do not infer its contents from the file list collected on another
VM.

Before every copy or removal, confirm that no process is running from
`$ServerExe`. Use an elevated 64-bit PowerShell if module enumeration requires
it:

```powershell
$running = Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path -ieq $ServerExe }
if ($running) { throw "Server is still running: PID $($running.Id -join ',')" }
```

## Integrity manifest helper

This records every existing file beneath the affected executable directory,
plus the selected configuration tree. Stage 0 files and its PID marker are
excluded from the comparison and retained separately as evidence.

```powershell
function Write-Stage0Manifest {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $OutputDirectory
    )

    $roots = @($ExeDir)
    if (Test-Path -LiteralPath $ConfigRoot -PathType Container) {
        $roots += $ConfigRoot
    }

    $files = foreach ($root in $roots) {
        Get-ChildItem -LiteralPath $root -File -Recurse -Force |
            Where-Object {
                $_.FullName -ine $LocalBootstrap -and
                $_.FullName -ine $LocalCompanion -and
                $_.Name -notlike 'RS2ServerFix.loader.*.log'
            }
    }

    $files |
        Sort-Object -Property FullName -Unique |
        ForEach-Object {
            $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName
            [pscustomobject]@{
                Path = $_.FullName
                Length = $_.Length
                LastWriteTimeUtc = $_.LastWriteTimeUtc.ToString('o')
                SHA256 = $hash.Hash
            }
        } |
        Export-Csv -NoTypeInformation -Encoding UTF8 `
            -LiteralPath (Join-Path $OutputDirectory "$Name-hashes.csv")

    foreach ($root in $roots) {
        Get-ChildItem -LiteralPath $root -Recurse -Force |
            Select-Object FullName, Length, Attributes, LastWriteTimeUtc |
            Export-Csv -NoTypeInformation -Encoding UTF8 `
                -LiteralPath (Join-Path $OutputDirectory `
                    "$Name-$([IO.Path]::GetFileName($root))-listing.csv")
    }
}
```

At minimum, confirm that this manifest covers the launched executable, every
`dbghelp.dll` below the selected roots, all configuration files, and every EXE
or DLL beside the executable.

## Phase 1 — clean control

1. Confirm the disposable server is stopped and has no public players.

2. Prove that no Stage 0 file, prior marker, or executable redirection already
   exists:

```powershell
if (Test-Path -LiteralPath $LocalBootstrap) { throw 'Pre-existing local faultrep.dll' }
if (Test-Path -LiteralPath $LocalCompanion) { throw 'Pre-existing RS2ServerFix.dll' }
if (Get-ChildItem -LiteralPath $ExeDir -Filter 'RS2ServerFix.loader.*.log' -File -Force) {
    throw 'Pre-existing Stage 0 marker'
}
if (Get-ChildItem -LiteralPath $ExeDir -Filter '*.exe.local' -Force) {
    throw 'Executable .local redirection is present'
}
```

3. Scan the exact disposable deployment tree and retain the report. Exit code
   must be zero, every `faultrep.dll` importer must be AMD64 and import only the
   named `ReportFault`, and no malformed PE or executable `.local` artifact may
   be reported. Inspect the TSV and require an `IMPORT` row for the launched
   `$ServerExe`; a zero-importer report means the wrong tree or executable was
   selected:

```powershell
& $Preflight $ExeDir 2>&1 |
    Tee-Object -LiteralPath (Join-Path $EvidenceRoot 'preflight.tsv')
$preflightExit = $LASTEXITCODE
if ($preflightExit -ne 0) { throw "Preflight failed: $preflightExit" }
```

4. Record AV/EDR product and policy state, WDAC/AppLocker enforcement state,
   Windows version, server executable hash, and both artifact hashes in the
   evidence directory. Do not continue while a security alert is unresolved.

5. Capture the baseline manifest:

```powershell
Write-Stage0Manifest -Name 'before-control' -OutputDirectory $EvidenceRoot
```

6. Start the server using its normal account, working directory, environment,
   launcher, and command. The command supplied for the original server was:

```text
E:\serverone\Binaries\Win64\VNGame\_pr1.exe VNTE-CuChi?mutator=IDBanMutator.IDBanMutator,TKLMutatorv2.TKLMutatorv2,XPFixesMutator.XPFixesMutator,SeedMutator.SeedMutator?bIsDedicated=True?WebAdminPort=8080 -DEDICATED -USEALLAVAILABLECORES -UNATTENDED -SEEKFREELOADINGSERVER -NOINNEREXCEPTION -NOPAUSE -ABSLOG=E:\Server\_Logs\Server1Voting\Launch\Launch.log -WebAdminPort=8080 -FORCELOGFLUSH
```

   On a differently rooted disposable copy, use its established launcher and
   change only the executable/log paths that must differ. Preserve all gameplay
   URL parameters, mutator order, switches, service account, and environment.

7. Record the server PID and loaded modules. The control must show the
   System32 `faultrep.dll`, no local `faultrep.dll`, and no
   `RS2ServerFix.dll`:

```powershell
$ServerPid = Read-Host 'Enter the disposable server PID'
$process = Get-Process -Id $ServerPid -ErrorAction Stop
$process.Modules |
    Where-Object { $_.ModuleName -in @('faultrep.dll', 'RS2ServerFix.dll') } |
    Select-Object ModuleName, FileName, FileVersionInfo |
    Format-List * |
    Out-File -Encoding UTF8 -LiteralPath `
        (Join-Path $EvidenceRoot 'control-modules.txt')
```

8. Capture and verify the same observable service set that will be checked in
   the two-file pass:

   - Steam initialization/session registration;
   - EOS status if present in this server build, otherwise record not
     applicable from the control;
   - EAC initialization/status without changing its policy;
   - game TCP/UDP listeners and clientless query response;
   - `VNTE-CuChi` map fully loaded;
   - WebAdmin port 8080 and its normal authentication page/status;
   - absence of new loader, security, crash, or repeated retry errors.

   Useful read-only snapshots include:

```powershell
Get-NetTCPConnection -OwningProcess $ServerPid -ErrorAction SilentlyContinue |
    Sort-Object LocalPort |
    Format-Table -AutoSize |
    Out-File -Encoding UTF8 -LiteralPath (Join-Path $EvidenceRoot 'control-tcp.txt')
Get-NetUDPEndpoint -OwningProcess $ServerPid -ErrorAction SilentlyContinue |
    Sort-Object LocalPort |
    Format-Table -AutoSize |
    Out-File -Encoding UTF8 -LiteralPath (Join-Path $EvidenceRoot 'control-udp.txt')
Test-NetConnection -ComputerName 127.0.0.1 -Port 8080 |
    Out-File -Encoding UTF8 -LiteralPath (Join-Path $EvidenceRoot 'control-webadmin.txt')
```

9. Observe idle operation for exactly `$ObservationMinutes`, capture CPU,
   private bytes, handles, threads, listener state, and the normal server log,
   then stop through the server's normal shutdown path. Do not terminate it to
   save time. A shutdown hang is a stop condition.

10. Confirm the process is gone and retain the control log. Do not proceed if
    any required service failed in the control; the pass would not be
    comparable.

## Phase 2 — two-file passive pass

1. Reconfirm the server is stopped. Copy the exact verified files without
   `-Force`; reject any pre-existing destination immediately before copying:

```powershell
if (Test-Path -LiteralPath $LocalBootstrap) { throw 'Local faultrep.dll now exists' }
if (Test-Path -LiteralPath $LocalCompanion) { throw 'Local RS2ServerFix.dll now exists' }
Copy-Item -LiteralPath $BootstrapSource -Destination $LocalBootstrap -ErrorAction Stop
Copy-Item -LiteralPath $CompanionSource -Destination $LocalCompanion -ErrorAction Stop

$sourceHashes = Get-FileHash -Algorithm SHA256 -LiteralPath `
    $BootstrapSource, $CompanionSource
$placedHashes = Get-FileHash -Algorithm SHA256 -LiteralPath `
    $LocalBootstrap, $LocalCompanion
if ($sourceHashes[0].Hash -ne $placedHashes[0].Hash -or
    $sourceHashes[1].Hash -ne $placedHashes[1].Hash) {
    throw 'Placed DLL hash mismatch'
}
$placedHashes | Export-Csv -NoTypeInformation -Encoding UTF8 `
    -LiteralPath (Join-Path $EvidenceRoot 'placed-dll-hashes.csv')
```

2. Start with the identical normal command, account, working directory,
   environment, map, and mutator order used by the control. Do not deliberately
   crash the process.

3. Record the new PID and enumerate modules. Require all three mappings:

   - local `$ExeDir\faultrep.dll` bootstrap;
   - genuine `%SystemRoot%\System32\faultrep.dll` target retained by the
     bootstrap;
   - local `$ExeDir\RS2ServerFix.dll` companion.

```powershell
$ServerPid = Read-Host 'Enter the two-file pass server PID'
$process = Get-Process -Id $ServerPid -ErrorAction Stop
$stage0Modules = $process.Modules |
    Where-Object { $_.ModuleName -in @('faultrep.dll', 'RS2ServerFix.dll') } |
    Select-Object ModuleName, FileName
$stage0Modules | Format-Table -AutoSize |
    Out-File -Encoding UTF8 -LiteralPath `
        (Join-Path $EvidenceRoot 'pass-modules.txt')
```

4. Require exactly one PID marker beside the executable and copy it to the
   evidence directory:

```powershell
$Marker = Join-Path $ExeDir "RS2ServerFix.loader.$ServerPid.log"
$deadline = (Get-Date).AddSeconds(15)
while (-not (Test-Path -LiteralPath $Marker) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 100
}
if (-not (Test-Path -LiteralPath $Marker -PathType Leaf)) {
    throw 'PID marker missing'
}
$markerText = Get-Content -Raw -LiteralPath $Marker
$markerText | Out-File -Encoding UTF8 -LiteralPath `
    (Join-Path $EvidenceRoot "pass-marker-$ServerPid.txt")
```

   Require all of these records and require `completion=complete` to be the
   final record:

```text
schema=1
pid=<the pass PID>
executable=<the launched executable leaf name>
sha256=<the independently measured server executable SHA-256>
bootstrap=faultrep.dll
bootstrap_beside_executable=true
companion=RS2ServerFix.dll
companion_beside_executable=true
resolver_status=ok
resolver_error=0
genuine_module=system32
initialize_result=0
primary_write_error=0
completion=complete
```

   Compare the marker SHA-256 to `Get-FileHash $ServerExe`; do not rely only on
   the friendly `build_identity` label. A missing, partial, duplicated, or
   mismatched marker stops the test. Successful companion identity and ABI
   validation are prerequisites to reaching its initializer and producing this
   complete marker.

5. Repeat the Steam/EOS/EAC, listener, map, WebAdmin, error-log, and resource
   snapshots from the control. Compare them directly; do not excuse a missing
   service merely because the process remains alive.

6. Observe idle operation for the same `$ObservationMinutes`. No players or
   bots are required for Stage 0, because this pass proves only load behavior.
   It does not test or claim to fix the ADF crash.

7. Stop normally. Confirm shutdown duration and behavior match the control,
   then verify the process is gone.

8. Capture and compare the post-pass integrity manifest:

```powershell
Write-Stage0Manifest -Name 'after-pass' -OutputDirectory $EvidenceRoot
$before = Import-Csv -LiteralPath (Join-Path $EvidenceRoot 'before-control-hashes.csv')
$after = Import-Csv -LiteralPath (Join-Path $EvidenceRoot 'after-pass-hashes.csv')
$integrityDiff = Compare-Object $before $after `
    -Property Path, Length, LastWriteTimeUtc, SHA256
$integrityDiff | Export-Csv -NoTypeInformation -Encoding UTF8 `
    -LiteralPath (Join-Path $EvidenceRoot 'integrity-diff.csv')
if ($integrityDiff) { throw 'An existing tracked file changed' }
```

## Phase 3 — rollback proof

1. Confirm the pass process is fully stopped. Copy the marker and pass log to
   `$EvidenceRoot` before deleting anything.

2. Re-hash the two local DLLs and require that they still equal the tested
   artifact hashes. Then remove only these exact added files and the Stage 0
   marker files:

```powershell
$localHashes = Get-FileHash -Algorithm SHA256 -LiteralPath `
    $LocalBootstrap, $LocalCompanion
if ($localHashes[0].Hash -ne $sourceHashes[0].Hash -or
    $localHashes[1].Hash -ne $sourceHashes[1].Hash) {
    throw 'Refusing rollback: local DLL hash no longer matches tested artifact'
}

Remove-Item -LiteralPath $LocalBootstrap -ErrorAction Stop
Remove-Item -LiteralPath $LocalCompanion -ErrorAction Stop
Get-ChildItem -LiteralPath $ExeDir -Filter 'RS2ServerFix.loader.*.log' -File |
    Remove-Item -ErrorAction Stop

if (Test-Path -LiteralPath $LocalBootstrap) { throw 'faultrep.dll rollback failed' }
if (Test-Path -LiteralPath $LocalCompanion) { throw 'RS2ServerFix.dll rollback failed' }
```

   These removals are recoverable from the exact hashed Release artifacts and
   copied marker evidence. Do not recursively delete anything.

3. Start the server once more with the identical normal command. Require normal
   Steam/EOS/EAC/network/map/WebAdmin initialization, System32
   `faultrep.dll`, no local bootstrap, no companion, and no new Stage 0 marker.

4. Stop normally and retain the rollback module list, full server log, service
   snapshots, shutdown timing, and final integrity manifest.

## Mandatory stop conditions

Stop Stage 0 immediately and preserve evidence for any of the following:

- startup or loader failure;
- AV/EDR, WDAC, AppLocker, EAC, or other security intervention;
- preflight reports a malformed PE, non-AMD64 `faultrep` importer, ordinal or
  unexpected `faultrep` import, executable `.local` redirection, or incomplete
  scan;
- local bootstrap, genuine System32 module, companion, host hash, file identity,
  or ABI evidence is missing or inconsistent;
- marker is missing, partial, duplicated, malformed, written only to fallback,
  or does not end with `completion=complete`;
- Steam/EOS/EAC, network listeners, map, WebAdmin, logging, or resource behavior
  regresses relative to control;
- any existing tracked executable, DLL, `dbghelp.dll`, configuration, or other
  manifest file changes;
- normal shutdown hangs or requires forced termination;
- either DLL cannot be removed while stopped, System32 loading is not restored,
  a marker reappears after rollback, or any rollback verification fails.

Do not advance to an ADF mitigation, hook, public-player test, production
deployment, deliberate crash, or anti-cheat exception from this procedure. Those
require a separate reviewed design and authorization.

## Evidence to retain

Retain together:

- full offline Release test transcript and PE-contract output;
- SHA-256 hashes of both tested DLLs and the server executable;
- direct preflight TSV from the exact disposable target;
- AV/EDR, WDAC, AppLocker, EAC, OS, and service-account disposition;
- control/pass/rollback command lines, environment notes, PIDs, module listings,
  listener/WebAdmin snapshots, complete logs, and shutdown timing;
- the original complete PID marker;
- before/after/rollback listings, hash manifests, and empty integrity diff;
- the final proof that neither local DLL nor any marker remains.

Only the operator performs this procedure. Codex prepared and verified the
offline artifacts and instructions but did not deploy either DLL or launch the
server.
