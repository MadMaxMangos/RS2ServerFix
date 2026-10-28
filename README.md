# RS2ServerFix

Targeted crash fixes and diagnostic tools for **Rising Storm 2: Vietnam dedicated servers**.

RS2ServerFix loads alongside the Windows 64-bit server, validates the executable
and startup state, and applies a narrowly scoped correction in memory. It keeps
the existing server launch command and does not rewrite the executable on disk.

This is an independent community project, not an official Tripwire Interactive
release. It is not a general performance patch or a fix for every server crash.

For the dated operator-trial status and outstanding investigations, see the
[28 October update for Tripwire Interactive](reference/TWI-STATUS-2026-10-28.md).
The update distinguishes prepared trial kits from published source and releases.

## What is implemented

Recon-only builds remain **0.2.0.0**. The separate, experimental Steam observer
companion is **0.3.0.0** and requires its own qualified trial package.
Steam reporting and manual Leech recovery use the **0.7.1.0 experimental target**.
The source includes manual WebAdmin control, compact operational diagnostics,
schema-2 bot-tolerant admission, valid idle-heartbeat error-history acceptance
and the r3 metadata observation window of 45 seconds.
It retains the earlier recon and native reporting admission corrections, without
replacing advertised counts or changing authentication. Memory, ownership and
lifecycle safeguards remain in force. The default configuration observes reporting
and disables manual recovery. Healthy training trials have completed native Leech
session replacement while players remained connected. The latest bot-inclusive
trial exposed a metadata deadline/cadence mismatch; the r3 correction still needs
its own runtime trial. Recovery after an actual Steam outage remains unproven;
this is not a generally qualified production release.

- **Recon crash correction** — the `recon-exclusive-scale-v1` fix, guarded by an
  exact executable hash, expected instruction bytes and startup checks.
- **Passive mode** — performs qualification without applying the recon correction.
- **Startup diagnostics** — a console status line and a per-process
  `RS2ServerFix.loader.<PID>.log` marker identifying the build, mode and outcome.
- **Verification tools** — PE/import checks, deployment preflight, runtime module
  inventory and isolated startup/rollback fixtures.

The optional observer records selected Steam calls the server already makes,
their synchronous results and coverage/loss counters. It adds no SDK calls,
ticket reads, authentication changes or reconnects. **It does not repair Steam
browser counts or registrations, and does not bypass anti-cheat checks.** Local
inert tests are not live-server qualification; use one controlled trial first.

## How it loads

| File | Purpose |
| --- | --- |
| `X3DAudio1_7.dll` | Startup bootstrap; forwards audio exports to the genuine system DLL and invokes the companion at the qualified startup point. |
| `RS2ServerFix.dll` | Build verification, diagnostics and the passive or active recon implementation. |

Both files sit beside the server executable in `Binaries\Win64`. The genuine
64-bit `X3DAudio1_7.dll` must already be available in the Windows system directory.
Do not replace a Windows system DLL with this project's bootstrap, or overwrite
another existing local proxy without checking compatibility.

The companion is retained until process exit. Rollback is performed with the
server stopped, by removing this project's two DLLs or restoring the previous
known-good package. Hot unloading is not supported.

## Compatibility and deployment

The active production profile currently targets one **PR3 full-dump-patched
Win64 executable**, identified by this SHA-256:

```text
0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393
```

The filename alone does not establish compatibility. Other builds may be
recognized by the inventory tools without being supported by the recon fix.
The full-dump executable modification is separate; these DLLs do not create it,
and proprietary game executables or SDK DLLs are not distributed here.

For a first recon-only deployment (experimental variants require their own
matched configuration and separately authorized trial):

1. Verify the executable and DLL package identities. Preserve the current files
   and use a test server or a planned maintenance window.
2. Stop the selected server before installing the matched bootstrap and companion.
   Choose the passive or active companion deliberately; both use the same filename.
3. Start with the existing command line. Check the console and the loader marker;
   a successful load is not, by itself, proof that the correction is active.
4. Confirm normal client joining, recon behaviour, map travel and shutdown before
   broader use. Keep the previous package available for rollback.

Ordinary qualification failures leave the recon correction disabled. If a failed
memory change cannot be safely rolled back, the implementation terminates startup
instead of continuing with an uncertain patch state. Test the package with your
own Windows, hosting and security-software environment; static checks are not a
guarantee of runtime compatibility.

The `Check-*.cmd` operator wrappers in [tools](tools/) expect a complete verified
test package, including its metadata and built utilities. A source checkout alone
is not that package.

## Building from source

### Automatic prerelease downloads

Every push to `main` runs the [Windows build workflow](.github/workflows/prerelease.yml).
After its seven public CI checks pass, it publishes two separate ZIPs under
[Releases](https://github.com/MadMaxMangos/RS2ServerFix/releases): recon-only and
the experimental read-only guard probe. Manual workflow runs on `main` are also
supported. Each release is a prerelease, never the stable/latest release, and is
bound to its source commit and workflow run. No server is deployed or restarted.

Each ZIP contains this project's DLLs, matching tools/configuration, instructions,
license and file checksums. The release has a separate ZIP checksum list. Versions
can repeat across commits: identify a build by commit and hashes, not version alone.
These DLLs are not Authenticode signed. The guard-probe config observes reporting
and disables manual recovery; the native-enabled recovery variant is not published.
Game/Steam DLLs, proprietary EXEs, private evidence and performance calibration are
excluded. Preserve the qualified game/Steam files already on your server.

Public CI runs recon transactions, observer fixtures, collector/helper tests and
the three published DLL PE contracts. It does not run `reporting_core` or the full
production-byte qualification suite because those require preserved proprietary
inputs. Successful CI is not runtime approval, a production-qualified trial kit,
or proof of browser-count repair. Keep the extracted guard-probe kit and collected
reports outside the server tree; its collector requires the intact package manifest
and matching utilities. Use only under a separately approved test procedure.
Use `Run-SteamReport.cmd` for kit collection. The legacy CountProbe files remain
only for manifest compatibility and are not supported in place in these ZIPs.

### Local builds

Requirements: Windows x64, an AMD64 MSVC C++ toolchain with the Windows SDK and
MASM, CMake 3.24 or newer, and Ninja for the commands below.

From an **x64 MSVC developer shell**, in the repository root:

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target rs2_x3daudio_bootstrap rs2_server_fix_companion rs2_server_fix_companion_active
```

The DLLs are written under:

```text
build/production/bootstrap/Release/X3DAudio1_7.dll
build/production/passive/Release/RS2ServerFix.dll
build/production/active/Release/RS2ServerFix.dll
```

The optional observer target is `rs2_server_fix_companion_observer`, producing
`build/production/observer/Release/RS2ServerFix.dll`. It retains the active recon
correction and requires `RS2SteamObserve.ini` beside the companion:

```ini
enabled=1
max_log_mib=512
```

Keep this small config comment-free. Results require a plain local fixed-drive
server path; UNC/mapped/removable/reparse paths are not supported. The observer
also declines copy-on-write IAT pages before any mutation because Windows cannot
restore their original protection exactly after writing; recon remains active.

Its initial Steam SDK1.57 disk identity is
`A44E5537939AE4EEBC69000589AA9B2437A667813A1657CC779198BAE9B815A9`.
Do not replace your SDK to force a match. Missing/invalid config or unsupported
identity disables observation without changing recon. Require separate armed,
bound and calls-observed notices before relying on a capture. Logs can lose events
or reach their configured cap; a quiet log does not prove an idle server.

Results are in `RS2SteamObserve` beside the EXE. Steam IDs are HMAC-pseudonymised;
the private key remains separately in `RS2SteamObserveKeys`. The packaged
`Run-SteamObserve.cmd` collector verifies identities and copies only allowlisted
results, never that key store. Do not publicly upload keys or full memory dumps.
Rollback restores the previous recon-only DLLs with the server stopped; no hot unload.

### Experimental native advertisement recovery

`rs2_server_fix_companion_reporting` produces
`build/production/reporting/Release/RS2ServerFix.dll`. It retains active recon and
uses the existing bootstrap and launch command. It preserves native player/bot
counting, authentication, anti-cheat decisions and publication scheduling.

The first isolated trial uses the supplied [reporting config](config/RS2SteamReport.ini)
beside the companion:

```ini
schema=3
mode=observe
diagnostics=normal
```

`RS2SteamObserve.ini` is no longer a reporting prerequisite. Do not mix this
config or the V3 tools with an older reporting DLL. The standalone 0.3 observer
and recon-only 0.2 M1R checker retain their separate contracts.
Observe makes no count-request or full-publication selection writes. Only a later
separately approved `mode=repair` trial may request fresh native counts and select
full data on already-scheduled native publications. This is not proof of Steam
registration repair or backend/browser recovery.

In the earlier 0.4.1 isolated repair trial, local safety, functional coverage and
per-call latency checks passed. Measured wrapper overhead was approximately
1.32-1.35 ms per second, exceeding the original strict 1 ms/s budget; the
performance result remains **FAIL**. Limited staged field trials are an explicit
operator risk decision, not a reclassification of that result. Full-server load
and browser-count recovery following an actual Steam outage remain unproven.

V3 reporting submits bounded structured `[RS2ServerFix:event]` records through
the qualified native logger into the actual server `Launch.log`, including an
`-ABSLOG` destination. Keep `-FORCELOGFLUSH`. There is no new reporting JSONL
directory, quota, private key, rotation or retention subsystem. This does not
move the game's logger off the engine thread: native logging and its console
mirror remain synchronous. Normal diagnostics use a ten-second anchor/summary
cadence plus state, request and builder events; detailed diagnostics use one
second. `diagnostics=operational` uses compact records and 60-second anchors,
with full detail around recovery. Operational logs are status evidence, not
performance/coverage qualification evidence; the collector rejects that mode for
qualification. Output is limited to eight native frames per second, not one per tick.

A read-only receipt worker verifies that submitted events reached the same log
file. Missing logger qualification or temporary receipt/credit pressure visibly
waits or pauses reporting and its repair admission; a real lost/corrupt record,
changed/truncated file or unsafe native profile permanently closes that admission.
Native forwarding and the separate recon result remain unchanged. Full structured
events are retained in Launch.log; the game's console mirror may truncate them.
Short `[RS2SteamReport]` notices report waiting, ready, pause, resume or disabled
states through a separate bounded console worker. The per-PID recon loader marker
still uses its original location and format.

The matched V3 `Run-SteamReport.cmd` reads current DATA before requesting logs and
collects a fixed five-minute window. When Launch.log is outside the server tree,
it requires an explicit permitted log root. It copies at most 512 MiB from the
run's original log offset, including unrelated game lines; this is a collection
limit, not a log retention limit. Missing history or a pause cannot yield a false
coverage pass. Archived evidence requires an explicit log path and saved DATA
from that same file identity. Local safety, coverage, measured performance,
operator smoke, client effect and outage recovery have separate verdicts. Missing
timing calibration or insufficient evidence cannot produce a qualification PASS.
Use only a reviewed, checksum-bound package and its deployment instructions.
The repository configuration defaults to observe; repair requires an explicit
deployment decision. A source checkout or a successful build is not a qualified
deployment package. Proprietary Steam DLLs and private operator bundles are not
included in this repository.

### Manual Leech recovery and the read-only guard probe

Leech is the game's native backend integration, distinct from Steam's query
responder. The in-game browser can replace Steam query counts with values from a
Leech backend record. Correct WebAdmin or Steam query counts therefore do not,
by themselves, establish a correct in-game browser count.

Manual Leech recovery uses a different mechanism from reporting `mode=repair`:
it submits a Finish for the old standalone server session, waits for a matched
successful response, then follows the native cleanup/Start/Create path. It checks
for a different session ID, publication into the game's session cache, and a fresh
heartbeat binding. It does not restart the server, disconnect players, reset
Steam authentication, or implement an automatic Tuesday-outage recovery loop.

The retained 0.6.2.0 r5 corrections establish four native guard contracts: the cached session ID
is a narrow `std::string`; a stable core GUID supplies lifetime identity while
authorization tokens may rotate; valid retained Finish slots can be reused by
the native allocator; and an unchanged public-IP value may move allocations.
Cache fingerprints now hash narrow initialized bytes excluding NUL, so older
UTF-16 cache fingerprints are not comparable across revisions.

Manual recovery is separate from the reporting `mode=repair` setting above. It
defaults to disabled in [RS2LeechRecovery.ini](config/RS2LeechRecovery.ini), which
must be placed beside the EXE, not in a `config` subfolder. The current
schema-1 configuration retains the original `E:\rs2v_trainingsrv` restriction.
Schema 2 binds an explicitly configured fixed-drive server root and operator SID;
it requires reporting `mode=observe`. It permits a manual pilot without changing
native counting or authentication. Each explicit pipe request uses the matched
[Request-LeechRecovery.ps1](tools/Request-LeechRecovery.ps1) helper and authenticates
the configured operator SID through the named pipe. The server and helper must
run as that same elevated administrator account. File permission changes are
not required by this control mechanism. The INI is trusted local configuration;
the root and SID checks identify this server and account, not the file's author.
A request transmission alone does not
establish admission, native completion or browser repair.

The optional schema-2 `console_trigger=server-admin` registers
`rs2leech status` and `rs2leech recover <run token>` for WebAdmin's management
console. It ships disabled. The console route trusts existing WebAdmin admin
privileges and local configuration; **it does not authenticate the Windows
operator and does not protect against local file writers**. The visible run token
checks deliberate, current-process intent; it is not an authentication credential.
Only the qualified WebAdmin reply path can claim recovery. Local and in-game
console output classes are not supported by this adapter. Pipe and console share
one request at a time and one native recovery recipe per process. Schema 2 may
release the claim after a fully recorded preflight rejection that entered no
native recipe or resource operation. Status retains the rejection reason and
shows `retry=yes`; a later explicit request may use either route and gets a new
operation number. **Do not resend a request while it is pending.** No automatic
retry occurs, and a rejection after any native recipe entry stays spent. A bad
pipe request can close that opportunity even without claiming the latch. A wrong
console token does not claim it. Disable the opt-in after the pilot window.

`diagnostics=operational` keeps compact structured records in the existing
`Launch.log`, uses 60-second routine anchors, and temporarily retains full detail
around recovery. Normal and detailed diagnostics remain available for controlled
captures. Operational logs are not collector qualification evidence: the collector
refuses that mode even with archive or training-recovery options. Preserve the raw
log and use a fresh normal/detailed run for qualification.

The pilot preserves native counts, including PI counts above capacity and the
native bot count. Schema 2 supports bots; schema 1 retains its original two-human,
zero-bot training policy. Both require zero spectators and retain exact
source/lifetime guards. Joins or actor-array changes during recovery can cause a
refusal requiring restart. Start with a low-population affected server. A successful
native callback, publication or metadata check is not proof of browser repair.

An inactive schema-2 configuration is shown below. The repository's supplied
schema-1 default also disables recovery. SID-free hosting support remains a
separate follow-up; the SID is configuration, not a hard-coded account identity.

```ini
schema=2
permission=disabled
server_root=E:\rs2v_trainingsrv
operator_sid=none
console_trigger=disabled
```

For a controlled trial, use the reviewed, checksum-bound kit. To build the
read-only guard variant from source, use a separate directory and supply the
preserved, hash-matched full-dump EXE as a data input:

```powershell
cmake -S . -B build-leech-probe -G Ninja -DCMAKE_BUILD_TYPE=Release `
  -DRS2_RECOVERY_GUARD_PROBE=ON `
  "-DRS2_CURRENT_FULLDUMP_PATH=C:/evidence/VNGame_pr3.exe"
cmake --build build-leech-probe --target rs2_server_fix_companion_reporting rs2_reporting_tests rs2_pe_contract
ctest --test-dir build-leech-probe -C Release `
  -R '^(reporting_core|pe_reporting_companion_contract)$' --no-tests=error --output-on-failure
```

Replace the example evidence path with your preserved input. The probe DLL is
under `build-leech-probe/diagnostic/guard-probe/Release`; its recovery native call
sites are compiled out. A build with `RS2_RECOVERY_GUARD_PROBE=OFF` uses
`production/reporting/Release` and can perform the native sequence only after
explicit configuration and its authorized pipe or WebAdmin request route. Both variants retain
FileVersion 0.7.1.0; distinguish them by their build setting and artifact hashes.
Use tools and configuration from the same verified trial package. A local rebuild
does not reproduce the kit's artifact hashes or inherit its package qualification.
Public prereleases remain recon-only or read-only guard-probe variants.
Native-enabled recovery requires a separately authorized operator trial; building
or publishing its source does not qualify it for populated public-server deployment.

#### Controlled healthy-server result (22 October 2026)

One native-enabled r5 trial completed the Finish/Create/publication/rebind sequence
in approximately **1.31 seconds**. Two Steam players remained connected and
stationary, without rejoining or changing maps; WebAdmin continued to show two.
The operator observed the in-game browser change from zero to one, then back to
two players after a catch-up delay estimated at about a minute. Exact end-to-end
browser latency was not measured. Backend propagation, player reassociation and
browser caching have not been separated as causes of that delay.

This demonstrates native session replacement and eventual browser convergence on
a healthy training server, **not recovery from a real Steam outage**. The local
terminal outcome `PublishedNotDelivered` is not a backend delivery receipt or
proof of client session adoption. Repeated post-recreation `PreparedMismatch`
diagnostics remain under investigation; they must not be dismissed simply because
the displayed count eventually became correct. The trial does not establish
full-server performance, automatic recovery or production qualification.

The probe's reason 63 / Inconclusive records snapshot and pre-submit admission
only; a timeout without that result does not prove admission. A native-enabled
attempt can fail irreversibly and require an operator restart. Native completion,
subsequent cache publication, client adoption and actual browser-count repair
need separate runtime evidence. ADF crash mitigation is not included here.

The r5 source archive (SHA-256
`98B01A306DE199B3C3B3299CBFE43E6C9B46CDFDC88D0E2CD7A4827E772DEAA5`)
passed the existing active and probe `reporting_core` checks (20,185 and 18,475
assertions, zero failures) and both companion PE contracts. The r4-to-r5 guard
correction review and source-custody checks closed with no blocking or important
findings; that was not a fresh review of the entire source tree. These local
results do not establish live recovery or production qualification.

#### Bot-inclusive trial and metadata window (28 October 2026)

The 0.7.1.0 r2 healthy training trial retained two Steam players with native
PI=32, bots=30 and maximum=32. Raw records confirm successful Finish/Create,
changed SDK/cache session fingerprints, local publication about 0.94 seconds
after request pickup and a fresh heartbeat binding. The operator reported correct
browser/WebAdmin counts. This did not reproduce maintenance-outage damage.

The local metadata follow-up timed out at about publication+30 seconds, before
the first recorded normal builder at +30.17 seconds. A coherent prepared snapshot
was observed at about +31.6 seconds. The explicit follow-up metadata Update was
not attempted. The source now includes r3's **45-second metadata window**, still
capped by the **120-second overall attempt deadline** and its existing margin.
Late publication can shorten the available window. The correction preserves the
existing native Update gates and one native recovery opportunity per process.
The changed native recipe and WebAdmin route require operator-run training
qualification before an outage pilot. The r3 window needs a new bot-inclusive
training trial; local coherence, backend delivery
and client/browser adoption remain separate observations.

Full qualification testing also requires locally supplied, preserved executable
inputs. Set the CMake cache paths `RS2_PR1_BASELINE_PATH`,
`RS2_CURRENT_STOCK_PATH`, `RS2_CURRENT_FULLDUMP_PATH`, and
`RS2_OBSERVER_SDK_BASELINE_PATH` to the matching evidence files before building all
test targets and running (the SDK path is read as data, never executed):

```powershell
cmake --build build
ctest --test-dir build -C Release --output-on-failure
```

The suite uses local fixtures and read-only production-byte evidence. Passing it
does not establish gameplay, Steam backend or anti-cheat compatibility on a live
server. See [the retained profile evidence](tests/evidence/README.md) for the
scope of the static checks.

## Investigation reference

The [9 October failure catalogue](reference/leech-reference-2026-10-09/FAILURE-CATALOGUE.md)
and its five directly named Markdown documents preserve the bounded Leech/ADF
findings. They are historical analysis, not implemented fixes or current release
qualification. Referenced raw evidence and other private notes are not published.

## Reporting problems and contributing

[Open an issue](https://github.com/MadMaxMangos/RS2ServerFix/issues) with the project
version, build variant and DLL SHA-256, Windows version, executable SHA-256,
relevant INI modes and loader/reporting/recovery status. Include reproduction
steps and whether removing the package
restores the previous behaviour.

Do not post full memory dumps, authentication material, unredacted player data
or proprietary binaries publicly. Review logs before sharing them.

Contributions should keep fixes small, build-specific and reversible, preserve
existing behaviour outside the intended correction, and include evidence and
checks appropriate to the change.

## License

**GNU General Public License v3.0 or later (`GPL-3.0-or-later`).**

RS2ServerFix is free software: you may redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later version.
It is distributed without any warranty, including the implied warranties of
merchantability or fitness for a particular purpose. See [LICENSE](LICENSE) for
the full terms.

This license applies to this project's original code. Rising Storm 2, Steam/EOS
and Windows components remain subject to their respective owners' licenses.
