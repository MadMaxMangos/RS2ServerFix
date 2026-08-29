# RS2 Two-DLL Passive Loader Design

Date: 2026-08-22

Revised: 2026-08-29 for reviewed safety fixes, current-build evidence, and the bootstrap/companion split

Stage: 0 - loader, companion initialization, diagnostics, and forwarding proof only

## Goal

Prove on an offline harness and then a user-operated disposable server copy that:

1. a minimal AMD64 `faultrep.dll` bootstrap can be selected through the server's existing load-time import;
2. it can resolve, validate, and publish genuine `System32\faultrep.dll!ReportFault` without doing loader work on the crash path;
3. after genuine forwarding is available, it can load an explicitly named companion `RS2ServerFix.dll` from the bootstrap directory and call one versioned initialization export outside loader-lock context;
4. the companion can identify the host and write privacy-minimal diagnostics without changing game memory or any existing file; and
5. both added files can be removed while the process is stopped to restore the original System32 path.

Stage 0 contains no game hook, detour, byte patch, allocator change, ADF mutation, anti-cheat interaction, deliberate crash, or server deployment by Codex.

## Why two DLLs

`faultrep.dll` is a fragile load-time compatibility boundary. Keeping it limited to Windows crash-report forwarding and one explicit companion call reduces the code that can prevent process startup or run near an exceptional path.

`RS2ServerFix.dll` owns build identification, marker output, and all future mitigation code. It is loaded dynamically after genuine `ReportFault` is published. A missing or rejected companion therefore disables only our optional functionality; the bootstrap remains able to forward Windows crash reporting. Future mitigation releases can replace the companion while the stable bootstrap contract remains unchanged.

The cost is a two-file deployment and rollback. Stage 0 tests partial installations explicitly.

## Evidence and fixed inputs

Historical crash lineage:

- crash-producing/full-dump PR1 SHA-256:
  `155EBC77D2FA574F0A94709839EF1DF6A3DA82B278C846F14223967B058C4622`
- preserved stock PR1 SHA-256:
  `5820F0DA82D7C2903DE31E0865320D9E70A0BF74F78F83C83DB4F9DEEAEB1DEF`
- the files differ at dump-type offset `0x00a6a313` (`0x40` to `0x42`) plus PE checksum offset `0x000001e1` (`0x39` to `0x3b`).

Newly shipped/current lineage, locally labelled PR3 after processing on another VM:

- current stock SHA-256:
  `F4E38510832D1FAADA8AAD3B88CD2255B3EA49267EF0E874468E23BDE4EDFCC3`
- current full-dump-modified SHA-256:
  `0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393`
- the files differ at dump-type offset `0x00a6bb43` (`0x40` to `0x42`) plus PE checksum offset `0x000001e1` (`0xf7` to `0xf9`).

Loader evidence:

- both examined executables are AMD64 and import named `ReportFault` from `faultrep.dll`;
- the PR1 crash dump captured `Faultrep.dll` from System32;
- `dinput8.dll` was neither imported nor loaded by PR1;
- `faultrep.dll` was not listed as a KnownDLL on the examined host, but the actual target is rechecked by the static-import harness and loaded-module path;
- the existing server-directory `dbghelp.dll` participates in full-dump handling and must not be altered, proxied, or imported by either new DLL;
- the SDK declares `EFaultRepRetVal APIENTRY ReportFault(LPEXCEPTION_POINTERS, DWORD)`;
- the examined System32 DLL exports named `ReportFault` at ordinal 13; the server imports by name, so the name is the hard contract.

The patched historical executable is no longer present at its former analysis path. Tests may derive a temporary copy from the preserved stock file using the two verified byte changes and must reproduce its exact SHA-256 without altering the stock input. Both current-lineage files are present under `D:\Documents\RisingStorm2\Binaries`.

## Windows constraints

- `DllMain` runs while the loader lock is held. It must not call `LoadLibrary`, wait for another thread, hash files, write diagnostics, or invoke the companion.
- `CreateThread` from `DllMain` is documented as risky but workable if there is no synchronization with the created thread. The host exposes no safer explicit initialization callback, so the bootstrap performs one non-joined `CreateThread` and tests the exact load-time scenario.
- `InitOnceExecuteOnce` is synchronous and blocks competing callers. It is not used.
- `ReportFault` may run in a process with corrupt heap/stack state. The exported path must be allocation-free, lock-free, loader-free, file-free, and log-free.
- A bad local load-time `faultrep.dll` can prevent process creation. There is no promised System32 fallback after Windows selects an invalid local file.
- Both DLLs use static CRT. Microsoft says not to call `DisableThreadLibraryCalls` from a static-CRT DLL, so neither DLL calls it.
- A fully qualified path identifies a distinct same-basename module, but both the System32 DLL and companion are still validated by module, file, and function identity before use.

Primary references:

- [Dynamic-Link Library Best Practices](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices)
- [DllMain entry point](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain)
- [Dynamic-Link Library Search Order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [LoadLibraryEx](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw)
- [DisableThreadLibraryCalls](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-disablethreadlibrarycalls)
- [ReportFault](https://learn.microsoft.com/en-us/windows/win32/api/errorrep/nf-errorrep-reportfault)

## Scope

Stage 0 delivers:

1. minimal AMD64 bootstrap `faultrep.dll`;
2. AMD64 companion `RS2ServerFix.dll`;
3. one shared versioned POD initialization ABI;
4. worker-only validated System32 resolution and crash-path forwarding;
5. explicit companion-path construction, validation, loading, and initialization;
6. historical/current SHA-256 build identity with fail-closed unknown states;
7. UTF-8 privacy-minimal marker plus debug milestones;
8. unit, PE-contract, static-import, partial-installation, and deployment-preflight tests;
9. manual disposable-server control/proxy/rollback instructions.

## Non-goals

Stage 0 will not:

- alter either server executable or any shipped DLL/configuration;
- alter, rename, proxy, or import local `dbghelp.dll`;
- hook or inspect ADF/game/player/Steam/EOS/EAC/network/mutator state;
- suppress or evade anti-cheat or integrity controls;
- inject remotely or load into a client;
- deploy to a production/public server;
- deliberately call genuine `ReportFault` with fabricated exception data;
- guarantee forwarding in the brief interval before worker resolution;
- treat any known hash as automatically eligible for a later ADF patch.

## Binary contracts

### Bootstrap `faultrep.dll`

- AMD64 native DLL, output filename exactly `faultrep.dll`;
- Release `/MT`, Debug `/MTd`;
- direct imports limited to `KERNEL32.dll`;
- no CNG, diagnostics formatting, companion static import, `dbghelp.dll`, managed, network, shell, COM, dynamic Visual C++ runtime, user TLS, or dynamic global constructor;
- `/DYNAMICBASE`, `/NXCOMPAT`, `/HIGHENTROPYVA`;
- one public export: named `ReportFault`, also assigned observed ordinal 13 without `NONAME`;
- no `DisableThreadLibraryCalls`.

### Companion `RS2ServerFix.dll`

- AMD64 native DLL, output filename exactly `RS2ServerFix.dll`;
- Release `/MT`, Debug `/MTd`;
- direct imports limited to `KERNEL32.dll` and `bcrypt.dll`;
- no `dbghelp.dll`, managed, network, shell, COM, dynamic Visual C++ runtime, user TLS, or dynamic global constructor;
- `/DYNAMICBASE`, `/NXCOMPAT`, `/HIGHENTROPYVA`;
- one public export: named `RS2ServerFix_InitializeV1`;
- user `DllMain` always returns `TRUE` and performs no work;
- no worker thread of its own and no `DisableThreadLibraryCalls`.

If either built image has an unexpected dependency/export, its PE contract test fails. The allowlist is investigated rather than silently expanded.

No build/install/test target copies either DLL outside repository build directories or unique system-temporary test directories.

## Shared initialization ABI

Both DLLs compile this exact C-compatible contract from one header:

```cpp
constexpr std::uint32_t kBootstrapAbiVersion = 1;

struct BootstrapContextV1 {
    std::uint32_t size;
    std::uint32_t abiVersion;
    HMODULE hostModule;
    HMODULE bootstrapModule;
    HMODULE genuineFaultrepModule;
    FARPROC genuineReportFault;
    std::uint32_t resolverStatus;
    DWORD resolverError;
};

static_assert(sizeof(BootstrapContextV1) == 48);

using InitializeV1Fn = DWORD(WINAPI*)(const BootstrapContextV1* context);
```

The bootstrap sets `size=48`, `abiVersion=1`, passes `GetModuleHandleW(nullptr)` as host, its saved `hinstDLL`, and the genuine module/function/status evidence. The companion validates size/version/non-null host/bootstrap before doing work.

Initialization return values are stable `DWORD` constants:

```text
0 = initialized
1 = already initialized
2 = invalid context
3 = host identity failed
4 = marker write failed
```

The companion uses a zero-initialized interlocked state (`0` unstarted, `1` running, `2` finished) so duplicate calls never run initialization concurrently and never wait.

## Runtime architecture

### Bootstrap `DllMain`

On `DLL_PROCESS_ATTACH` only:

1. store `hinstDLL` in a zero-initialized POD global;
2. call `CreateThread` once with the module handle as parameter;
3. close a successful thread handle without waiting;
4. return `TRUE` regardless of worker creation.

All thread/detach notifications perform no user work. There is no load, file access, formatting, debug output, CRT call, synchronization wait, cleanup, or `FreeLibrary` in user `DllMain`.

### Bootstrap worker order

The one worker performs a non-retrying sequence:

1. emit a leaf-name/status-only debug milestone;
2. resolve and validate genuine System32 `ReportFault`;
3. atomically publish a validated non-null pointer, or leave it null permanently;
4. derive the bootstrap directory and absolute `RS2ServerFix.dll` path;
5. load and validate the companion;
6. call `RS2ServerFix_InitializeV1` once with `BootstrapContextV1`;
7. emit terminal status and return.

Publishing genuine forwarding precedes all companion work. No companion failure causes a retry or clears a published genuine pointer.

The 32,768-character path and marker scratch workspaces are obtained with
`VirtualAlloc` only on the bootstrap worker/companion initializer and released
before return. They are never placed in the host thread's stack frame and are
never touched by exported `ReportFault`.

### Genuine reporter resolution

The worker:

1. builds bounded absolute `System32\faultrep.dll` using `GetSystemDirectoryW`;
2. calls `LoadLibraryExW(path, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)`;
3. rejects null or `candidate == bootstrapModule`;
4. obtains candidate path;
5. compares the expected and candidate files by volume serial plus file index, not path string;
6. resolves named `ReportFault` and rejects null;
7. calls `VirtualQuery` and rejects query failure or allocation base equal to the bootstrap;
8. publishes only after all validation succeeds.

Rejected non-null candidate references are released on the worker. A successful reference is retained until process termination so the published pointer cannot dangle. No name-only load/handle call finds the genuine module.

### Companion loading

The worker derives its own module path into a 32,768-wide-character bounded buffer, removes only the final leaf component, and appends exact leaf `RS2ServerFix.dll` after capacity checks.

It calls:

```cpp
LoadLibraryExW(
    absoluteCompanionPath,
    nullptr,
    LOAD_LIBRARY_SEARCH_SYSTEM32);
```

The full path selects the companion; the flag restricts its dependencies to System32. Stage 0 permits no local dynamic dependency.

Validation requires:

- non-null module distinct from bootstrap and genuine System32 module;
- candidate file identity equal to the explicitly constructed companion file;
- named `RS2ServerFix_InitializeV1` export present;
- successful `VirtualQuery` whose allocation base equals the candidate module, so forwarded initializers are rejected.

Only then is the ABI context passed. A validated/called companion reference is retained until process exit even if initialization returns a failure code, avoiding unload after partial initialization. Candidates rejected before the call are released.

Missing, malformed, wrong-architecture, wrong-file, missing-export, or initialization-return failure leaves genuine crash forwarding intact and is reported only through bounded debug milestones or a partial companion marker when one was produced.

### Exported `ReportFault`

The export atomically reads one function pointer with an interlocked operation. If null, it immediately returns documented `frrvErrNoDW`; otherwise it calls the genuine function with both original arguments and returns its result unchanged.

It performs no lazy resolution, companion call, allocation, lock, load, file access, logging, hashing, SEH swallowing, or retry. Behavioral x64 ABI fidelity is required; a compiler tail call is not.

### Companion initialization

The companion's exported initializer:

1. validates context pointer, size, ABI version, resolver fields, and module handles;
2. atomically claims its non-waiting initialization state;
3. verifies `context->hostModule == GetModuleHandleW(nullptr)`;
4. resolves the host executable path;
5. hashes it with SHA-256 using CNG and a 64 KiB `VirtualAlloc` buffer;
6. classifies build identity;
7. writes one marker beside the executable, with one temporary-directory fallback;
8. emits terminal debug status;
9. marks initialization finished and returns a stable result.

Hashing opens with all three share flags and `FILE_FLAG_SEQUENTIAL_SCAN`, uses a 10-second soft budget checked between reads, and distinguishes:

- `pr1-crash-full-dump`;
- `pr1-stock-baseline`;
- `current-stock`;
- `current-full-dump`;
- `unknown` (valid different digest);
- `indeterminate` (path/read/CNG/time failure).

These identify builds only. Stage 0 never patches any identity.

### Marker and privacy

Marker name:

```text
RS2ServerFix.loader.<pid>.log
```

The companion attempts the executable directory once, then `GetTempPathW` once. It creates no directory and has no retry loop.

UTF-8 schema version 1 contains only:

- schema version and UTC timestamp;
- process ID;
- executable leaf name, size, SHA-256 if valid, and build identity;
- bootstrap/companion leaf names and same-directory booleans;
- genuine resolver status/error and `system32`/`unavailable` classification;
- initialization result and primary marker error if fallback was required;
- terminal `completion=complete` or `completion=partial` line written last.

It excludes full paths, username/account identifiers, command line, environment values, network addresses, tokens, player/exception/memory data. A truncated file lacks the terminal record and fails tests.

## Lifetime and failure behavior

Production bootstrap lifetime is guaranteed by the server's load-time import. Tests run in fresh processes and never call `FreeLibrary` while a worker can execute. The successful genuine and companion references remain until process termination.

Process exit may briefly wait if the worker is inside a loader operation. Normal tests wait for terminal marker before child exit. No detach handler waits or frees modules.

| Failure | Required result |
|---|---|
| Companion present without bootstrap | Ignored; server uses System32 exactly as before. |
| Bootstrap absent | Server uses System32 exactly as before. |
| Invalid bootstrap/wrong bootstrap bitness/dependency | Windows may fail process creation; preflight must prevent deployment. |
| Bootstrap worker creation | Process continues; target remains null; no companion/marker; early fault returns `frrvErrNoDW`. |
| Genuine reporter validation | Target remains null; companion may still report resolver failure; no retry. |
| Early `ReportFault` | Immediate `frrvErrNoDW`; no initialization attempt. |
| Companion absent/load/identity/export | Published genuine forwarding remains; no companion functionality; no retry. |
| Companion initializer returns failure | Published forwarding remains; companion stays mapped; partial marker/debug status when possible. |
| Host hash fails | Build identity `indeterminate`; forwarding unaffected. |
| Marker primary fails | One temporary-directory attempt. |
| Both marker writes fail | Debug status only; initializer returns marker failure. |
| Process termination | No explicit cleanup; OS tears down mappings/handles. |

Neither DLL shows UI, performs network access, edits existing files, recursively calls `ReportFault`, or attempts recovery of game state.

## Test strategy

All tests use repository build directories and unique system-temporary directories.

### Unit tests

1. all four known hashes plus unknown/indeterminate identity;
2. fixed SHA-256 fixture and both stock files;
3. temporary derived full-dump copies reproduce both expected hashes while stock files remain unchanged;
4. bounded path construction and file identity, including hard-link/same-file and different-file cases;
5. genuine resolver failures: self module, wrong identity, null export, failed `VirtualQuery`, self address;
6. companion loader failures: self/genuine module, wrong identity, null export, forwarded/wrong allocation base;
7. atomic forwarder null/stub semantics and argument fidelity;
8. initialization ABI size/version and duplicate non-waiting claim;
9. marker schema, fallback, short write, terminal record, and forbidden-content scan;
10. no Stage 0 build identity permits patch behavior.

### Built-PE contracts

Parse both outputs and fail unless machine/DLL/security flags, exports, and direct-import allowlists match their separate contracts. Parse the static harness and require named `faultrep.dll!ReportFault`, not ordinal import.

Ordinal 13 is reported for bootstrap compatibility but named export is the hard gate.

### Static-import process cases

Each case runs in a fresh unique temporary directory; no real `ReportFault` call occurs:

1. **System control:** harness only; System32 module must load.
2. **Companion only:** harness plus `RS2ServerFix.dll`; System32 still loads and no companion marker appears.
3. **Bootstrap only:** harness plus `faultrep.dll`; local bootstrap loads and child process remains healthy despite missing companion.
4. **Both files:** local bootstrap loads, marker proves genuine System32 validation and companion initialization.
5. **Invalid companion:** local bootstrap plus malformed companion; child still starts and forwarding bootstrap stays loaded, with no valid complete marker.
6. **Invalid bootstrap:** malformed local `faultrep.dll`; process creation or loader termination must fail, proving no fallback claim.
7. **Rollback:** remove both while no child runs; System32 control succeeds again.

The harness does not unload modules. The runner disables critical-error UI and bounds child waits.

### Deployment preflight

A read-only scanner examines the exact user-selected deployment tree, without following directory reparse points, and records every PE machine plus all `faultrep.dll` imports. It fails on malformed PE extensions, incompatible `faultrep` importers, ordinal-only/unexpected required exports, or executable `.local` redirection.

Another VM's file list is contextual only; the disposable target must be scanned directly.

## Disposable-server procedure

Codex prepares but does not execute deployment.

### Control

1. User selects a stopped disposable server copy with no public players.
2. Confirm no local `faultrep.dll`, `RS2ServerFix.dll`, executable `.local`, or prior marker.
3. Run deployment preflight and retain its report.
4. Record AV/EDR, WDAC, and AppLocker disposition for both unsigned DLLs.
5. Capture recursive listing and hashes for executable, `dbghelp.dll`, configurations, and root PE files.
6. Start using the normal command, verify Steam/EOS/EAC/network/map/WebAdmin initialization, capture logs, then stop normally.

### Two-file pass

1. While stopped, copy the exact tested `RS2ServerFix.dll` and `faultrep.dll` beside the executable.
2. Start with identical command/environment.
3. Require loaded local bootstrap plus complete marker proving genuine System32 resolution, companion file identity/ABI, and host identity.
4. Compare services and logs against control.
5. Observe idle operation for a pre-agreed bounded period.
6. Stop normally, capture identical listing/hash manifest, and diff. No existing file may differ.

### Rollback

1. Confirm process stopped.
2. Remove both added DLLs and marker files.
3. Restart once and prove System32 `faultrep.dll` plus normal initialization.
4. Retain control/pass/rollback logs, manifests, preflight report, and both tested DLL hashes.

Any startup failure, security intervention, incompatible importer, missing/partial marker, genuine/companion validation failure, service regression, integrity change, shutdown hang, or rollback failure stops Stage 0.

## Success criteria

Stage 0 succeeds only when:

- all unit, two-image PE-contract, static-import/partial-installation, and preflight tests pass in Release AMD64;
- bootstrap contains no crash-path initialization and companion is not a static dependency;
- control/companion-only/rollback cases use System32;
- bootstrap-only and malformed-companion cases keep the child process healthy;
- both-file case proves local bootstrap, genuine System32 target, companion ABI, marker privacy, and correct host identity;
- exact disposable tree has no incompatible importer/redirection;
- disposable control/pass/rollback completes with all expected services;
- pre/post hashes prove no existing executable, `dbghelp.dll`, configuration, or shipped DLL changed;
- artifacts are limited to two manually placed DLLs plus diagnostic evidence;
- no client, public player, production server, deliberate crash, anti-cheat bypass, or game-memory patch is involved.

## Later ADF stage

A separate reviewed design may place the mitigation exclusively in `RS2ServerFix.dll`. Current required direction remains:

- current executable independently analyzed and exact-hash gated;
- pack-wide single-flight guard;
- index/state/count/raw-length/cycle/visit/destination validation;
- fail-closed abort and diagnostics;
- no live free-list reconstruction;
- original-byte validation, concurrency testing, and independent rollback.

Stage 0 proves only the two-DLL loader boundary. It does not prove a later hook safe.
