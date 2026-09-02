# RS2 Passive X3Audio Bootstrap Design

Date: 2026-09-02

Stage: Milestone 1 - native loader, genuine API forwarding, companion
initialization, diagnostics, and rollback proof only

Status: Draft for Claude Opus 5 Max and user review

## Goal

Provide a reversible, zero-EXE-edit way for the Rising Storm 2 dedicated server
to load `RS2ServerFix.dll` at process startup while preserving the genuine
Windows X3Audio behavior.

Milestone 1 succeeds only if an offline harness and then a user-operated
disposable server prove that:

1. Windows selects a local AMD64 `X3DAudio1_7.dll` bootstrap through VNGame's
   existing normal import;
2. the bootstrap resolves and validates the genuine
   `System32\X3DAudio1_7.dll` and both public X3Audio exports;
3. calls to both exports preserve the exact ABI, arguments, return value, and
   output behavior;
4. the bootstrap loads an explicitly named `RS2ServerFix.dll` companion only
   outside loader-lock context;
5. the companion identifies the host and writes one privacy-minimal marker
   without changing game memory or any existing protected binary or
   configuration file; and
6. removing the two added DLLs while the process is stopped restores the
   original System32 load path.

Milestone 1 contains no game hook, detour, EasyHook load, allocation-system
change, logging offload, relevancy change, EOS/EAC interception, executable
patch, deliberate crash, or production deployment.

## Selected architecture

The selected architecture keeps the existing two-DLL split:

```text
VNGame.exe
  -> normal PE import: X3DAudio1_7.dll!X3DAudioInitialize
  -> local X3DAudio1_7.dll bootstrap
       -> validated System32 X3DAudio1_7.dll
       -> RS2ServerFix.dll!RS2ServerFix_InitializeV2
```

`X3DAudio1_7.dll` owns only genuine X3Audio resolution/forwarding and one
asynchronous companion initialization attempt. `RS2ServerFix.dll` owns build
identification, the marker, and all future functionality. A missing or rejected
companion disables only optional RS2ServerFix behavior; genuine X3Audio
forwarding remains available.

The bootstrap and companion are separate because the bootstrap is a fragile
load-time compatibility boundary. Future instrumentation or mitigation must
not expand its import surface or make genuine X3Audio depend on companion
success.

## Why X3Audio is selected

Evidence tied to the current RS2 server files shows:

- current stock VNGame SHA-256:
  `F4E38510832D1FAADA8AAD3B88CD2255B3EA49267EF0E874468E23BDE4EDFCC3`;
- current full-dump VNGame SHA-256:
  `0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393`;
- both current files have the same normal, non-delay import of named
  `X3DAudio1_7.dll!X3DAudioInitialize`;
- the examined server directory contains no local `X3DAudio1_7.dll`;
- the production dump resolved it from
  `C:\Windows\System32\X3DAudio1_7.dll` even on a sound-disabled dedicated
  server;
- the captured module and examined genuine file agree on PE timestamp
  `0x4B6B06BE`, image size 36,864, and checksum `0x00008C0D`;
- the examined genuine file is AMD64, Microsoft-signed, version
  `9.28 (DXSDK_FEB10.100204-0932)`, and SHA-256
  `9460709339701AD471A5CABE6365355F4D586DC4FCB86507C1331839DC555446`;
- it exports only named `X3DAudioCalculate` at ordinal 1 and named
  `X3DAudioInitialize` at ordinal 2;
- `X3DAudio1_7.dll` is not in the examined host's KnownDLL registry set; and
- a contextual scan of 96 of 99 loaded-module equivalents found no second
  module importing that basename.

The desktop System32 hash is evidence, not a universal deployment allowlist.
The disposable target's genuine module must be inspected and recorded on that
host.

## Rejected loader alternatives

### Existing `faultrep.dll` bootstrap

Do not deploy it. The captured process loads `SHCore.dll`, whose delay-import
table requires `faultrep.dll!ReportCoreHang`. The existing proxy exports only
`ReportFault`, so occupying the process-wide basename can break a later
SHCore delay resolution. The old Stage 0 implementation remains a source of
tested path, identity, companion, marker, and harness patterns only.

### Unique `rs2boot.dll` import edit

This avoids process-wide basename collision and remains the safest design if a
second executable edit is acceptable. It is not selected because the approved
milestone specifically requires zero additional VNGame modification.

### `EOSSDK-Win64-Shipping.dll` proxy

VNGame normally imports 79 EOS exports, including 20 anti-cheat client/server
functions. A forwarding proxy is mechanically possible, but it would replace
an Epic-signed module at the authentication, sanctions, and EAC boundary. SDK
export surfaces also change between releases. This is unnecessary loader and
operational risk for Milestone 1.

### TBB and EasyHook files

The server depot contains `tbbmalloc.dll`, `tbbmalloc_debug.dll`, and
`EasyHook64.dll`, but the current VNGame has no direct/delay import or ASCII or
UTF-16 filename reference to them. None was loaded in the production dump.
EasyHook may be considered later as a hook engine loaded by the companion, but
neither file is a native bootstrap for this dedicated executable.

## Fixed Windows and ABI constraints

- The bootstrap is server-only and must never be deployed to a client or
  editor.
- `DllMain` executes under loader lock. It must not call `LoadLibrary`, wait,
  hash, write a marker, invoke the companion, or resolve X3Audio.
- The one worker created from `DllMain` is never joined or waited on by
  `DllMain`.
- Both DLLs use the static CRT. Neither calls `DisableThreadLibraryCalls`.
- The genuine module is located by a bounded absolute System32 path, never a
  name-only load or handle lookup.
- Runtime validation uses module path, file identity, export presence, and
  export allocation base. Authenticode validation is a preflight concern so
  the bootstrap retains a minimal import surface.
- A successful genuine-module reference and successful companion reference
  remain held until process exit.
- No code catches or suppresses exceptions raised inside genuine X3Audio.
- No export records diagnostics or calls the companion.

The SDK header at the selected build toolchain defines:

```cpp
typedef BYTE X3DAUDIO_HANDLE[20];

HRESULT STDAPIVCALLTYPE X3DAudioInitialize(
    UINT32 speakerChannelMask,
    FLOAT32 speedOfSound,
    X3DAUDIO_HANDLE instance);

void STDAPIVCALLTYPE X3DAudioCalculate(
    const X3DAUDIO_HANDLE instance,
    const X3DAUDIO_LISTENER* listener,
    const X3DAUDIO_EMITTER* emitter,
    UINT32 flags,
    X3DAUDIO_DSP_SETTINGS* settings);
```

The proxy compiles against the installed Windows SDK `x3daudio.h`; it does not
copy or hand-maintain the SDK structures. AMD64 calling convention and the two
named exports plus their observed ordinals are hard PE contracts.

## Binary contracts

### Bootstrap `X3DAudio1_7.dll`

- AMD64 native DLL; output filename exactly `X3DAudio1_7.dll`;
- Release `/MT`, Debug `/MTd`;
- direct imports limited to `KERNEL32.dll` plus unavoidable API-set expansion
  accepted only after inspection;
- no direct or delay import of `X3DAudio1_7.dll`, `RS2ServerFix.dll`,
  `dbghelp.dll`, EOS, EasyHook, TBB, shell, COM, network, CNG, WinTrust, or a
  dynamic Visual C++ runtime;
- no user TLS, dynamic global constructor, UI, network, config parser, or game
  symbol/address table;
- `/DYNAMICBASE`, `/NXCOMPAT`, and `/HIGHENTROPYVA`;
- exactly two public exports:
  `X3DAudioCalculate @1` and `X3DAudioInitialize @2`, both exported by name;
- no `DisableThreadLibraryCalls`.

### Companion `RS2ServerFix.dll`

- AMD64 native DLL; output filename exactly `RS2ServerFix.dll`;
- Release `/MT`, Debug `/MTd`;
- direct imports limited to `KERNEL32.dll` and `bcrypt.dll` unless a reviewed
  PE-contract change proves another dependency necessary;
- no `dbghelp.dll`, EOS, EasyHook, TBB, managed, network, shell, COM, dynamic
  Visual C++ runtime, user TLS, or dynamic global constructor;
- `/DYNAMICBASE`, `/NXCOMPAT`, and `/HIGHENTROPYVA`;
- exactly one public export: `RS2ServerFix_InitializeV2`;
- user `DllMain` always returns `TRUE` and performs no work;
- no worker thread of its own in Milestone 1.

No build, install, or test target copies either DLL outside repository build
directories or unique system-temporary test directories.

## Genuine X3Audio resolution

### One permanent resolution result

The bootstrap owns one zero-initialized `INIT_ONCE` and one static dispatch
record containing:

```cpp
struct X3AudioDispatch {
    HMODULE module;
    X3DAudioInitializeFn initialize;
    X3DAudioCalculateFn calculate;
    GenuineResolverStatus status;
    DWORD win32Error;
};
```

The init-once callback performs the only genuine resolution attempt and returns
success to `InitOnceExecuteOnce` even when validation fails. That publishes a
permanent success or permanent failure record and prevents retry storms or a
partially published function table.

Both the bootstrap worker and both public exports call the same
`EnsureGenuineX3Audio` function. If they race, `InitOnceExecuteOnce` serializes
them. Export calls occur after normal process import/DllMain completion in the
supported VNGame flow; no design claim permits a caller to invoke these exports
from its own `DllMain`.

### Resolution and validation sequence

The init-once callback:

1. allocates its 32,768-character path workspace with `VirtualAlloc`;
2. obtains the System32 directory with `GetSystemDirectoryW`;
3. appends exact leaf `X3DAudio1_7.dll` with bounded arithmetic;
4. calls `LoadLibraryExW` with the absolute path and
   `LOAD_LIBRARY_SEARCH_SYSTEM32`;
5. rejects null or `candidate == bootstrapModule`;
6. obtains the candidate's actual module path;
7. compares expected and candidate file identity using volume serial and file
   index;
8. resolves both named exports;
9. applies `VirtualQuery` to both function addresses;
10. requires both allocation bases to equal the candidate module and not the
    bootstrap;
11. publishes the complete dispatch record only after all checks pass; and
12. retains the successful candidate module to process exit.

Rejected non-null candidates are released after a permanent failure record is
prepared. The temporary workspace is always released. Resolution does not load
the companion or write diagnostics.

## Export behavior

### `X3DAudioInitialize`

The export obtains the permanent dispatch record. On success it calls the
genuine function once with the original arguments and returns the exact
`HRESULT` unchanged.

On resolver failure it returns `HRESULT_FROM_WIN32(win32Error)` when a nonzero
Win32 error exists, otherwise `E_FAIL`. It performs no partial initialization
and does not fabricate a handle.

### `X3DAudioCalculate`

The export obtains the same permanent dispatch record. On success it calls the
genuine function once with the original pointers and flags and returns after
the genuine call.

The function has no error return. If the genuine dispatch is unavailable, the
proxy invokes `RaiseFailFastException` rather than returning with undefined or
partially written DSP outputs. This behavior is covered by a fresh-process
failure test. It is not expected on an eligible system because genuine
resolution is a deployment precondition.

Both exports are free of companion calls, file writes, logging, hashing,
game-memory access, retries, and exception swallowing.

## Bootstrap lifetime and worker

On `DLL_PROCESS_ATTACH`, user `DllMain` only:

1. stores `hinstDLL` in a zero-initialized POD global;
2. calls `CreateThread` once with the module handle as its parameter;
3. closes a successful thread handle without waiting; and
4. returns `TRUE` regardless of worker creation.

Other notifications perform no user work.

The worker performs one non-retrying sequence:

1. calls `EnsureGenuineX3Audio`;
2. atomically observes the final resolver record;
3. constructs the absolute sibling path to `RS2ServerFix.dll`;
4. validates, loads, and calls `RS2ServerFix_InitializeV2` once;
5. returns without unloading a successful genuine or companion module.

Worker-creation failure disables companion initialization, but it does not
disable lazy genuine resolution by a later X3Audio export call. The bootstrap
does not create another worker from an export.

## Shared initialization ABI V2

V1 is faultrep-specific and must not be reinterpreted. The X3Audio bootstrap
and companion compile one new C-compatible context:

```cpp
constexpr std::uint32_t kBootstrapAbiVersion = 2;

struct BootstrapContextV2 {
    std::uint32_t size;
    std::uint32_t abiVersion;
    HMODULE hostModule;
    HMODULE bootstrapModule;
    HMODULE genuineX3AudioModule;
    FARPROC genuineX3AudioInitialize;
    FARPROC genuineX3AudioCalculate;
    std::uint32_t resolverStatus;
    DWORD resolverError;
};

static_assert(sizeof(BootstrapContextV2) == 56);

using InitializeV2Fn = DWORD(WINAPI*)(const BootstrapContextV2*);
```

The companion validates exact size/version, non-null host/bootstrap, resolver
status range, and all-or-none consistency of genuine module and both function
pointers. It verifies `hostModule == GetModuleHandleW(nullptr)` before hashing.

Initialization return values remain stable:

```text
0 = initialized
1 = already initialized
2 = invalid context
3 = host identity failed
4 = marker write failed
```

Duplicate calls use the existing zero-initialized interlocked state and never
wait. V1 may be removed from this feature branch; no binary may export both V1
and V2 accidentally without a separate compatibility decision and test.

## Companion initialization and marker

The companion reuses the reviewed Stage 0 sequence:

1. validate context and atomically claim initialization;
2. verify the current host-module handle;
3. resolve and hash the host executable with a bounded 10-second soft budget;
4. classify the four preserved stock/full-dump identities plus
   unknown/indeterminate;
5. verify bootstrap and companion locations;
6. write one privacy-minimal marker beside the executable, with one temporary
   directory fallback; and
7. publish terminal initialization state.

The marker schema increments to version 2 and identifies:

- UTC timestamp and process ID;
- executable leaf, size, SHA-256 when valid, and build identity;
- bootstrap leaf `X3DAudio1_7.dll` and same-directory boolean;
- companion leaf `RS2ServerFix.dll` and same-directory boolean;
- resolver status/error;
- genuine module classification `system32` or `unavailable`;
- presence/validation of both required genuine exports;
- initializer result and primary marker error if fallback was required; and
- terminal `completion=complete` or `completion=partial` written last.

It excludes full paths, account/user identifiers, command line, environment,
network addresses, tokens, player data, exception data, memory contents, EOS
state, and anti-cheat state. A truncated marker lacks the terminal line and
fails tests.

Milestone 1 recognizes builds but grants none permission to patch or hook.

## Failure behavior

| Failure | Required behavior |
|---|---|
| Both added DLLs absent | VNGame loads System32 X3Audio as before. |
| Companion present without bootstrap | Companion is ignored; System32 X3Audio loads as before. |
| Invalid bootstrap/wrong bitness/dependency | Process creation may fail; preflight must prevent placement. |
| Worker creation fails | Companion/marker absent; exported calls can still resolve and forward genuine X3Audio. |
| System path/load/identity/export validation fails | Permanent resolver failure; initialize returns failing HRESULT and calculate fails fast if called. |
| Early initialize races worker | Both serialize through the same init-once result; exactly one resolver attempt. |
| Early calculate races worker | Both serialize through the same init-once result; genuine call occurs only after complete validation. |
| Companion missing/load/identity/export failure | Genuine X3Audio remains usable; no retry. |
| Companion initializer fails | Genuine X3Audio remains usable; validated companion remains mapped after the call. |
| Host hash fails | Build identity is `indeterminate`; no hook/patch behavior exists. |
| Marker primary path fails | One temporary-directory write attempt. |
| Both marker writes fail | Debug milestone only; initializer returns marker failure. |
| Normal process termination | No explicit unload or detach cleanup; Windows tears down mappings. |

The bootstrap never returns fake successful initialization, never supplies a
zeroed handle as success, and never silently skips a failed calculate call.

## PE parsing and deployment preflight

The existing preflight parsed only the normal import directory and therefore
missed the SHCore delay-import blocker. Milestone 1 must add bounded PE32/PE32+
delay-import parsing before its scanner can approve any deployment.

The read-only preflight examines the exact user-selected stopped-server tree,
does not follow directory reparse points, and fails unless:

- the selected VNGame is AMD64 and has a recognized SHA-256;
- it normally imports named
  `X3DAudio1_7.dll!X3DAudioInitialize` exactly as profiled;
- no local `faultrep.dll`, executable `.local` redirection, or unapproved proxy
  is present;
- the proposed bootstrap and companion match their recorded hashes and PE
  contracts;
- the target System32 genuine file is AMD64, has a valid Microsoft signature,
  and exports both required names/ordinals;
- all direct and delay imports of `X3DAudio1_7.dll` in the selected tree are
  reported with every required symbol;
- no incompatible importer requires an export outside the complete two-export
  proxy surface;
- malformed PE-like files, incomplete scans, and reparse-point PE files are
  explicit failures; and
- security-product disposition and target-host KnownDLL state are recorded.

The desktop loaded-module scan is contextual only. The disposable target's
actual tree and runtime module list decide compatibility.

## Test strategy

All automated tests operate only in repository build directories and unique
system-temporary directories.

### Unit tests

1. both genuine function signatures and dispatch-record all-or-none validity;
2. init-once permanent success and permanent failure under concurrent callers;
3. resolver validation: null, self module, wrong file identity, one/both exports
   missing, failed `VirtualQuery`, and wrong allocation base;
4. initialize null-dispatch HRESULT behavior and exact genuine return/argument
   fidelity;
5. calculate exact pointer/flag fidelity and isolated fail-fast behavior;
6. companion ABI V2 size/version and all-or-none pointer consistency;
7. existing build identities, stock-input immutability, path identity, and
   bounded companion-path construction;
8. marker schema 2, fallback, short-write cleanup, terminal line, and forbidden
   content scan; and
9. proof that no known build identity permits hook/patch behavior.

### Built-PE contracts

The PE tool fails unless:

- the bootstrap is AMD64 with required security flags;
- its imports obey the bootstrap allowlist and contain no X3Audio self-import;
- it exports exactly the two named functions at ordinals 1 and 2;
- the companion is AMD64 with its separate import/export contract;
- the static harness imports named
  `X3DAudio1_7.dll!X3DAudioInitialize`; and
- no artifact has a TLS directory, unexpected export, or unexpected dynamic
  runtime dependency.

### Static-import fresh-process matrix

The harness links against the proxy target's generated import library so its PE
contains the same `X3DAudio1_7.dll` import while control cases omit the local
proxy file.

Each case runs in a fresh, bounded child process:

1. **System control:** harness only; System32 X3Audio loads and initialize
   succeeds.
2. **Companion only:** harness plus companion; System32 still loads and no
   marker appears.
3. **Bootstrap only:** local proxy loads, both genuine exports validate, an
   initialize/calculate smoke sequence matches control, and no companion marker
   appears.
4. **Both files:** local proxy plus companion; complete marker proves genuine,
   companion, ABI, and host identity.
5. **Invalid companion:** genuine calls still match control; no complete marker.
6. **Missing/invalid genuine simulation:** initialize returns failure and an
   isolated calculate child terminates through fail-fast.
7. **Concurrent first calls:** multiple initialize callers plus worker produce
   one resolver attempt and consistent results.
8. **Invalid bootstrap:** process creation or loader termination fails, proving
   there is no promised fallback after local selection.
9. **Rollback:** remove both while no child runs; System32 control succeeds.

The harness never unloads a module while the worker can run and disables
critical-error UI.

### Baseline status

Before this design was drafted, the unchanged `feature/two-dll-stage0` source
built in Release and all 6 existing CTest tests passed. The Windows SDK is now
installed under `E:\Windows Kits\10`, so configuration required an explicit
`RS2_SYSTEM_FAULTREP_IMPORT_LIBRARY` cache value; no source change was made.

## Disposable-server validation

Codex may prepare scripts and artifacts after a separately approved
implementation plan but may not start, stop, or modify a server without the
user's explicit runtime authorization.

### Control

1. Use a stopped disposable dedicated-server copy with no public players.
2. Confirm no local `X3DAudio1_7.dll`, `RS2ServerFix.dll`, `faultrep.dll`,
   executable `.local`, or prior marker.
3. Run the complete preflight and retain its sanitized report.
4. Record AV/EDR, WDAC, AppLocker, and EAC disposition.
5. Record hashes for VNGame, System32 X3Audio, `dbghelp.dll`, configuration, and
   root PE files without publishing sensitive configuration.
6. Start with the normal command and verify Steam/EOS/EAC/network/map/WebAdmin
   initialization; capture the loaded System32 X3Audio path; then stop normally.

### Two-file pass

1. While stopped, place only the exact reviewed Release
   `X3DAudio1_7.dll` and `RS2ServerFix.dll` beside VNGame.
2. Start with the identical command and environment.
3. Require both local bootstrap and genuine System32 X3Audio in the module
   inventory plus one complete schema-2 marker.
4. Require Steam, EOS, EAC, client join/authentication, network, WebAdmin, map
   load/travel, and normal shutdown to match control.
5. Observe a pre-agreed bounded idle/play interval.
6. Stop normally, capture the same sanitized manifest, and prove no protected
   executable, DLL, or configuration file changed. Expected runtime logs and
   explicitly named marker evidence are recorded separately.

### Rollback

1. Confirm the process is stopped.
2. Remove only the two added DLLs and task marker files.
3. Restart once and prove the System32 X3Audio path and normal services.
4. Retain control/pass/rollback evidence and exact tested hashes.

Any startup failure, EAC/security intervention, unexpected module path,
incompatible importer, genuine/companion validation failure, missing/partial
marker, service regression, shutdown hang, protected-artifact mutation, or
rollback failure stops Milestone 1.

## Success criteria

Milestone 1 is complete only when:

- the reviewed Release build passes all unit, PE-contract, static-import,
  partial-installation, concurrency, fail-fast, and preflight tests;
- normal and delay imports are both parsed and covered by malformed-fixture
  tests;
- both X3Audio exports preserve genuine behavior when the proxy is present;
- companion absence/failure cannot break valid genuine forwarding;
- no export performs companion work, logging, hashing, or game-memory access;
- control/companion-only/rollback load System32 directly;
- bootstrap cases prove local bootstrap plus separately validated System32
  genuine module;
- the exact disposable server passes control/proxy/rollback with Steam, EOS,
  EAC, join, travel, WebAdmin, and shutdown intact;
- pre/post hashes prove no protected executable, shipped DLL, or configuration
  changed; expected runtime logs and named marker evidence are excluded from
  that invariant and retained separately;
- deployable artifacts are limited to two manually placed DLLs and sanitized
  evidence; and
- no production/public server, client, anti-cheat bypass, game hook, or
  performance claim is involved.

## Deferred milestones

After the user separately accepts Milestone 1 runtime evidence, a new reviewed
design may add low-overhead timing instrumentation to `RS2ServerFix.dll`.
EasyHook versus a minimal detour implementation, exact current-build hook
addresses, sampling overhead, worker queues, logging offload, and any
relevancy/collision optimization remain out of scope here.

No Milestone 1 result proves that Unreal objects, world collision, replication,
EOS callbacks, or game logic can safely execute on another thread.
