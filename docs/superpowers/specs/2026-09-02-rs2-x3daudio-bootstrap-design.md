# RS2 Passive X3Audio Bootstrap Design

Date: 2026-09-02

Stage: Milestone 1 - native loader, genuine API forwarding, companion
initialization, diagnostics, and rollback proof only

Status: Revised after Claude Opus 5 Max review round 1; awaiting round 2

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
3. calls to both exports preserve the exact legacy 1.7 ABI, arguments, and
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
  `0x4B6B06BE`, PE `SizeOfImage` 36,864, and checksum `0x00008C0D`; the file
  size is 24,920 bytes;
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
tested path, identity, companion, marker, and harness patterns only. On this
feature branch the `faultrep.dll` target, its V1 ABI, its import-library search,
and its faultrep-specific tests are removed from the active source/build graph.
Their history remains recoverable from commit `a0e733d`; no build from this
branch may emit `faultrep.dll` or export `RS2ServerFix_InitializeV1`.

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
- Export calls from another DLL's `DllMain` are unsupported. The zero-EXE-edit
  proxy cannot safely load the genuine DLL while its caller holds loader lock;
  the disposable-server gate therefore has to prove the observed VNGame path
  calls the initializer after process loader initialization.

The name `X3DAudio1_7.dll` is a legacy DirectX/XAudio 2.7 contract. The
installed Windows 10 SDK header describes the newer XAudio 2.8/2.9 contract
and declares `X3DAudioInitialize` as returning `HRESULT`; it is not the ABI
authority for this proxy. Direct inspection of the qualified 1.7 binary shows
that its initializer is a 97-byte leaf, writes all 20 handle bytes, and returns
with `RAX` containing scratch arithmetic rather than an API result. The proxy
therefore declares only the ABI actually present in the qualified binary:

```cpp
using X3DAudioInitializeFn = void (WINAPI*)(
    UINT32 speakerChannelMask,
    FLOAT speedOfSound,
    BYTE* instance20Bytes);

using X3DAudioCalculateFn = void (WINAPI*)(
    const BYTE* instance20Bytes,
    const void* listener,
    const void* emitter,
    UINT32 flags,
    void* settings);

extern "C" void WINAPI X3DAudioInitialize(
    UINT32 speakerChannelMask,
    FLOAT speedOfSound,
    BYTE* instance20Bytes);

extern "C" void WINAPI X3DAudioCalculate(
    const BYTE* instance20Bytes,
    const void* listener,
    const void* emitter,
    UINT32 flags,
    void* settings);
```

The bootstrap never dereferences the opaque listener, emitter, or settings
pointers and does not include `x3daudio.h`. The offline harness may use the SDK
structure declarations under renamed function identifiers, but it declares
the imported legacy initializer itself as `void` and proves compatible
structure layout by compile-time size/offset assertions plus a System32
control run. AMD64 calling convention, the 20-byte handle, and both named
exports plus their observed ordinals are hard contracts. A new genuine-file
hash is unqualified until its initializer semantics are independently checked
and its control harness passes.

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
- an honest VERSIONINFO resource identifying it as the unsigned
  `RS2ServerFix` passive X3Audio bootstrap and not as a Microsoft binary;
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
- an honest VERSIONINFO resource identifying it as the `RS2ServerFix`
  companion;
- user `DllMain` always returns `TRUE` and performs no work;
- no worker thread of its own in Milestone 1.

No build, install, or test target copies either DLL outside repository build
directories or unique system-temporary test directories.

## Genuine X3Audio resolution

### One permanent successful publication

The bootstrap owns one zero-initialized `INIT_ONCE`. A successful resolver
allocates one page-aligned immutable dispatch record containing:

```cpp
struct X3AudioDispatch {
    HMODULE module;
    X3DAudioInitializeFn initialize;
    X3DAudioCalculateFn calculate;
    GenuineResolverStatus status;
    DWORD win32Error;
};
```

Both the worker and both public exports call `AcquireGenuineX3Audio`. It uses
`InitOnceBeginInitialize(INIT_ONCE_ASYNC)` and
`InitOnceComplete(INIT_ONCE_ASYNC, dispatch)` rather than a callback or
`InitOnceExecuteOnce`:

1. an already completed call returns the immutable published record;
2. every concurrent caller receiving `pending=TRUE` resolves into its own
   private record without holding an INIT_ONCE or project lock;
3. only a fully validated success record is offered to `InitOnceComplete`;
4. the single completion winner retains its module reference and record;
5. a losing successful caller releases only its own extra module reference and
   private record, then obtains the winner through `INIT_ONCE_CHECK_ONLY`; and
6. a failed attempt is abandoned without completing the INIT_ONCE, performs a
   non-blocking check for a concurrently published success, and otherwise
   returns its local failure to the caller.

This design guarantees exactly one published successful dispatch, not exactly
one resolution attempt. It permits duplicate first-race `LoadLibraryExW` calls
but never exposes a partial table and never waits on a project synchronization
object while acquiring loader lock. A worker failure may therefore be retried
by the first later export call; an export failure terminates the process, so it
cannot produce a retry storm. All INIT_ONCE API-error paths are terminal in an
export and simply disable the worker path.

Calls from another DLL's `DllMain` remain outside the supported contract: the
algorithm avoids private-lock/loader-lock inversion, but no proxy can safely
promise a first `LoadLibraryExW` while its caller itself holds loader lock.

### Resolution and validation sequence

Each private resolution attempt:

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
11. returns a complete private success record only after all checks pass.

The caller then attempts the asynchronous one-time publication described
above. A rejected candidate is released only when it is neither null nor the
bootstrap module; the `SelfModule` case must never call `FreeLibrary` on the
bootstrap. Every temporary workspace and losing private record is released.
The publication winner retains its genuine module and dispatch record until
process exit. Resolution does not load the companion or write diagnostics.

## Export behavior

### `X3DAudioInitialize`

The export obtains a validated dispatch, calls the genuine legacy `void`
function exactly once with the original arguments, and returns after the
genuine function returns. The proxy neither reads nor rewrites the 20-byte
handle.

The legacy ABI has no error channel. If no validated dispatch is available,
the export records nothing and invokes `RaiseFailFastException`, with
`TerminateProcess` as a defensive non-return fallback. It never returns a
zeroed, untouched, or fabricated handle as if initialization succeeded.

### `X3DAudioCalculate`

The export obtains the same permanent dispatch record. On success it calls the
genuine function once with the original pointers and flags and returns after
the genuine call.

The function also has no error return. If the genuine dispatch is unavailable,
the proxy takes the same fail-fast path rather than returning with undefined or
partially written DSP outputs. Both failure paths are covered by separate
fresh-process tests. They are not expected on an eligible system because an
exact qualified genuine-file hash is a deployment precondition.

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

1. calls `AcquireGenuineX3Audio` once;
2. continues only with a validated published or private success record;
3. constructs the absolute sibling path to `RS2ServerFix.dll`;
4. validates, loads, and calls `RS2ServerFix_InitializeV2` once;
5. returns without unloading a successful genuine or companion module.

Worker-creation failure disables companion initialization, but it does not
disable lazy genuine resolution by a later X3Audio export call. The bootstrap
does not create another worker from an export.

Creating a non-joined worker from `DllMain` is an explicit residual Windows
loader risk accepted only for this passive startup experiment. The worker never
waits, and both project `DllMain` process-detach paths remain empty. Its two
`LoadLibraryExW` windows occur before host hashing. Automated acceptance adds a
repeated child that reaches `main` and immediately calls `ExitProcess` while
the worker may still be active; any startup/shutdown hang or abnormal exit is a
failure. The disposable-server procedure also measures normal and immediate
post-start shutdown. This evidence can reduce but cannot prove the absence of
all third-party detach-lock interactions, so the risk remains named in the
release evidence.

## Shared initialization ABI V2

The faultrep-specific V1 ABI is removed from this feature branch rather than
reinterpreted or retained beside V2. The X3Audio bootstrap and companion
compile one new C-compatible context. It deliberately carries no callable
genuine-function pointers:

```cpp
constexpr std::uint32_t kBootstrapAbiVersion = 2;

struct BootstrapContextV2 {
    std::uint32_t size;
    std::uint32_t abiVersion;
    HMODULE hostModule;
    HMODULE bootstrapModule;
    HMODULE genuineX3AudioModule;
    std::uint32_t genuineExportsMask;
    std::uint32_t reserved;
};

constexpr std::uint32_t kGenuineInitializePresent = 1u << 0;
constexpr std::uint32_t kGenuineCalculatePresent = 1u << 1;
constexpr std::uint32_t kRequiredGenuineExports =
    kGenuineInitializePresent | kGenuineCalculatePresent;

static_assert(sizeof(BootstrapContextV2) == 40);

using InitializeV2Fn = DWORD(WINAPI*)(const BootstrapContextV2*);
```

The companion validates exact size/version, non-null host/bootstrap/genuine
module, `genuineExportsMask == kRequiredGenuineExports`, and `reserved == 0`.
It verifies `hostModule == GetModuleHandleW(nullptr)` before hashing. Because
the worker calls the companion only after successful genuine validation, a
resolver failure never produces a V2 call or marker.

Initialization return values remain stable:

```text
0 = initialized
1 = already initialized
2 = invalid context
3 = host identity failed
4 = marker write failed
```

Duplicate calls use the existing zero-initialized interlocked state and never
wait. `RS2ServerFix.dll` exports V2 only; the active CMake graph and PE tests
fail if V1 or any second companion export is present.

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

The primary marker leaf is exactly
`RS2ServerFix.loader.<decimal-pid>.log` beside VNGame. The sole fallback uses
the same leaf beneath the process temporary directory. The marker schema
increments to version 2 and identifies:

- UTC timestamp and process ID;
- executable leaf, size, SHA-256 when valid, and build identity;
- bootstrap leaf `X3DAudio1_7.dll` and same-directory boolean;
- companion leaf `RS2ServerFix.dll` and same-directory boolean;
- genuine module classification `system32`;
- `genuine_initialize_present=true` and
  `genuine_calculate_present=true`;
- initializer result and primary marker error if fallback was required; and
- terminal `completion=complete` or `completion=partial` written last.

It excludes full paths, account/user identifiers, command line, environment,
network addresses, tokens, player data, exception data, memory contents, EOS
state, and anti-cheat state. A truncated marker lacks the terminal line and
fails tests. The exact cleanup pattern is `RS2ServerFix.loader.*.log`, but an
operator removes only the marker paths captured for the test PIDs rather than
blindly deleting every match.

Milestone 1 recognizes builds but grants none permission to patch or hook.

## Failure behavior

| Failure | Required behavior |
|---|---|
| Both added DLLs absent | VNGame loads System32 X3Audio as before. |
| Companion present without bootstrap | Companion is ignored; System32 X3Audio loads as before. |
| Invalid bootstrap/wrong bitness/dependency | Process creation may fail; preflight must prevent placement. |
| Worker creation fails | Companion/marker absent; exported calls can still resolve and forward genuine X3Audio. |
| System path/load/identity/export validation fails in worker | No publication, companion, or marker; a later export may make one fresh attempt. |
| System path/load/identity/export validation fails in either export | The process fails fast; the legacy void ABI has no safe fallback. |
| Early initialize races worker | Each may resolve privately without waiting; exactly one successful dispatch is published and the genuine function is called only through a complete record. |
| Early calculate races worker | Each may resolve privately without waiting; exactly one successful dispatch is published and the genuine function is called only through a complete record. |
| Companion missing/load/identity/export failure | Genuine X3Audio remains usable; no retry. |
| Companion initializer fails | Genuine X3Audio remains usable; validated companion remains mapped after the call. |
| Host hash fails | Build identity is `indeterminate`; no hook/patch behavior exists. |
| Marker primary path fails | One temporary-directory write attempt. |
| Both marker writes fail | Debug milestone only; initializer returns marker failure. |
| Normal process termination | No explicit unload or detach cleanup; Windows tears down mappings. |
| Immediate `ExitProcess` while worker runs | Residual risk; bounded repetition must show no hang before disposable use. |

The bootstrap never returns from a failed initializer as if a handle were
valid, never supplies a zeroed handle as success, and never silently skips a
failed calculate call.

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
- the target System32 genuine file is AMD64, has an explicitly qualified
  SHA-256, and matches the qualified file's recorded size, PE timestamp,
  `SizeOfImage`, version, and both required names/ordinals;
- that exact file passes timestamp-aware embedded Authenticode verification
  through `WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)` with no UI,
  `WTD_REVOKE_NONE`, cache-only URL retrieval, and paired VERIFY/CLOSE state
  actions; only `ERROR_SUCCESS` is accepted, with no manual certificate-expiry
  override;
- all direct and delay imports of `X3DAudio1_7.dll` in the selected tree are
  reported with every required symbol;
- no incompatible importer requires an export outside the complete two-export
  proxy surface;
- malformed PE-like files, incomplete scans, and reparse-point PE files are
  explicit failures; and
- security-product disposition and target-host KnownDLL state are recorded.

The first qualified genuine hash is
`9460709339701AD471A5CABE6365355F4D586DC4FCB86507C1331839DC555446`.
Its Microsoft signer certificate is expired in wall-clock terms but its
embedded time-stamp makes `WinVerifyTrust` and `Get-AuthenticodeSignature`
return valid. The preflight must not reproduce trust by comparing `NotAfter`
itself. Catalog-only signatures are not accepted in Milestone 1; a target with
a different or catalog-only genuine file stops for separate qualification,
including legacy-void-ABI inspection and a System32 control-harness run.

For tree compatibility, by-name imports of either public export and ordinal
imports `@1`/`@2` are compatible and reported. Every other X3Audio name or
ordinal is rejected. The selected VNGame contract remains stricter: it must
normally import named `X3DAudioInitialize` exactly as profiled.

The desktop loaded-module scan is contextual only. The disposable target's
actual tree and runtime module list decide compatibility.

## Test strategy

All automated tests operate only in repository build directories and unique
system-temporary directories.

### Unit tests

1. compile-time legacy-void initializer signature, calculate signature, and
   dispatch-record all-or-none validity;
2. asynchronous INIT_ONCE behavior under concurrent callers: no caller waits,
   only complete successes are offered, exactly one success is published,
   losing module references are released, and a worker failure remains
   retryable;
3. resolver validation: null, self module, wrong file identity, one/both exports
   missing, failed `VirtualQuery`, and wrong allocation base;
4. initialize exact argument/output fidelity and isolated resolver-failure
   fail-fast behavior;
5. calculate exact pointer/flag/output fidelity and isolated resolver-failure
   fail-fast behavior;
6. companion ABI V2 size/version, required export mask, reserved field, and
   module-handle validation;
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

The old faultrep target and its contracts are absent. The active suite keeps
the six baseline test roles under X3Audio-aware implementations and adds one
early-exit test:

1. `core` (adapted);
2. `pe_bootstrap_contract` (two X3Audio exports, not `ReportFault`);
3. `pe_companion_contract` (V2 only);
4. `pe_harness_contract` (named legacy initializer import);
5. `static_import_cases` (the matrix below);
6. `preflight_fixture` (normal and delay imports); and
7. `early_exit_cases` (repeated immediate `ExitProcess`).

The CMake graph no longer searches for or links `FaultRep.Lib` and no active
test expects `ReportFault`, `faultrep.dll`, or V1.

### Static-import fresh-process matrix

The harness links against the proxy target's generated import library so its PE
contains a named `X3DAudio1_7.dll!X3DAudioInitialize` import while control
cases omit the local proxy file. It declares that imported function with the
legacy `void` ABI. To exercise calculate, it enumerates loaded modules by full
path, selects the intended local or System32 module handle unambiguously, and
resolves `X3DAudioCalculate` from that exact handle.

Every functional case zero-initializes the handle, listener, emitter, settings,
matrix, and padding, then runs one fixed valid initialize/calculate vector. The
harness emits a deterministic digest of the resulting handle and defined DSP
outputs to captured stdout. The runner compares proxy-case digests with the
System32 control and also requires the expected full-path module inventory; it
does not use basename-only `GetModuleHandleW` or discard child output.

Each case runs in a fresh, bounded child process:

1. **System control:** harness only; the qualified System32 X3Audio loads and
   produces the reference digest.
2. **Companion only:** harness plus companion; System32 still loads and no
   marker appears.
3. **Bootstrap only:** local proxy loads, both genuine exports validate, an
   initialize/calculate vector matches the control digest, two distinct
   expected X3Audio full paths are enumerated, and no companion marker appears.
4. **Both files:** local proxy plus companion; complete marker proves genuine,
   companion, ABI, and host identity.
5. **Invalid companion:** genuine calls still match control; no complete marker.
6. **Missing genuine simulation:** a non-deployable test-only bootstrap is
   compiled with an absent System32 genuine leaf while retaining local output
   name `X3DAudio1_7.dll`; separate initializer and calculate children must
   terminate through fail-fast without modifying System32.
7. **Concurrent first calls:** multiple initializer/calculate callers plus the
   worker produce consistent control digests and exactly one published success;
   attempt-count and loser-cleanup assertions live in the injected unit test,
   not in external-process inference.
8. **Invalid bootstrap:** process creation or loader termination fails, proving
   there is no promised fallback after local selection.
9. **Rollback:** remove both while no child runs; System32 control succeeds.

`early_exit_cases` is separate from the nine functional cases. It repeatedly
starts a bootstrap-plus-companion harness whose `main` immediately calls
`ExitProcess`; each child has a strict timeout and must exit normally. The
repeat count is fixed in the implementation plan, high enough to exercise the
worker race without turning the normal suite into an unbounded soak.

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
6. In a separate disposable repetition, request normal shutdown immediately
   after startup readiness and require it to complete within the same bound as
   control; do not force termination to turn a hang into a pass.
7. Stop normally, capture the same sanitized manifest, and prove no protected
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

If AV/EDR quarantines or deletes the local bootstrap, do not disable the
control or add an exclusion. Stop the server, preserve the alert, remove the
remaining exact companion and captured marker while stopped, and prove the
System32 control path again. Quarantine-in-place may block process creation;
quarantine-by-deletion may silently restore System32 loading, so the required
local-module inventory and marker are acceptance evidence rather than optional
diagnostics.

## Success criteria

Milestone 1 is complete only when:

- the reviewed Release build passes all unit, PE-contract, static-import,
  partial-installation, concurrency, fail-fast, and preflight tests;
- normal and delay imports are both parsed and covered by malformed-fixture
  tests;
- the offline System32-control digest proves both X3Audio exports preserve the
  qualified legacy ABI and defined output behavior when the proxy is present;
- companion absence/failure cannot break valid genuine forwarding;
- no export performs companion work, logging, hashing, or game-memory access;
- concurrent first callers never wait on project synchronization while loading
  the genuine module, exactly one complete success is published, and repeated
  immediate-exit children do not hang;
- control/companion-only/rollback load System32 directly;
- bootstrap cases prove local bootstrap plus separately validated System32
  genuine module;
- the exact disposable server proves local/bootstrap and System32/genuine
  coexistence and passes control/proxy/rollback with Steam, EOS, EAC, join,
  travel, WebAdmin, and shutdown intact; forwarding fidelity remains an
  offline-harness claim because VNGame imports only the initializer and the
  exports intentionally emit no diagnostics;
- pre/post hashes prove no protected executable, shipped DLL, or configuration
  changed; expected runtime logs and named marker evidence are excluded from
  that invariant and retained separately;
- deployable artifacts are limited to two manually placed DLLs and sanitized
  evidence; and
- no production/public server, client, anti-cheat bypass, game hook, or
  performance claim is involved.

The accepted residual risk statement must accompany any Milestone 1 artifact:
`CreateThread` from `DllMain` is a pragmatic startup trigger, is documented by
Microsoft as risky, and cannot be proven safe against every third-party
process-detach lock. Offline early-exit repetition plus bounded disposable
shutdown are required evidence, not a claim that the platform risk is absent.

## Deferred milestones

After the user separately accepts Milestone 1 runtime evidence, a new reviewed
design may add low-overhead timing instrumentation to `RS2ServerFix.dll`.
EasyHook versus a minimal detour implementation, exact current-build hook
addresses, sampling overhead, worker queues, logging offload, and any
relevancy/collision optimization remain out of scope here.

No Milestone 1 result proves that Unreal objects, world collision, replication,
EOS callbacks, or game logic can safely execute on another thread.
