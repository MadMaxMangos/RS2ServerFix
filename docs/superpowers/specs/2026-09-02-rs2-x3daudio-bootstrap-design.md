# RS2 Passive X3Audio Bootstrap Design

Date: 2026-09-02

Stage: Milestone 1 - native loader, genuine API forwarding, companion
initialization, diagnostics, and rollback proof only

Status: Approved by Claude Opus 5 Max after review round 6 and by the user on
2026-09-02. The user-approved first-runtime console-status amendment is
incorporated; focused Claude Opus 5 Max review-round-1 findings are addressed
and focused re-review is pending. Earlier mechanical implementation-plan
amendments separated ordinal DLL exports from by-name test imports and made
Git's CRLF custody check internally consistent; architecture and scope are
unchanged.

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
5. the companion identifies the host, writes one privacy-minimal marker, and
   then emits one exact success-only console status line without changing game
   memory or any existing protected binary or configuration file; and
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
identification, the marker, one success-only console confirmation, and all
future functionality. A missing or rejected companion disables only optional
RS2ServerFix behavior; genuine X3Audio forwarding remains available.

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
- the examined genuine file is AMD64 and Microsoft-signed; its
  `VS_FIXEDFILEINFO` file and product version quads are both `9.28.1886.0`, its
  human display `FileVersion` is `9.28 (DXSDK_FEB10.100204-0932)`, and its SHA-256 is
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
  proxy cannot safely load the genuine DLL while its caller holds loader lock.

The statically visible current-build path is safe by construction: both
recognized current VNGame images have a zero TLS-directory RVA/size, VNGame is
the only observed static importer of the X3Audio basename, and executable code
runs from its entry point only after process loader initialization. Deployment
preflight makes the zero TLS directory and VNGame-only tree importer set hard
requirements. The clean control additionally requires a complete scan of every
loaded module's normal and delay imports and must still identify VNGame as the
sole importer before the proxy pass. A module could nevertheless resolve the
exports dynamically with `GetProcAddress` and call from its own `DllMain`;
static preflight cannot exclude that behavior, so it remains an explicit
residual risk rather than an unimplemented proof obligation.

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
exports plus their observed ordinals are hard contracts. Qualification state
comes only from the reviewed, version-controlled
`config/qualified_x3audio_genuine.manifest` file and follows the explicit
provisional-to-qualified procedure below. A provisional entry is never accepted
by the normal test suite or deployment preflight.

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
- one shared compile-time project-version source supplies both DLL VERSIONINFO
  resources and the companion's success-only console status;
- user `DllMain` always returns `TRUE` and performs no work;
- no worker thread of its own in Milestone 1.

No build, install, or test target copies either DLL outside repository build
directories or unique system-temporary test directories.

## Genuine X3Audio resolution

### One normal publication plus one bounded fallback

The bootstrap owns one zero-initialized `INIT_ONCE`. Resolution first produces
a private stack result. Only after genuine validation succeeds does the caller
attempt to allocate a page-aligned immutable dispatch record containing:

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

1. a non-blocking `INIT_ONCE_CHECK_ONLY` first returns any normal publication;
   otherwise a `Ready` static fallback is returned before new resolution begins;
2. every concurrent caller receiving `pending=TRUE`, or encountering a
   begin-initialize API error, resolves into its own private stack result
   without holding an INIT_ONCE or project lock;
3. only a fully validated success is copied to a page-aligned record and
   offered to `InitOnceComplete`;
4. the single completion winner retains its module reference and record;
5. after `InitOnceComplete` returns false, the caller performs
   `INIT_ONCE_CHECK_ONLY`. If it obtains a winner, it releases only its own
   extra module reference and record and returns that winner. Only a failed
   check with no winner proceeds to step 6; and
6. a successful private result whose allocation fails, or whose
   `InitOnceComplete` and following check both fail,
   frees any unusable record storage without releasing the private module
   reference, then falls back to one process-static `alignas(8)` dispatch plus
   an interlocked three-state
   `Empty/Writing/Ready` publication word. A successful caller may change
   `Empty` to `Writing`, transfer its module reference, copy the complete
   dispatch, and publish `Ready` with `InterlockedExchange`. Every reader uses
   `InterlockedCompareExchange(&fallbackState, Empty, Empty)` as its acquire
   read and must not touch the static record unless the returned state is
   `Ready`. No fallible API,
   loader operation, allocation, or external call occurs between claiming
   `Writing` and publishing `Ready`. After `Ready`, the claimant may offer the
   aligned static pointer to `InitOnceComplete`; an API rejection does not
   invalidate the fallback;
7. a caller that loses the fallback claim never waits. It may use its already
   validated private dispatch for the current worker/export operation, while
   the fallback claimant's retained reference keeps the genuine module mapped,
   then releases its own extra reference. A `Ready` fallback is immutable and
   is returned by later acquisitions even if `InitOnceComplete` itself failed;
   and
8. a failed resolution attempt is abandoned without completing the INIT_ONCE,
   performs non-blocking checks for both a normally published success and the
   `Ready` fallback, and otherwise returns its classified local failure to the
   caller.

The normal INIT_ONCE path guarantees exactly one published successful dispatch,
not exactly one resolution attempt. The fallback path guarantees at most one
additional immutable static record. An exact race may leave both records and
two retained genuine-module references, but both contain the same fully
validated module and export addresses; no caller observes either record before
it is complete. It permits duplicate first-race
`LoadLibraryExW` calls but never exposes a partial table and never waits on a
project synchronization object while acquiring loader lock. A worker makes one
attempt and quietly stops on failure. An export receiving a resource/API
failure checks for a concurrent publication, makes exactly one immediate
private retry, then checks once more before failing fast. A validation failure
is not retried. A successful private result is always usable even if INIT_ONCE
or publication allocation fails, and a persistent publication failure cannot
accumulate a module reference on every later call. The remaining micro-race in
which another thread publishes just after the final non-blocking check cannot
be removed without waiting and is an accepted fail-fast risk.

Calls from another DLL's `DllMain` remain outside the supported contract: the
algorithm avoids private-lock/loader-lock inversion, but no proxy can safely
promise a first `LoadLibraryExW` while its caller itself holds loader lock.

### Resolution and validation sequence

Each private resolution attempt:

1. zeroes fixed 512-character stack buffers for the expected and candidate
   paths; preflight rejects a target whose exact System32 path plus leaf does
   not fit this declared capacity;
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
11. returns a complete private success only after all checks pass.

Before these buffers are used, the shared `AppendPathLeaf` and
`ExtractDirectoryAndLeaf` helpers are changed to bound `wcsnlen_s` by their
caller's supplied capacity, never by the old global 32,768-character capacity.
`ExtractDirectoryAndLeaf` gains a `std::size_t pathCapacity` parameter
immediately after `path`; both existing call sites and every new call pass the
capacity of that exact input buffer. `AppendPathLeaf` gains
`directoryCapacity` immediately after `directory` and `leafCapacity`
immediately after `leaf`; its existing `capacity` becomes `outputCapacity`.
Every call passes the capacity of each exact input and output buffer, including
the compile-time array extent for literal leaves. Tests pass terminated and
unterminated directory, leaf, and 512-character path inputs. Zeroing the
resolver buffers remains defense in depth, not the read-bound invariant.

Failures are classified before returning. `SystemPathFailed`, path-capacity,
`LoadFailed`, candidate-path API failure, and file-identity API failure are
resource/API failures eligible for the export's single retry. `SelfModule`,
wrong file identity, either missing export, failed address query, wrong
allocation base, or a function resolving into the bootstrap are validation
failures and are not retried.

The caller then attempts the asynchronous one-time publication described
above. A rejected candidate is released only when it is neither null nor the
bootstrap module; the `SelfModule` case must never call `FreeLibrary` on the
bootstrap. Losing allocated records and their extra module references are
released after the winner is obtained. The normal publication winner and any
`Ready` fallback each retain exactly their own genuine-module reference until
process exit; callers using a private record while the fallback is `Writing`
release their extra reference after their current operation.
Resolution does not load the companion or write diagnostics.

## Export behavior

### `X3DAudioInitialize`

The export obtains a validated dispatch, calls the genuine legacy `void`
function exactly once with the original arguments, and returns after the
genuine function returns. The proxy neither reads nor rewrites the 20-byte
handle.

The legacy ABI has no error channel. If no validated dispatch is available,
the export applies the classified retry policy above, records nothing, and
invokes `RaiseFailFastException(nullptr, nullptr,
FAIL_FAST_GENERATE_EXCEPTION_ADDRESS)`. `TerminateProcess` with the same
`STATUS_FAIL_FAST_EXCEPTION` value is the defensive non-return fallback. The
observable child exit status is therefore exactly `0xC0000602`. It never
returns a zeroed, untouched, or fabricated handle as if initialization
succeeded.

### `X3DAudioCalculate`

The export obtains a validated dispatch, whether normally published, from the
immutable fallback, or private for the current call. On success it calls the
genuine function once with the original pointers and flags and returns after
the genuine call.

The function also has no error return. If the genuine dispatch is unavailable,
the proxy takes the same fail-fast path rather than returning with undefined or
partially written DSP outputs. Both failure paths are covered by separate
fresh-process tests. An exact qualified genuine-file hash prevents known
validation mismatch but cannot prevent runtime resource exhaustion,
file-access interference, or the documented final-check race.

Both exports are free of companion calls, file writes, logging, hashing,
game-memory access, unbounded retries, and exception swallowing.

## Bootstrap lifetime and worker

On `DLL_PROCESS_ATTACH`, user `DllMain` only:

1. stores `hinstDLL` in a zero-initialized POD global;
2. calls `CreateThread` once with the module handle as its parameter;
3. closes a successful thread handle without waiting; and
4. returns `TRUE` regardless of worker creation.

Other notifications perform no user work.

The worker performs one non-retrying sequence:

1. calls `AcquireGenuineX3Audio` once;
2. continues only with a validated normal publication, immutable fallback, or
   private success record;
3. constructs the absolute sibling path to `RS2ServerFix.dll`;
4. validates, loads, and calls `RS2ServerFix_InitializeV2` once;
5. returns without unloading a normal/fallback-owned genuine or successful
   companion module. If it used a private record while the fallback was
   `Writing`, it releases only that extra genuine reference after companion
   work, because the fallback claimant already owns the persistent reference.

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

## Companion initialization, marker, and console status

The companion reuses the reviewed Stage 0 sequence:

1. validate context and atomically claim initialization;
2. verify the current host-module handle;
3. resolve and hash the host executable with a bounded 10-second soft budget;
4. classify the four preserved stock/full-dump identities plus
   unknown/indeterminate;
5. verify bootstrap and companion locations;
6. write one privacy-minimal marker beside the executable, with one temporary
   directory fallback;
7. after a complete marker and only for result `kInitOk`, make one best-effort
   attempt to emit the exact success console status; and
8. publish terminal initialization state.

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

### Success console status

The companion emits exactly this 7-bit ASCII template, terminated by CRLF:

```text
[RS2ServerFix] v0.1.0.0 loaded; host=<build-identity>; X3Audio=System32; mode=passive; marker=complete\r\n
```

`<build-identity>` is the exact `BuildIdentityName` value. The only eligible
values are `pr1-crash-full-dump`, `pr1-stock-baseline`, `current-stock`,
`current-full-dump`, and `unknown`. `indeterminate` and an out-of-range enum can
never accompany a complete marker and the formatter rejects them. The expected
line for the planned current full-dump first runtime is therefore:

```text
[RS2ServerFix] v0.1.0.0 loaded; host=current-full-dump; X3Audio=System32; mode=passive; marker=complete
```

The project version comes from one shared header also consumed by both
VERSIONINFO resources. Formatting uses a fixed `char[192]` stack buffer, no
heap allocation, and a capacity-aware formatter. The production adapter calls
`GetStdHandle(STD_OUTPUT_HANDLE)` once and, for a non-null/non-
`INVALID_HANDLE_VALUE` handle, calls `WriteFile` exactly once for the complete
line. A failed or short write returns false; there is no retry, stderr fallback,
`OutputDebugString`, `WriteConsole`, Unreal logging call, iostream, CRT logging,
allocation, or explicit wait.

The attempt occurs only after `WriteMarkerWithFallback` has produced a terminal
`completion=complete` marker and the initializer result is `kInitOk`. The
existing atomic initialization claim makes the attempt exactly once even when
initialization calls race. Console absence or write failure is observational
and nonfatal: it does not change the successful initializer result or the
already complete marker. The marker remains authoritative. The line may appear
in an attached console or redirected standard output; this design does not
claim that it enters Unreal's `Launch.log`.

This diagnostic adds no marker field and does not change marker schema 2.

## Failure behavior

| Failure | Required behavior |
|---|---|
| Both added DLLs absent | VNGame loads System32 X3Audio as before. |
| Companion present without bootstrap | Companion is ignored; System32 X3Audio loads as before. |
| Invalid bootstrap/wrong bitness/dependency | Process creation may fail; preflight must prevent placement. |
| Worker creation fails | Companion/marker absent; exported calls can still resolve and forward genuine X3Audio. |
| Resource/API resolution failure in worker | No publication, companion, or marker; a later export may make its bounded attempts. |
| Resource/API resolution failure in either export | Check publication, retry privately once, check again, then fail fast with `0xC0000602`; runtime resource failure is not excluded by preflight. |
| Genuine-validation failure in worker | No publication, companion, or marker; a later export repeats validation. |
| Genuine-validation failure in either export | Immediate fail-fast `0xC0000602`; the legacy void ABI has no safe fallback. |
| INIT_ONCE/dispatch-allocation failure after private genuine success | One claimant publishes the immutable static fallback; concurrent callers use complete private records without waiting and release their extra references after their current operation. Later calls reuse the permanent fallback instead of accumulating references. |
| Early initialize races worker | Each may resolve privately without waiting; the normal INIT_ONCE path publishes exactly one success, the fallback path publishes at most one additional immutable success, and the genuine function is called only through a complete record. |
| Early calculate races worker | Each may resolve privately without waiting; the normal INIT_ONCE path publishes exactly one success, the fallback path publishes at most one additional immutable success, and the genuine function is called only through a complete record. |
| Companion missing/load/identity/export failure | Genuine X3Audio remains usable; no retry, marker, or console status. |
| Companion initializer fails | Genuine X3Audio remains usable; validated companion remains mapped after the call; no success console status. |
| Host hash fails | Build identity is `indeterminate`; no hook/patch behavior exists. |
| Marker primary path fails | One temporary-directory write attempt. |
| Both marker writes fail | Debug milestone only; initializer returns marker failure and emits no console status. |
| Standard output is absent or its write fails/is short after a complete marker | Initialization remains successful, the complete marker remains authoritative, and there is no retry or alternate diagnostic. |
| Normal process termination | No explicit unload or detach cleanup; Windows tears down mappings. |
| Immediate `ExitProcess` while worker runs | Residual risk; bounded repetition must show no hang before disposable use. |

The bootstrap never returns from a failed initializer as if a handle were
valid, never supplies a zeroed handle as success, and never silently skips a
failed calculate call.

## PE parsing and deployment preflight

The existing preflight parsed only the normal import directory and therefore
missed the SHCore delay-import blocker. Milestone 1 must add bounded PE32/PE32+
delay-import parsing before its scanner can approve any deployment.

Both `rs2_deployment_preflight.exe` and `rs2_static_import_runner.exe` require an
explicit absolute `--genuine-manifest <path>` argument; there is no compiled-in
path, current-directory search, or basename fallback. CTest passes the absolute
repository manifest path. Disposable validation runs the preflight on the
target host from a user-selected, empty, non-reparse task-evidence directory
outside the game tree and supplies the absolute path to an exact copied
manifest. The invocation also requires absolute `--target-root`, `--bootstrap`,
`--companion`, and `--report` paths. It records the tool and manifest SHA-256 in
the sanitized report and writes nothing inside the stopped-server tree.
Qualification mode additionally requires an absolute, non-existing
`--qualification-output <path>` whose leaf is exactly
`<provisional-sha256>.qualification.evidence`; creation uses create-new
semantics.

The preflight executable, manifest copy, and report are custody/evidence tools,
not deployable game artifacts and are never placed beside VNGame. No build or
test target copies them to another host. After the user preserves the sanitized
report, rollback removes the task-local executable and manifest copies from the
target evidence directory. The two DLLs remain the only artifacts ever placed
in the game directory.

The read-only preflight examines the exact user-selected stopped-server tree,
does not follow directory reparse points, and fails unless:

- the selected VNGame is AMD64 and has a recognized SHA-256;
- it normally imports named
  `X3DAudio1_7.dll!X3DAudioInitialize` exactly as profiled;
- its TLS data-directory RVA and size are both zero;
- no local `faultrep.dll`, executable `.local` redirection, or unapproved proxy
  is present;
- the proposed bootstrap and companion match their recorded hashes and PE
  contracts;
- the target System32 genuine file is AMD64, has an explicitly qualified
  SHA-256, and matches the qualified file's recorded size, PE timestamp,
  `SizeOfImage`, both `VS_FIXEDFILEINFO` version quads, and both required
  names/ordinals; display-version strings are human evidence only;
- its absolute System32 path plus leaf fits the bootstrap's declared
  512-character resolver capacity;
- that exact file passes timestamp-aware embedded Authenticode verification
  through `WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)` with no UI,
  `WTD_REVOKE_NONE`, cache-only URL retrieval, and paired VERIFY/CLOSE state
  actions; only `ERROR_SUCCESS` is accepted, with no manual certificate-expiry
  override;
- all direct and delay imports of `X3DAudio1_7.dll` in the selected tree are
  reported with every required symbol;
- VNGame is the sole X3Audio importer in that stopped tree;
- no incompatible importer requires an export outside the complete two-export
  proxy surface;
- malformed PE-like files, incomplete scans, and reparse-point PE files are
  explicit failures; and
- security-product disposition and target-host KnownDLL state are recorded.

The authoritative reviewed input is
`config/qualified_x3audio_genuine.manifest`, schema 1. It uses the project's
existing bounded line-oriented convention: 7-bit ASCII, CRLF endings, no BOM,
one `key=value` pair per line, and no blank lines or escaping. Every line,
including the final line, must end in CRLF.

The fixed key order is `schema`, `entry_count`, then these complete keys for
each zero-based entry: `entry.N.state`, `entry.N.sha256`,
`entry.N.file_size`, `entry.N.machine`, `entry.N.coff_timestamp`,
`entry.N.size_of_image`, `entry.N.file_version_quad`,
`entry.N.product_version_quad`, `entry.N.export_1`, `entry.N.export_2`,
`entry.N.signature_policy`, and `entry.N.evidence_path`. Their value domains
are exact:

- `schema=1`; `entry_count` is unsigned decimal `1..32` with no leading zero;
  `N` is each contiguous decimal index `0..entry_count-1`, also with no leading
  zero except the single digit `0`;
- `state` is `provisional` or `qualified`;
- `sha256` is exactly 64 uppercase hexadecimal digits;
- `file_size` is unsigned decimal `1..18446744073709551615`, with no leading
  zero; `machine` is exactly `AMD64`;
- `coff_timestamp` is `0x` followed by exactly eight uppercase hexadecimal
  digits; `size_of_image` is unsigned decimal `1..4294967295`, with no leading
  zero;
- each version quad is four unsigned decimal components `0..65535` separated
  by dots, with no component leading zero except the single digit `0`; these
  are the `VS_FIXEDFILEINFO` values compared by preflight;
- `export_1` and `export_2` are exact literals `X3DAudioCalculate@1` and
  `X3DAudioInitialize@2`; their `@` is part of the literal, not a generic value
  character;
- `signature_policy` is exactly `embedded-winverifytrust-v2-cache-only`; and
- `evidence_path` is exactly
  `docs/evidence/x3audio/<matching-uppercase-sha256>.md`, using only
  `[A-Za-z0-9._/-]`, with no absolute form, backslash, empty component, or
  `.`/`..` component.

Human version-resource display strings, including
`9.28 (DXSDK_FEB10.100204-0932)`, exist only in the referenced Markdown evidence
record and are never parsed or machine-compared.

The initial committed manifest contains exactly this single record; the actual
file uses CRLF after every shown line, including the last:

```text
schema=1
entry_count=1
entry.0.state=qualified
entry.0.sha256=9460709339701AD471A5CABE6365355F4D586DC4FCB86507C1331839DC555446
entry.0.file_size=24920
entry.0.machine=AMD64
entry.0.coff_timestamp=0x4B6B06BE
entry.0.size_of_image=36864
entry.0.file_version_quad=9.28.1886.0
entry.0.product_version_quad=9.28.1886.0
entry.0.export_1=X3DAudioCalculate@1
entry.0.export_2=X3DAudioInitialize@2
entry.0.signature_policy=embedded-winverifytrust-v2-cache-only
entry.0.evidence_path=docs/evidence/x3audio/9460709339701AD471A5CABE6365355F4D586DC4FCB86507C1331839DC555446.md
```

The implementation also adds the exact `.gitattributes` rule
`/config/*.manifest -text -whitespace` so Git preserves those reviewed CRLF
bytes instead of normalizing the deployment-gating manifest and does not treat
the preserved CR byte as trailing whitespace during `git diff --check`. The
strict manifest parser and tests, rather than Git whitespace heuristics, enforce
the exact ASCII/CRLF grammar and inspect the worktree bytes as well as parsed
fields.

A dependency-free hand-written reader accepts at most 64 KiB, 32 entries, and
1,024 bytes per line. It rejects BOM/NUL/non-ASCII, bare LF, duplicate, unknown,
missing, misordered, malformed, unterminated-final-line, or trailing fields and
any count mismatch. No third-party parser or serialization dependency is
permitted. The preflight and normal test runner accept only `qualified` records
and never modify or auto-promote the manifest.

The first qualified genuine hash is
`9460709339701AD471A5CABE6365355F4D586DC4FCB86507C1331839DC555446`.
Its Microsoft signer certificate is expired in wall-clock terms but its
embedded time-stamp makes `WinVerifyTrust` and `Get-AuthenticodeSignature`
return valid. The preflight must not reproduce trust by comparing `NotAfter`
itself.

A different embedded-signed candidate uses this non-circular qualification
sequence:

1. In an isolated evidence directory, inspect its complete exports/ordinals and
   disassembly to confirm the legacy `void` initializer, 20-byte handle writes,
   and calculate ABI. Record hashes and tool output in
   `docs/evidence/x3audio/<sha256>.md`.
2. The project maintainer adds a `provisional` manifest record pointing to that
   evidence in a reviewed commit. This does not make any normal test or
   preflight pass.
3. An explicit, non-default runner mode
   `--qualify-system32 <provisional-sha256>` accepts only the exact provisional
   host file, runs only the fresh-process direct-System32 control vector, and
   emits `<sha256>.qualification.evidence` in the same ASCII/CRLF `key=value`
   convention. Its exact fixed key order is `schema`, `mode`,
   `manifest_sha256`, `candidate_sha256`, `candidate_file_size`,
   `candidate_machine`, `candidate_coff_timestamp`,
   `candidate_size_of_image`, `candidate_file_version_quad`,
   `candidate_product_version_quad`, `candidate_export_1`, `candidate_export_2`,
   `candidate_signature_policy`, `winverifytrust_status`, `abi_layout`,
   `child_exit_status`, and `control_digest_sha256`. `schema=1`;
   `mode=qualify-system32`; manifest/candidate/control hashes use the same
   uppercase SHA-256 grammar; candidate identity, quads, and exports use the
   manifest grammars; `candidate_signature_policy` is
   `embedded-winverifytrust-v2-cache-only`;
   `winverifytrust_status=ERROR_SUCCESS`; `abi_layout=pass`; and
   `child_exit_status=0x00000000`. There is no floating-point serialization.
   The writer uses bounded fixed templates, requires a final CRLF, rejects
   partial writes, and never overwrites an existing record. It emits a record
   only after every listed check succeeds; failure returns nonzero and leaves
   no evidence file. It never loads the proxy and cannot be used as deployment
   evidence.
4. After reviewing that run and appending its sanitized result to the evidence
   record, the project maintainer changes the record to `qualified` in a second
   reviewed commit. Only that state enables the normal suite and preflight.

Catalog-only signatures are not accepted in Milestone 1 and cannot enter this
qualification flow; supporting one requires a new reviewed design amendment.

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
   only complete successes are offered, exactly one normal INIT_ONCE success is
   published, losing module references are released, and a worker failure
   remains retryable; publication-allocation/API failure after private success
   publishes or reuses the static fallback, forwards successfully, and does not
   grow retained references across repeated calls; separate injections cover
   `InitOnceComplete` false with a visible winner, false without a winner, and
   acquire readers refusing `Empty` or `Writing` fallback records;
3. resolver validation: null, self module, wrong file identity, one/both exports
   missing, failed `VirtualQuery`, and wrong allocation base, plus classification
   and exactly one export retry for injected resource/API failures;
4. initialize exact argument/output fidelity and isolated resolver-failure
   fail-fast behavior;
5. calculate exact pointer/flag/output fidelity and isolated resolver-failure
   fail-fast behavior;
6. companion ABI V2 size/version, required export mask, reserved field, and
   module-handle validation;
7. existing build identities, stock-input immutability, path identity, the new
   `ExtractDirectoryAndLeaf` path-capacity and `AppendPathLeaf`
   directory/leaf/output-capacity contracts, and bounded companion-path
   construction;
8. marker schema 2, fallback, short-write cleanup, terminal line, and forbidden
   content scan;
9. success-console formatting for every eligible build identity, rejection of
   indeterminate/out-of-range identities, exact current-full-dump bytes and
   CRLF, fixed-buffer boundaries, null/invalid output handles, failed/zero/short
   writes, exactly one write call, no sensitive content, nonfatal console
   failure after a complete marker, no console attempt after marker failure,
   and one status line under duplicate/concurrent initialization; the displayed
   version must equal the shared VERSIONINFO source;
10. the shipped manifest parses to exactly the canonical qualified seed record
   above; manifest size/line/entry bounds, fixed field order, every value domain,
   required final CRLF, malformed/duplicate/unknown/trailing rejection,
   provisional/qualified gate, qualification-evidence round-trip, no-overwrite,
   and short-write cleanup are covered; required absolute CLI paths have no
   fallback search; and
11. proof that no known build identity permits hook/patch behavior.

### Built-PE contracts

The PE tool fails unless:

- the bootstrap is AMD64 with required security flags;
- its imports obey the bootstrap allowlist and contain no X3Audio self-import;
- it exports exactly the two named functions at ordinals 1 and 2;
- it has a VERSIONINFO resource whose `CompanyName` and `ProductName` identify
  the `RS2ServerFix` project and contain no claim of Microsoft, Epic, or
  Tripwire authorship;
- the companion is AMD64 with its separate import/export contract;
- the companion has the corresponding non-Microsoft `RS2ServerFix`
  VERSIONINFO identity;
- both VERSIONINFO resources contain fixed and display version `0.1.0.0`; a
  separate source/unit-test gate proves both resources and the console formatter
  consume the same project-version definitions;
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

The production proxy target keeps its ordinal-bearing `.def`, so its generated
import library is not used by test consumers. The harness and both import
fixtures instead link a test-only by-name import library generated by `lib.exe`
from an ordinal-free `.def` with `/NAME:X3DAudio1_7.dll /MACHINE:X64`. Their PEs
therefore contain a named `X3DAudio1_7.dll!X3DAudioInitialize` import while
control cases omit the local proxy file. The harness declares that imported
function with the legacy `void` ABI. To exercise calculate, it enumerates loaded
modules by full path, selects the intended local or System32 module handle
unambiguously, and resolves `X3DAudioCalculate` from that exact handle. Before
running any normal functional case, the runner requires the build host's
System32 file to exist and match a `qualified` manifest record; absence,
`provisional` state, or mismatch is a clear test failure, not a skip or a
generic child-process loader error. The separate provisional qualification mode
is the only exception and cannot report the normal suite as passed.

Every functional case zero-initializes the handle, listener, emitter, settings,
matrix, delay array, and padding, then runs one fixed valid
initialize/calculate vector in this order: call the statically imported
initializer, enumerate and assert the expected full-path module set, resolve
calculate from the exact selected module handle, then call calculate. The
harness emits a deterministic digest covering only the 20 handle bytes, eight
DSP output scalars, `pMatrixCoefficients[SrcChannelCount * DstChannelCount]`,
and `pDelayTimes[DstChannelCount]`; it never hashes pointer values or raw
structure padding. The runner compares proxy-case digests with the System32
control and captures stdout. It does not use basename-only `GetModuleHandleW`
or discard child output.

Each case runs in a fresh, bounded child process:

1. **System control:** harness only; the qualified System32 X3Audio loads and
   produces the reference digest.
2. **Companion only:** harness plus companion; System32 still loads and no
   marker appears.
3. **Bootstrap only:** local proxy loads, both genuine exports validate, an
   initialize/calculate vector matches the control digest, two distinct
   expected X3Audio full paths are enumerated, and no companion marker appears.
4. **Both files:** local proxy plus companion; complete marker proves genuine,
   companion, ABI, and host identity, and captured stdout contains exactly one
   success line with `host=unknown` because the harness executable is not a
   preserved VNGame identity.
5. **Invalid companion:** genuine calls still match control; no complete marker.
6. **Missing genuine simulation:** a non-deployable test-only bootstrap is
   compiled with an absent System32 genuine leaf while retaining local output
   name `X3DAudio1_7.dll`; it is emitted only beneath a distinct
   `test-invalid-genuine` output directory and is excluded from every artifact
   or deployment manifest by target identity and hash. Separate initializer
   and calculate children must exit with exactly `0xC0000602` without modifying
   System32.
7. **Concurrent first calls:** multiple initializer/calculate callers plus the
   worker produce consistent control digests, exactly one captured success line
   with `host=unknown`, and no hang; publication count, attempt count, and
   loser-cleanup assertions live in the injected unit test, not in
   external-process inference.
8. **Invalid bootstrap:** process creation or loader termination fails, proving
   there is no promised fallback after local selection.
9. **Rollback:** remove both while no child runs; System32 control succeeds.

Cases 01-03, 05-06, 08, and 09 must contain no success-console line. The runner
parses that line independently from the one required `digest_sha256=` line so
the diagnostic cannot weaken or contaminate the forwarding-fidelity check.
For complete-marker cases, the short-lived harness uses its separately opened
redirected-output file only to wait a bounded two seconds for the exact line
after the marker; this prevents process exit from terminating the worker between
marker close and console write. The runner's post-mortem raw-byte/count parse
remains authoritative. This is test-only observation, not production
synchronization.

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
   initialization and capture the loaded System32 X3Audio path.
7. Establish a stable module set with two consecutive identical enumerations,
   bounded to three complete attempts. For every entry, record module base,
   image size, full path, and file identity, then parse the backing PE's normal
   and delay imports. A vanished or changed entry restarts the complete
   enumeration; an unreadable, pathless, malformed, or still-unstable entry is
   recorded by sanitized identity and hard-stops Milestone 1. No entry is
   silently skipped and there is no adjudication exception in this milestone;
   accepting such a module requires a reviewed design amendment. Only a
   complete parse may conclude that VNGame is the sole X3Audio importer. Retain
   the sanitized module/import report as the static-call timing evidence, then
   stop normally.

### Two-file pass

1. While stopped, place only the exact reviewed Release
   `X3DAudio1_7.dll` and `RS2ServerFix.dll` beside VNGame.
2. Start with the identical command and environment.
3. Require both local bootstrap and genuine System32 X3Audio in the module
   inventory, one complete schema-2 marker, and one exact visible console status
   whose host identity matches the selected VNGame hash. For the planned
   current full-dump run this is the exact line shown above. Record the line as
   evidence; its absence fails the two-file pass even though console output is
   non-authoritative inside the DLL.
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
3. Preserve the sanitized report outside the target-host task directory, then
   remove only the copied preflight executable, manifest, and named temporary
   child outputs from that directory.
4. Restart once and prove the System32 X3Audio path and normal services.
5. Confirm that control and rollback show no RS2ServerFix success status.
6. Retain control/pass/rollback evidence and exact tested hashes.

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
- recognized VNGame has no TLS directory, stopped-tree and complete control
  runtime scans identify VNGame as the sole static X3Audio importer, and the
  residual dynamic-`GetProcAddress`-from-`DllMain` case is recorded rather than
  claimed away;
- the offline System32-control digest proves both X3Audio exports preserve the
  qualified legacy ABI and defined output behavior when the proxy is present;
- companion absence/failure cannot break valid genuine forwarding;
- no export performs companion work, logging, hashing, or game-memory access;
- concurrent first callers never wait on project synchronization while loading
  the genuine module; the normal INIT_ONCE path publishes exactly one complete
  success, injected publication failure yields at most one immutable static
  fallback without repeat reference growth, and repeated immediate-exit
  children do not hang;
- control/companion-only/rollback load System32 directly;
- bootstrap cases prove local bootstrap plus separately validated System32
  genuine module;
- the exact disposable server proves local/bootstrap and System32/genuine
  coexistence and passes control/proxy/rollback with Steam, EOS, EAC, join,
  travel, WebAdmin, and shutdown intact; the proxy pass also shows exactly one
  success-console line matching the selected host identity while control and
  rollback show none; forwarding fidelity remains an offline-harness claim
  because VNGame imports only the initializer and the X3Audio exports
  intentionally emit no diagnostics;
- pre/post hashes prove no protected executable, shipped DLL, or configuration
  changed; expected runtime logs and named marker evidence are excluded from
  that invariant and retained separately;
- deployable artifacts are limited to two manually placed DLLs and sanitized
  evidence; target-host custody copies of the read-only preflight and manifest
  stay outside the game tree and are removed after the report is preserved; and
- no production/public server, client, anti-cheat bypass, game hook, or
  performance claim is involved.

The accepted residual risk statement must accompany any Milestone 1 artifact:
`CreateThread` from `DllMain` is a pragmatic startup trigger, is documented by
Microsoft as risky, and cannot be proven safe against every third-party
process-detach lock. Offline early-exit repetition plus bounded disposable
shutdown are required evidence, not a claim that the platform risk is absent.
Static import/TLS evidence cannot rule out a third-party dynamic call from its
own `DllMain`. A correctly preflighted host can also fail fast with
`0xC0000602` after two resource/API failures or in the final publication-check
micro-race; the legacy void ABI offers no safe error return. Those are accepted
only for the disposable Milestone 1 experiment and must be revisited before
any production proposal.

## Deferred milestones

After the user separately accepts Milestone 1 runtime evidence, a new reviewed
design may add low-overhead timing instrumentation to `RS2ServerFix.dll`.
EasyHook versus a minimal detour implementation, exact current-build hook
addresses, sampling overhead, worker queues, logging offload, and any
relevancy/collision optimization remain out of scope here.

No Milestone 1 result proves that Unreal objects, world collision, replication,
EOS callbacks, or game logic can safely execute on another thread.
