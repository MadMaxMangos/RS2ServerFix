# RS2 Passive `faultrep.dll` Proxy Design

Date: 2026-08-22

Revised: 2026-08-29 after external design review

Stage: 0 - loader and forwarding proof only

## Goal

Prove that an x64 DLL named `faultrep.dll`, placed beside the dedicated-server executable on a disposable server copy, can load at process startup, preserve the operating system's `ReportFault` behavior after one-pass asynchronous initialization, identify the host executable, and record a minimal diagnostic marker without modifying game memory or any existing file.

The proof establishes a reversible loader for a later ADF crash mitigation. Stage 0 contains no engine hooks, detours, byte patches, allocator changes, ADF logic, anti-cheat interaction, or live-server deployment.

## Evidence and fixed inputs

- Crash-producing executable SHA-256:
  `155EBC77D2FA574F0A94709839EF1DF6A3DA82B278C846F14223967B058C4622`
- Preserved pre-full-dump baseline SHA-256:
  `5820F0DA82D7C2903DE31E0865320D9E70A0BF74F78F83C83DB4F9DEEAEB1DEF`
- The only functional difference between those executables is the dump-type byte at file offset `0x00a6a313` changing from `0x40` to `0x42`; the other changed byte, at `0x000001e1`, is the PE checksum.
- Newly shipped/current stock executable SHA-256, copied from another VM and locally labelled PR3:
  `F4E38510832D1FAADA8AAD3B88CD2255B3EA49267EF0E874468E23BDE4EDFCC3`
- Full-dump-modified copy of that current executable SHA-256:
  `0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393`
- Those current-build files likewise differ only at file offset `0x00a6bb43` (`0x40` to `0x42`) plus the PE checksum byte at `0x000001e1` (`0xf7` to `0xf9`).
- The preserved PR1 executable is AMD64 and imports `ReportFault` from `faultrep.dll` by name.
- The PR1 crash dump captured `Faultrep.dll` loaded from the operating-system `System32` directory.
- `faultrep.dll` was not listed under KnownDLLs on the examined host. This is host-specific and must be rechecked by the static-import test on the disposable target.
- `dinput8.dll` was neither imported nor loaded by PR1.
- The server-directory `dbghelp.dll` must remain untouched because existing full-dump handling uses it.
- The Windows SDK declares:

  ```cpp
  EFaultRepRetVal APIENTRY ReportFault(
      LPEXCEPTION_POINTERS exceptionPointers,
      DWORD options);
  ```

- The examined Windows 11 System32 DLL exports `ReportFault` by name at ordinal 13. The host imports by name, so the name is the required contract and the ordinal is a separately checked compatibility detail.

The patched PR1 executable was no longer present in the former analysis directory at the time of this revision. The preserved baseline remains available. Tests may construct a temporary derived copy from the baseline using the two verified byte changes above and must verify that the result has the crash-producing SHA-256. The baseline itself must never be edited. Both current-build files are present under `D:\Documents\RisingStorm2\Binaries`; their PR3 filenames are local analysis labels, not different game editions.

## Design constraints from Windows behavior

- `DllMain` runs while the loader lock is held. It must not call `LoadLibrary`, wait for another thread, perform hashing, write diagnostics, or invoke APIs with uncertain loader dependencies.
- Creating a thread from `DllMain` is documented as risky but can work when no synchronization with that thread occurs. Because the host exposes no explicit post-start initialization callback, one minimal `CreateThread` is the selected compromise and is tested under the same load-time-import conditions as the server.
- `InitOnceExecuteOnce` is synchronous: competing callers block until the initializer completes. It must not guard work that may need the loader lock while a caller can already hold that lock.
- `ReportFault` runs on an exceptional and potentially heap-corrupt path. It must remain allocation-free, lock-free, file-free, and loader-free.
- A local load-time import can prevent process creation if the proxy is missing a dependency, has the wrong architecture, is blocked by policy, or fails initialization. Stage 0 cannot promise graceful System32 fallback after the loader selects an invalid local file.
- The proxy uses the static CRT (`/MT`). Microsoft explicitly says not to call `DisableThreadLibraryCalls` from a DLL linked with the static CRT, so Stage 0 does not call it.
- Two DLLs with the same basename in different fully qualified paths are distinct modules for run-time loading. A fully qualified System32 load is still followed by identity checks so redirection or an implementation error cannot publish the proxy itself.

Primary references:

- [Dynamic-Link Library Best Practices](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices)
- [DllMain entry point](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain)
- [One-Time Initialization](https://learn.microsoft.com/en-us/windows/win32/sync/one-time-initialization)
- [Dynamic-Link Library Search Order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [LoadLibraryEx](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw)
- [DisableThreadLibraryCalls](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-disablethreadlibrarycalls)
- [ReportFault](https://learn.microsoft.com/en-us/windows/win32/api/errorrep/nf-errorrep-reportfault)

## Scope

Stage 0 delivers:

1. A small native AMD64 proxy built as `faultrep.dll`.
2. A single public export, `ReportFault`, with the documented ABI.
3. Worker-only resolution and validation of genuine `System32\faultrep.dll!ReportFault`.
4. Crash-path forwarding through one atomically published function pointer.
5. SHA-256 host identification with explicit historical/current build identities and fail-closed unknown states.
6. Privacy-minimal marker and debug-milestone diagnostics.
7. Unit, integration, static-import, PE-contract, and deployment-preflight tests.
8. Manual disposable-server smoke-test and rollback instructions.

## Non-goals

Stage 0 will not:

- alter or replace either PR1 executable;
- alter, rename, proxy, or import the local `dbghelp.dll`;
- hook ADF or any other game function;
- inspect or modify player, Steam, EOS, EAC, network, or mutator state;
- suppress, evade, or interact with anti-cheat checks;
- inject into another process;
- deploy files to a production or public server;
- deliberately crash the live or disposable game server;
- repair, reconstruct, or otherwise touch the captured ADF pool;
- guarantee forwarding during the brief interval before worker resolution completes;
- support an unknown executable for future patch behavior.

## Build and binary contract

The project uses CMake and the installed MSVC AMD64 toolchain.

Required proxy properties:

- AMD64 PE DLL;
- Release static CRT (`/MT`), never `/MD`;
- no external package or managed-runtime dependency;
- no user-defined static TLS, `thread_local`, function-local static, or C++ object requiring dynamic construction/destruction;
- no call to `DisableThreadLibraryCalls`;
- expected direct-import allowlist of `KERNEL32.dll` and `bcrypt.dll` only;
- explicitly no import of `dbghelp.dll`, User32, Shell, COM, networking, or a Visual C++ runtime DLL;
- `/DYNAMICBASE`, `/NXCOMPAT`, and `/HIGHENTROPYVA` enabled;
- `ReportFault` exported by name;
- ordinal 13 may also identify that named export, without `NONAME`; ordinal mismatch is reported separately and does not override the required name check;
- no additional public exports in the production DLL.

If the compiler emits a dependency outside the expected allowlist, the build/test gate fails. The dependency is investigated rather than silently added to the allowlist.

Repository layout:

```text
RS2ServerFix/
  .gitignore
  CMakeLists.txt
  docs/
    superpowers/specs/
    disposable-server-test.md
  src/
    faultrep_proxy/
  tests/
  tools/
```

Build products remain under an ignored `build/` directory or another explicitly selected output directory. No build, test, install, or packaging target copies a DLL into a game/server directory.

## Runtime architecture

### Static state

All writable global state is zero-initialized plain data:

- `HMODULE g_selfModule`;
- atomically accessed `ReportFault` function pointer `g_reportFault`;
- optional integer milestone/error codes used by in-process unit seams.

There are no global constructors, destructors, locks, `INIT_ONCE` objects, heap-backed containers, or function-local statics.

### `DllMain`

On `DLL_PROCESS_ATTACH`, `DllMain` performs only:

1. store `hinstDLL` in `g_selfModule`;
2. call Win32 `CreateThread` once for the worker;
3. close the returned thread handle without waiting if creation succeeded;
4. return `TRUE` on every path.

It does not call `DisableThreadLibraryCalls`, `LoadLibrary`, CNG, file APIs, debug-output APIs, path APIs, the CRT, or any synchronization wait. A worker-creation failure does not fail process attach. It leaves the forwarding pointer null.

`DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` do nothing. `DLL_PROCESS_DETACH` does nothing, including during process termination. It never waits and never calls `FreeLibrary`.

The design accepts the documented residual risk of calling `CreateThread` from `DllMain`; there is no safe host callback available and the rejected alternatives are worse:

- loading the genuine DLL inside `DllMain` can deadlock under the loader lock;
- resolving lazily inside `ReportFault` performs loader/heap work on the crash path;
- thread-pool, COM, shell, or managed scheduling introduces additional loader dependencies;
- copying or renaming an operating-system DLL creates servicing and provenance problems.

### Module lifetime

In the production scenario, `faultrep.dll` is a load-time import of the server executable and remains mapped for process lifetime. The worker therefore does not permanently pin the proxy and does not add a self-reference.

Integration tests run the loader in a fresh process and end the process after the terminal marker is observed. They never call `FreeLibrary` while the worker may execute. Unit tests exercise independently compiled core functions rather than dynamically unloading the production DLL.

After successful genuine resolution, its `LoadLibraryExW` reference is intentionally retained until process termination so the published function pointer cannot dangle. Failed candidates are released from the worker after validation has completed.

### Worker ordering

The worker performs one non-retrying pass in this order; hashing has the soft budget defined below, while operating-system loader and file calls are not falsely described as time-bounded:

1. emit a leaf-name-only `worker-start` debug milestone;
2. resolve and validate genuine `ReportFault`;
3. atomically publish the validated pointer, or leave it permanently null and record a resolver error;
4. resolve the host path and hash/classify the executable;
5. write one marker, first beside the executable and then to the process temporary directory if the primary location fails;
6. emit a terminal `worker-complete` debug milestone and return.

Genuine reporter resolution precedes hashing so the crash-forwarding gap is as short as practicable. There is no retry loop. A failure remains fail-closed for the life of the process.

### Genuine `ReportFault` resolution

The worker:

1. obtains the System32 directory with `GetSystemDirectoryW` into an explicitly bounded wide-character buffer;
2. appends `\faultrep.dll` only after checking capacity;
3. calls `LoadLibraryExW(absolutePath, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)`;
4. rejects a null handle;
5. rejects `candidateModule == g_selfModule`;
6. obtains the actual candidate path with `GetModuleFileNameW`;
7. opens the expected System32 file and candidate file for attributes using all three share flags and compares volume serial plus file index, avoiding case, junction, short-name, and prefix-sensitive string identity;
8. resolves `ReportFault` by name with `GetProcAddress`;
9. rejects a null `GetProcAddress` result;
10. uses `VirtualQuery` on the returned address and rejects it if `VirtualQuery` fails or the allocation base is `g_selfModule`;
11. atomically publishes the pointer only after every validation succeeds.

No code path uses name-only `LoadLibraryW(L"faultrep.dll")` or `GetModuleHandleW(L"faultrep.dll")` to find the genuine module. The candidate module path may be recorded as the constant classification `system32` but is not copied verbatim into the marker.

If module identity or target-address validation fails, the worker releases only the extra candidate reference, records the reason, leaves the function pointer null, and never retries.

### Exported `ReportFault`

The exported function:

1. atomically reads the published function pointer using an interlocked operation;
2. returns `frrvErrNoDW` immediately if it is null;
3. otherwise calls the genuine function with the original two arguments and returns its value unchanged.

`frrvErrNoDW` is the documented result for an error-reporting client that could not be launched, allowing the system to perform its default action. It is more accurate than `frrvErr`, which states that the reporting client was launched but failed.

The forwarder performs no lazy initialization, loader call, allocation, lock, logging, file access, hash work, exception swallowing, or retry. It does not promise a compiler tail call; behavioral ABI fidelity is the requirement. On x64, both parameters and the return value must pass unchanged under the platform calling convention.

### Host hashing and build identity

After reporter publication, the worker:

1. gets the host image path with `GetModuleFileNameW(nullptr, ...)` into a bounded buffer large enough for the Win32 extended path limit;
2. opens it with `GENERIC_READ`, `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`, and `FILE_FLAG_SEQUENTIAL_SCAN`;
3. reads 64 KiB chunks from a `VirtualAlloc` buffer;
4. computes SHA-256 using Windows CNG;
5. compares the 32 raw digest bytes against compile-time byte arrays;
6. checks a 10-second soft budget between reads, abandoning further hashing if exceeded;
7. closes all file, CNG, and virtual-memory resources before returning.

The soft budget cannot interrupt a blocked `ReadFile`; it only prevents continued work after control returns. The target executable is approximately 24 MB, so exceeding the budget is diagnostic rather than expected.

Build identities are distinct:

- `pr1-crash-full-dump`: exact historical crash-producing PR1 hash;
- `pr1-stock-baseline`: exact preserved pre-full-dump PR1 hash;
- `current-stock`: exact newly shipped/current stock hash;
- `current-full-dump`: exact full-dump-modified current hash;
- `unknown`: hashing succeeded but the digest is not a known build;
- `indeterminate`: path, file, size, CNG, read, or time-budget failure prevented a verified digest.

These values identify builds; they do not grant patch compatibility. Stage 0 performs no patch for any identity. A later ADF stage must independently analyze the newly shipped executable and declare the exact eligible hash; it must not inherit eligibility from the historical PR1 result.

### Diagnostics and marker

The worker uses two bounded channels:

- `OutputDebugStringW` milestones for load/resolution/hash/marker outcomes;
- one UTF-8 marker file.

No diagnostics occur inside `DllMain` or `ReportFault`.

Marker name:

```text
RS2ServerFix.loader.<pid>.log
```

The worker attempts the executable directory once. If opening or writing fails, it attempts the directory returned by `GetTempPathW` once. It records the primary Win32 error when the fallback succeeds. There is no retry loop and no directory creation.

Marker schema version 1 contains only:

- schema version;
- UTC timestamp;
- process ID;
- executable leaf filename and size;
- SHA-256 when available;
- one of the six host build identities;
- proxy leaf filename and whether it is in the executable directory;
- resolver status code;
- genuine module classification (`system32` or `unavailable`);
- primary marker-write error when fallback was required;
- terminal `completion=complete` or `completion=partial` written last.

It excludes full executable/proxy paths, command line, environment variables, account identifiers, usernames, network addresses, tokens, player data, exception data, and memory contents. Tests inspect content for forbidden path/account fragments, not only field names.

If both marker locations fail, debug milestones remain the only diagnostic. If no debugger is listening, this failure is silent by design and the static-import test treats marker absence as failure.

## Failure behavior

| Failure | Required behavior |
|---|---|
| Local proxy rejected/missing dependency/wrong bitness | Windows may fail process creation; preflight must prevent deployment. |
| User `DllMain` path | Always returns `TRUE`; performs no wait or diagnostic. |
| Worker creation | Process continues; target stays null; no marker is possible; `ReportFault` returns `frrvErrNoDW`. |
| Genuine DLL load/identity/export | Leave target null permanently; record reason when worker diagnostics are available. |
| Early `ReportFault` | Return `frrvErrNoDW` immediately; never attempt initialization. |
| Hash/path/read/CNG/time | Identify as `indeterminate`; forwarding result is unaffected. |
| Unknown digest | Identify as `unknown`; forwarding result is unaffected. |
| Primary marker write | Attempt temporary-directory fallback once. |
| Both marker writes | Emit debug failure milestone and exit worker. |
| Process termination | No detach cleanup or wait; operating system tears down retained handles/mappings. Exit may briefly wait if the worker is already inside an in-flight loader operation. |

No proxy-controlled failure shows UI, performs network access, edits the executable, calls `ReportFault` recursively, or attempts to repair state.

## Test strategy

Implementation proceeds test-first. Tests use fresh temporary directories and never copy artifacts to a game/server directory.

### Unit tests

1. **Build identity:** the four exact historical/current hashes, arbitrary unknown, and indeterminate cases remain distinct.
2. **SHA-256:** a fixed small file and the preserved baseline produce expected digests.
3. **Derived full-dump fixtures:** copy each stock executable to a temporary file, apply only its two verified byte changes, verify the corresponding full-dump SHA-256, and delete the temporary copy. Never alter either stock input.
4. **Path bounds:** System32, host, marker, and oversized/truncated path cases fail closed without buffer overrun.
5. **File identity:** identical file, alternate path to the same file, and different file exercise volume/file-index comparison.
6. **Resolver validation:** self `HMODULE`, self allocation base, missing export, wrong file identity, and genuine success paths leave/publish the pointer as required.
7. **Marker schema/privacy:** required fields, terminal completion record, primary/fallback errors, no full paths, no `\Users\` fragment, and no environment expansion.
8. **No patch behavior:** every Stage 0 build identity leaves game code/data untouched.

### Built-PE contract test

Parse the production DLL and fail unless:

- machine is AMD64;
- it is a DLL;
- ASLR, NX, and high-entropy VA flags are present;
- `ReportFault` is exported by name;
- no unexpected public export exists;
- ordinal 13 is reported separately;
- all direct imports are within the reviewed allowlist;
- no dynamic Visual C++ runtime or `dbghelp.dll` import exists.

The export name and import allowlist are hard gates. Ordinal 13 is compatibility information unless an observed target importer requires it.

### Static-import harness

A small AMD64 executable links against `Faultrep.lib` so its import table contains a name import for `ReportFault`, but it never calls the function with fabricated exception data.

Each case runs in a new process:

1. **System control:** no local proxy; process must start and report that loaded `faultrep.dll` is under System32.
2. **Local proxy:** tested proxy beside the harness; process must start, report that the loaded import is the local proxy, observe a complete marker within a fixed timeout, and confirm the marker reports a validated System32 target.
3. **Rollback:** remove the proxy while no harness process is running; repeat the system control.
4. **Invalid-local negative:** in a temporary directory only, place an intentionally invalid file as `faultrep.dll` and confirm that process startup fails. This records the static-import failure mode rather than pretending System32 fallback occurs.

The harness never calls `FreeLibrary`. Process exit ends each case. No deliberate crash is generated.

### Deployment preflight scanner

Before a disposable server test, a read-only tool scans every PE file in the exact executable directory/tree selected by the user and records:

- path relative to the selected root;
- machine type;
- every import from `faultrep.dll`, by name or ordinal;
- whether an executable redirection artifact such as `<exe>.local` is present.

The gate fails if any relevant importer is not AMD64, requires an export other than named `ReportFault`, or cannot be parsed. A file list from a different VM is not sufficient evidence.

### Optional diagnostic checks

- Run the static-import harness under Application Verifier loader checks if available.
- Capture loader events with Process Monitor or loader snaps in the disposable test environment if the local-path assertion fails.
- Confirm AV/EDR, WDAC, and AppLocker disposition before placing the unsigned test DLL.

## Disposable-server smoke test

The test is manual, performed by the user on a stopped disposable copy with no public players. Codex does not deploy the DLL.

### Control

1. Confirm the disposable executable path and SHA-256.
2. Confirm no local `faultrep.dll`, executable `.local` redirection, or prior marker remains.
3. Run the deployment preflight scanner and retain its report.
4. Record AV/EDR, WDAC, and AppLocker status relevant to unsigned DLL loading.
5. Capture a recursive directory listing and SHA-256 manifest for at least the executable, `dbghelp.dll`, and root-level PE files.
6. Start the server with its normal command line, wait for Steam, EOS/EAC, networking, map and WebAdmin initialization, capture the log, then stop normally.

### Proxy pass

1. With the server stopped, copy only the exact offline-tested `faultrep.dll` beside the executable.
2. Start with the same command line and environment as the control.
3. Confirm the local proxy is the loaded `faultrep.dll` and the marker reports validated System32 resolution.
4. Compare startup behavior and logs against the control for Steam, EOS/EAC, networking, map and WebAdmin initialization.
5. Observe idle operation for a bounded period agreed before the test.
6. Stop normally and capture the same listing/hash manifest.
7. Diff logs and manifests. The executable, `dbghelp.dll`, configurations, and shipped DLLs must be unchanged.

### Rollback

1. Ensure the server process is stopped; a mapped DLL cannot be removed reliably while it is running.
2. Remove the local proxy and its marker files.
3. Restart once with the original command and confirm System32 resolution and normal initialization.
4. Retain the control, proxy, rollback logs, manifests, preflight report, and tested proxy hash together.

Any startup failure, security-product intervention, unexpected import, missing/partial marker, genuine-resolution failure, service regression, integrity difference, shutdown hang, or rollback failure stops Stage 0. Do not continue to ADF work.

## Success criteria

Stage 0 succeeds only when current evidence proves all of the following:

- unit, PE-contract, and static-import tests pass on AMD64;
- the static-import control loads System32, the proxy case loads locally and validates System32 forwarding, and rollback returns to System32;
- `ReportFault` contains no lazy initialization path;
- all four known build identities plus unknown and indeterminate states are verified;
- the exact deployment tree contains no incompatible importer;
- a disposable server starts, initializes its normal services, stops, and restarts after removal;
- pre/post hashes prove no existing executable, configuration, `dbghelp.dll`, or shipped DLL changed;
- runtime artifacts are limited to the manually placed proxy and diagnostic marker/log captures;
- no deliberate crash, public player traffic, anti-cheat bypass, or production deployment occurred.

## Later stage, explicitly excluded

After Stage 0 is proven, a separate reviewed design may add ADF mitigation. The intended direction remains:

- one single-flight pack guard;
- chunk-index, state, count, raw-length, cycle, visit-count, and destination-capacity validation;
- fail-closed abort and diagnostics on corruption;
- no live free-list reconstruction;
- exact executable-hash gating and original-byte validation;
- independent rollback and concurrency testing.

Stage 0 does not reserve implementation details or claim that the later hook is safe merely because the loader works.
