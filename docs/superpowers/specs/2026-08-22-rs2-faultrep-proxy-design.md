# RS2 Passive `faultrep.dll` Proxy Design

Date: 2026-08-22  
Stage: 0 - loader and forwarding proof only

## Goal

Prove that an x64 DLL named `faultrep.dll`, placed beside the dedicated-server executable on a disposable server copy, can load at process startup, preserve the operating system's `ReportFault` behavior, and record a minimal diagnostic marker without modifying game memory or files.

The proof establishes a reversible loader for a later ADF crash mitigation. This stage contains no engine hooks, detours, byte patches, allocator changes, or ADF logic.

## Evidence and fixed inputs

- Crash-producing executable SHA-256:
  `155EBC77D2FA574F0A94709839EF1DF6A3DA82B278C846F14223967B058C4622`
- Pre-full-dump baseline SHA-256:
  `5820F0DA82D7C2903DE31E0865320D9E70A0BF74F78F83C83DB4F9DEEAEB1DEF`
- The only functional difference between those executables is the dump-type byte changing from `0x40` to `0x42`; the other changed byte is the PE checksum.
- The executable imports `ReportFault` from `faultrep.dll` by name.
- The PR1 dump captured `Faultrep.dll` loaded from the operating-system `System32` directory.
- `faultrep.dll` is not a KnownDLL on the examined host.
- `dinput8.dll` was neither imported nor loaded by PR1.
- The server-directory `dbghelp.dll` must remain untouched because existing full-dump handling uses it.

## Scope

The Stage 0 deliverables are:

1. A small native x64 proxy built as `faultrep.dll`.
2. An exported `ReportFault` with the documented `ErrorRep.h` ABI:

   ```cpp
   EFaultRepRetVal APIENTRY ReportFault(LPEXCEPTION_POINTERS, DWORD);
   ```

3. Resolution and invocation of the genuine `System32\faultrep.dll!ReportFault`.
4. A worker that runs after process attach and writes a minimal marker log.
5. SHA-256 identification of the host executable, with explicit recognition of the crash-producing PR1 build.
6. An offline test harness and automated contract checks.
7. Disposable-server smoke-test and rollback instructions.

## Non-goals

Stage 0 will not:

- alter or replace either `VNGame_pr1.exe` copy;
- alter, rename, or proxy `dbghelp.dll`;
- hook ADF or any other game function;
- inspect or modify player, Steam, EOS, EAC, network, or mutator state;
- suppress, evade, or interact with anti-cheat checks;
- inject into any process remotely;
- deploy files to the live server;
- deliberately crash the live or disposable game server;
- repair the captured ADF corruption.

## Architecture

### Proxy module

The proxy is a native x64 Windows DLL with no managed runtime dependency. Its output filename is exactly `faultrep.dll`.

`DllMain` performs only minimal setup deliberately constrained for loader-lock context:

1. store its own module handle;
2. disable thread attach/detach notifications;
3. create a worker thread without waiting for it;
4. return immediately.

The design relies on Windows loader serialization delaying the new thread's DLL-dependent work until process attach returns. No file I/O, hashing, game inspection, loading of the real DLL, or synchronization waits occur inside `DllMain`. The load/unload harness specifically tests this choice for hangs and re-entry.

### Post-attach worker

After `DllMain` returns, the worker:

1. resolves the host executable path;
2. computes its SHA-256 using Windows CNG (`BCrypt`);
3. classifies it as supported, known pre-full-dump, or unknown;
4. resolves the genuine `System32\faultrep.dll` from an absolute system path;
5. resolves the genuine `ReportFault` address;
6. confirms with `GetModuleFileNameW` that the resolved module is the system copy rather than the local proxy;
7. writes one UTF-8 marker log beside the host executable;
8. exits without modifying process code or data.

The marker filename includes the process ID to avoid collisions between multiple servers in one directory:

```text
RS2ServerFix.loader.<pid>.log
```

The marker contains only:

- UTC timestamp;
- process ID;
- executable filename, size, and SHA-256;
- proxy path;
- supported/unsupported classification;
- whether the genuine `ReportFault` resolved successfully.

It does not record command-line arguments, environment variables, account identifiers, network addresses, tokens, or player data.

### Genuine `ReportFault` forwarding

The proxy exports `ReportFault` by name and with ordinal 13, matching the observed operating-system export.

Resolution uses an absolute path built from `GetSystemDirectoryW`; it never searches the current directory for the genuine DLL. Initialization is guarded by `INIT_ONCE` so the worker and an unexpectedly early caller cannot race.

The exported function tail-calls the genuine function with the original arguments and returns its result unchanged. If genuine resolution fails, it returns `frrvErr`. It must not create recursive error reporting or attempt to load the local proxy again.

The executable imports only `ReportFault`. Stage 0 intentionally exports only that required contract. The disposable-server startup test is the gate that detects whether another startup module unexpectedly requires additional `faultrep.dll` exports. If it does, implementation stops and the proxy contract is expanded before any further test.

## Host-build gate

The loader itself must continue to forward `ReportFault` for any host so it does not break Windows error handling merely because the executable is unknown.

All future patch behavior is gated on the exact crash-producing executable hash. At Stage 0 there is no patch behavior; the classification exists to exercise and verify this safety boundary.

Classification rules:

- `155EBC...C4622`: supported full-dump PR1 build;
- `5820F0...B1DEF`: known pre-full-dump baseline, no future patch;
- every other hash: unsupported, no future patch.

No offset or signature fallback is permitted in Stage 0.

## Failure behavior

- If worker creation fails, the proxy still loads and `ReportFault` retains lazy resolution.
- If hashing fails, the host is classified unsupported.
- If the marker cannot be written, no retry loop or fatal error occurs.
- If the genuine DLL cannot be loaded or `ReportFault` cannot be resolved, the exported function returns `frrvErr` and the marker records the failure when possible.
- No failure path terminates the server, shows UI, performs network access, or changes the executable.
- Process detach performs no blocking cleanup.

## Build layout

The project will use CMake and the installed MSVC x64 toolchain:

```text
RS2ServerFix/
  CMakeLists.txt
  docs/superpowers/specs/
  src/faultrep_proxy/
  tests/
```

Build products remain outside the source tree or under an ignored `build/` directory. No generated DLL is copied to a game/server directory automatically.

## Test strategy

Implementation proceeds test-first.

### Automated tests

1. **Hash classification:** known modified, known baseline, and unknown hashes classify correctly.
2. **SHA-256 calculation:** a fixed test fixture produces its expected digest.
3. **System path construction:** the genuine path resolves under `System32`, not the application directory.
4. **Genuine resolution:** loading the proxy in a harness resolves the real system DLL and `ReportFault` without recursion.
5. **Export contract:** the built DLL is x64 and exports `ReportFault` by name and ordinal 13.
6. **Marker privacy:** the marker contains only the allowlisted fields.
7. **Unknown host behavior:** the proxy logs unsupported and performs no patch action.
8. **Load/unload smoke:** a native harness loads and frees the proxy without an exception or hang.

The harness will not invoke `ReportFault` with fabricated exception pointers. Forwarding is validated by successful genuine-symbol resolution and ABI/export inspection; deliberate crash-report testing is reserved for an isolated VM and requires separate approval.

### Disposable-server smoke test

After automated tests pass, the user performs this manually on a stopped disposable server copy:

1. confirm the executable hash;
2. place only the tested proxy beside the executable;
3. start the dedicated server with its normal arguments;
4. verify the PID-specific marker and genuine-resolution success;
5. verify normal Steam, EOS/EAC, networking, map load, and WebAdmin startup;
6. leave it idle for a bounded observation period;
7. shut it down normally;
8. remove the proxy;
9. restart once to prove rollback.

No public players or production service are used for Stage 0.

## Success criteria

Stage 0 succeeds only when:

- automated tests pass on x64;
- the proxy has the expected export contract;
- the genuine system `ReportFault` resolves without recursion;
- the known executable hashes classify correctly;
- no executable or shipped DLL is modified;
- a disposable server starts, initializes its normal services, shuts down, and restarts after proxy removal;
- the only added runtime artifact is the proxy and its PID-specific marker log.

## Rollback

With the server stopped, remove the local `faultrep.dll` and any marker logs. Because Stage 0 does not edit the executable, registry, service configuration, or shipped DLLs, the next launch returns to the original System32 resolution path.

## Later stage, explicitly excluded here

After Stage 0 is proven, a separate reviewed design will cover the ADF mitigation. The current intended direction is a single-flight pack guard plus cycle/range/capacity validation that aborts and logs corrupt packs without attempting live free-list reconstruction.
