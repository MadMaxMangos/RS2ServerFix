# RS2 Two-DLL Passive Loader Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify offline an AMD64 `faultrep.dll` bootstrap that safely forwards Windows `ReportFault` and explicitly initializes a separate `RS2ServerFix.dll` companion, then provide deployment preflight and manual disposable-server rollback instructions without deploying either DLL.

**Architecture:** `faultrep.dll` contains only the load-time boundary, genuine System32 resolver, crash-path forwarder, and companion loader. Its one non-joined worker publishes genuine `ReportFault` before loading `RS2ServerFix.dll` by an absolute file-validated path. The companion's inert `DllMain` does no work; its versioned initialization export hashes the host and writes the Stage 0 marker on the bootstrap worker.

**Tech Stack:** C++17, Win32, Windows CNG (`bcrypt` in the companion only), CMake 4.3, MSVC x64/Visual Studio 18 2026, CTest, and PowerShell for build/evidence commands only.

## Global Constraints

- Output files are exactly `faultrep.dll` and `RS2ServerFix.dll`.
- Production `faultrep.dll` exports only named `ReportFault`, also assigned observed ordinal 13 without `NONAME`.
- Production `RS2ServerFix.dll` exports only named `RS2ServerFix_InitializeV1`.
- Both DLLs are AMD64, `/MT` Release or `/MTd` Debug, with `/DYNAMICBASE`, `/NXCOMPAT`, and `/HIGHENTROPYVA`.
- Neither DLL calls `DisableThreadLibraryCalls`, defines user static TLS, uses a function-local static, or has a dynamic global constructor/destructor.
- Bootstrap direct imports are limited to `KERNEL32.dll`; companion direct imports are limited to `KERNEL32.dll` and `bcrypt.dll`.
- Neither DLL imports `dbghelp.dll`, networking, User32, Shell, COM, managed runtime, or a dynamic Visual C++ runtime.
- Bootstrap `DllMain` only stores its module, calls `CreateThread`, closes the handle without waiting, and returns `TRUE`.
- Companion user `DllMain` always returns `TRUE` and performs no work.
- Worker resolves and publishes genuine `ReportFault` before loading/calling the companion.
- Exported `ReportFault` performs only an atomic pointer read and direct call-through; null returns `frrvErrNoDW`.
- A missing/rejected companion never clears genuine forwarding and never triggers a retry.
- Stage 0 performs no hook, detour, game-memory write, ADF work, anti-cheat interaction, deliberate crash, or server deployment.
- Builds and tests write only below ignored build directories or unique validated system-temporary directories.

## File Map

- `.gitignore` — ignores build trees and generated evidence.
- `CMakeLists.txt` — configures static CRT, warnings, fixtures, DLLs, tools, and CTest.
- `src/shared/bootstrap_abi.h` — the exact 48-byte C-compatible V1 context and result constants.
- `src/shared/path_identity.h/.cpp` — fixed-capacity paths, leaf/directory extraction, file identity, and same-file checks.
- `src/bootstrap/bootstrap_types.h` — genuine-resolver and companion-loader POD statuses/results.
- `src/bootstrap/genuine_resolver.h/.cpp` — pure validation seam and actual System32 resolver.
- `src/bootstrap/companion_loader.h/.cpp` — absolute companion path, identity/export validation, and V1 invocation.
- `src/bootstrap/forwarder.h/.cpp` — independently testable call-or-`frrvErrNoDW` behavior.
- `src/bootstrap/bootstrap_main.cpp` — zero-initialized pointer, one worker, minimal `DllMain`, and public `ReportFault`.
- `src/bootstrap/faultrep.def` — single named bootstrap export.
- `src/companion/build_identity.h/.cpp` — raw SHA-256 build identity.
- `src/companion/sha256.h/.cpp` — Win32/CNG one-pass file hashing.
- `src/companion/marker.h/.cpp` — fixed-buffer privacy-minimal UTF-8 marker and fallback write.
- `src/companion/companion_init.h/.cpp` — context validation, non-waiting claim, host identity, and marker orchestration.
- `src/companion/companion_main.cpp` — inert `DllMain`, non-waiting initialization claim, and V1 export.
- `src/companion/RS2ServerFix.def` — single named companion export.
- `tests/test_framework.h` — dependency-free test accounting/macros.
- `tests/core_tests.cpp` — ABI, identity, hash, path, resolver, loader, forwarder, and marker tests.
- `tests/static_import_harness.cpp` — real load-time name import of `faultrep!ReportFault`, never invoked.
- `tests/static_import_runner.cpp` — isolated system/partial/both/invalid/rollback process cases.
- `tools/pe_reader.h/.cpp` — bounded PE32/PE32+ import/export/security parser.
- `tools/pe_contract.cpp` — separate bootstrap/companion/harness contract modes.
- `tools/deployment_preflight.cpp` — read-only selected-tree `faultrep` importer inventory.
- `tests/preflight_fixture_test.cpp` — safe/unsafe temporary scanner fixtures.
- `docs/disposable-server-test.md` — exact manual control, two-file pass, integrity comparison, and rollback.

---

### Task 1: Project Skeleton, Shared ABI, and Build Identities

**Files:**
- Create: `.gitignore`
- Create: `CMakeLists.txt`
- Create: `src/shared/bootstrap_abi.h`
- Create: `src/bootstrap/bootstrap_types.h`
- Create: `src/companion/build_identity.h`
- Create: `src/companion/build_identity.cpp`
- Create: `tests/test_framework.h`
- Create: `tests/core_tests.cpp`

**Interfaces:**
- Produces: `BootstrapContextV1`, `InitializeV1Fn`, V1 return constants.
- Produces: `BuildIdentity`, `Sha256Digest`, `ClassifyBuild`, `BuildIdentityName`.
- Produces: `GenuineResolverStatus`, `GenuineResolverResult`, `CompanionLoadStatus`, `CompanionLoadResult`.

- [ ] **Step 1: Create the static-CRT CMake skeleton and ABI assertions**

Set:

```cmake
cmake_minimum_required(VERSION 3.24)
project(RS2ServerFix LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
include(CTest)
```

All targets use `UNICODE`, `_UNICODE`, `WIN32_LEAN_AND_MEAN`, `NOMINMAX`, `/W4`, and `/WX`. `.gitignore` contains `/build*/`, `*.user`, `*.suo`, and generated `RS2ServerFix.loader.*.log`.

Define the shared ABI exactly:

```cpp
#pragma once
#include <Windows.h>
#include <cstdint>

namespace rs2fix {
inline constexpr std::uint32_t kBootstrapAbiVersion = 1;

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

using InitializeV1Fn = DWORD(WINAPI*)(const BootstrapContextV1*);
inline constexpr DWORD kInitOk = 0;
inline constexpr DWORD kInitAlreadyInitialized = 1;
inline constexpr DWORD kInitInvalidContext = 2;
inline constexpr DWORD kInitHostIdentityFailed = 3;
inline constexpr DWORD kInitMarkerWriteFailed = 4;
} // namespace rs2fix
```

Define the fixed internal types in `bootstrap_types.h` and `build_identity.h`:

```cpp
namespace rs2fix {
using ReportFaultFn =
    EFaultRepRetVal(APIENTRY*)(LPEXCEPTION_POINTERS, DWORD);
using Sha256Digest = std::array<std::uint8_t, 32>;

enum class BuildIdentity : std::uint32_t {
    Pr1CrashFullDump,
    Pr1StockBaseline,
    CurrentStock,
    CurrentFullDump,
    Unknown,
    Indeterminate,
};

enum class GenuineResolverStatus : std::uint32_t {
    Ok = 0,
    SystemPathFailed,
    LoadFailed,
    SelfModule,
    CandidatePathFailed,
    FileIdentityFailed,
    WrongFile,
    ExportMissing,
    QueryAddressFailed,
    SelfAddress,
};

struct GenuineResolverResult {
    HMODULE module{};
    ReportFaultFn function{};
    GenuineResolverStatus status{GenuineResolverStatus::LoadFailed};
    DWORD win32Error{};
};

enum class CompanionLoadStatus : std::uint32_t {
    Ok,
    PathFailed,
    LoadFailed,
    SelfModule,
    GenuineModule,
    CandidatePathFailed,
    FileIdentityFailed,
    WrongFile,
    ExportMissing,
    QueryAddressFailed,
    WrongAddressBase,
    InitializeFailed,
};

struct CompanionLoadResult {
    HMODULE module{};
    CompanionLoadStatus status{CompanionLoadStatus::LoadFailed};
    DWORD win32Error{};
    DWORD initializeResult{kInitInvalidContext};
};

struct FileHashResult {
    Sha256Digest digest{};
    std::uint64_t fileSize{};
    DWORD error{};
    bool digestValid{};
    bool timedOut{};
};
} // namespace rs2fix
```

- [ ] **Step 2: Add failing ABI and identity tests**

Tests assert the ABI size/version/result values and classify these raw digests:

```text
155EBC77D2FA574F0A94709839EF1DF6A3DA82B278C846F14223967B058C4622 -> pr1-crash-full-dump
5820F0DA82D7C2903DE31E0865320D9E70A0BF74F78F83C83DB4F9DEEAEB1DEF -> pr1-stock-baseline
F4E38510832D1FAADA8AAD3B88CD2255B3EA49267EF0E874468E23BDE4EDFCC3 -> current-stock
0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393 -> current-full-dump
```

A valid zero digest returns `unknown`; `digestValid=false` returns `indeterminate` regardless of bytes.

- [ ] **Step 3: Run the initial test and observe unresolved identity symbols**

```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Debug --target rs2_core_tests
```

Expected: link failure for declared but undefined `ClassifyBuild`/`BuildIdentityName`.

- [ ] **Step 4: Implement raw-byte build identity**

Use namespace-scope `constexpr std::array<std::uint8_t, 32>` values, direct array equality, and a switch returning these exact stable names:

```text
pr1-crash-full-dump
pr1-stock-baseline
current-stock
current-full-dump
unknown
indeterminate
```

- [ ] **Step 5: Run the first passing test and commit**

```powershell
cmake --build build --config Debug --target rs2_core_tests
ctest --test-dir build -C Debug --output-on-failure -R core
git add .gitignore CMakeLists.txt src tests/test_framework.h tests/core_tests.cpp
git commit -m "test: add two-dll ABI and build identity"
```

---

### Task 2: Companion SHA-256 and Marker Core

**Files:**
- Create: `src/companion/sha256.h`
- Create: `src/companion/sha256.cpp`
- Create: `src/companion/marker.h`
- Create: `src/companion/marker.cpp`
- Modify: `tests/core_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces: `FileHashResult HashFileSha256(const wchar_t*, ULONGLONG softDeadlineTick) noexcept`.
- Produces: `MarkerData`, `FormatMarkerUtf8`, `WriteMarkerWithFallback`.

Use these marker interfaces:

```cpp
namespace rs2fix {
struct MarkerData {
    DWORD processId{};
    std::uint64_t executableSize{};
    Sha256Digest digest{};
    bool digestValid{};
    BuildIdentity buildIdentity{BuildIdentity::Indeterminate};
    GenuineResolverStatus resolverStatus{GenuineResolverStatus::LoadFailed};
    DWORD resolverError{};
    DWORD initializeResult{kInitInvalidContext};
    DWORD primaryWriteError{};
    bool bootstrapBesideExecutable{};
    bool companionBesideExecutable{};
    bool complete{};
    wchar_t executableLeaf[260]{};
};

struct MarkerWriteResult {
    bool written{};
    bool usedFallback{};
    DWORD primaryError{};
    DWORD finalError{};
    wchar_t writtenPath[32768]{};
};

bool FormatMarkerUtf8(
    const MarkerData&, char*, std::size_t,
    std::size_t* bytesUsed) noexcept;
MarkerWriteResult WriteMarkerWithFallback(
    const wchar_t* primaryDirectory,
    const wchar_t* fallbackDirectory,
    const MarkerData&) noexcept;
} // namespace rs2fix
```

- [ ] **Step 1: Add failing fixed-file, real-fixture, derivation, and marker tests**

CMake cache inputs:

```cmake
set(RS2_PR1_BASELINE_PATH "" CACHE FILEPATH "Preserved PR1 stock executable")
set(RS2_CURRENT_STOCK_PATH "" CACHE FILEPATH "Current stock executable")
```

Tests must:

- hash exactly `abc` to `BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD`;
- force a deadline timeout and require no valid digest;
- verify both configured stock hashes;
- make temporary copies, change only PR1 offsets `0x1e1`/`0xa6a313` and current offsets `0x1e1`/`0xa6bb43`, and reproduce both full-dump hashes;
- rehash both stock inputs afterward to prove they are unchanged;
- format every identity/resolver state into an 8 KiB fixed buffer;
- reject a too-small buffer;
- require schema, leaf names, PID, hash/identity, bootstrap resolver evidence, initializer result, and terminal completion line;
- reject output containing a drive-root path, `\Users\`, command line, environment, account, network, token, exception, or memory field;
- force invalid-primary/valid-temp fallback and verify exactly one complete file.

- [ ] **Step 2: Configure with real local fixtures and observe failure**

```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64 `
  -DRS2_PR1_BASELINE_PATH="D:/Documents/RisingStorm2/VNGame_pr1.exe_old4" `
  -DRS2_CURRENT_STOCK_PATH="D:/Documents/RisingStorm2/Binaries/VNGame_pr3.stock-F4E38510832D1FAA.exe"
cmake --build build --config Debug --target rs2_core_tests
```

Expected: unresolved hash/marker functions.

- [ ] **Step 3: Implement one-pass CNG hashing**

Implementation must:

- reject null/empty paths with `ERROR_INVALID_PARAMETER`;
- open `GENERIC_READ`, all three share flags, `OPEN_EXISTING`, and `FILE_FLAG_SEQUENTIAL_SCAN`;
- retain `GetFileSizeEx` value;
- use `BCRYPT_SHA256_ALGORITHM`, query object/hash lengths, and require 32-byte output;
- allocate the CNG object and a 64 KiB read buffer with `VirtualAlloc`;
- check the soft deadline before each `ReadFile`;
- finish only after clean EOF;
- destroy/close/free every acquired resource on every path;
- store a stable nonzero diagnostic for CNG failures without importing formatting/UI libraries.

- [ ] **Step 4: Implement fixed-buffer UTF-8 marker formatting/writing**

Use bounded append functions, uppercase 64-character digest, and `WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, -1, output, remainingCapacity, nullptr, nullptr)` for leaf names. Emit stable `key=value\r\n` with completion last. Write all bytes with short-write handling, call `FlushFileBuffers`, and delete an incomplete output. Attempt primary once, fallback once, with filename `RS2ServerFix.loader.<pid>.log`.

- [ ] **Step 5: Run tests and commit**

```powershell
cmake --build build --config Debug --target rs2_core_tests
ctest --test-dir build -C Debug --output-on-failure -R core
git add CMakeLists.txt src/companion tests/core_tests.cpp
git commit -m "feat: add companion hashing and marker core"
```

---

### Task 3: Shared Path/File Identity and Bootstrap Genuine Resolver

**Files:**
- Create: `src/shared/path_identity.h`
- Create: `src/shared/path_identity.cpp`
- Create: `src/bootstrap/genuine_resolver.h`
- Create: `src/bootstrap/genuine_resolver.cpp`
- Create: `src/bootstrap/forwarder.h`
- Create: `src/bootstrap/forwarder.cpp`
- Modify: `tests/core_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces: `kPathCapacity=32768`, `FileIdentity`, bounded path helpers, and `SameFileIdentity`.
- Produces: `ValidateGenuineEvidence` and `ResolveGenuineReportFault`.
- Produces: `ForwardOrFail`.

- [ ] **Step 1: Add failing path, identity, resolver, and forwarder tests**

Public interfaces:

```cpp
namespace rs2fix {
inline constexpr std::size_t kPathCapacity = 32768;
struct FileIdentity {
    DWORD volumeSerial{};
    DWORD fileIndexHigh{};
    DWORD fileIndexLow{};
    bool valid{};
};

bool BuildSystemFaultrepPath(wchar_t*, std::size_t, DWORD*) noexcept;
bool GetBoundedModulePath(HMODULE, wchar_t*, std::size_t, DWORD*) noexcept;
bool ExtractDirectoryAndLeaf(
    const wchar_t*, wchar_t*, std::size_t,
    wchar_t*, std::size_t, DWORD*) noexcept;
bool AppendPathLeaf(
    const wchar_t*, const wchar_t*, wchar_t*, std::size_t, DWORD*) noexcept;
bool QueryFileIdentity(const wchar_t*, FileIdentity*, DWORD*) noexcept;
bool SameFileIdentity(const FileIdentity&, const FileIdentity&) noexcept;

GenuineResolverStatus ValidateGenuineEvidence(
    HMODULE bootstrap,
    HMODULE candidate,
    FARPROC function,
    const FileIdentity& expected,
    const FileIdentity& actual,
    bool virtualQuerySucceeded,
    const void* allocationBase) noexcept;
GenuineResolverResult ResolveGenuineReportFault(HMODULE bootstrap) noexcept;

EFaultRepRetVal ForwardOrFail(
    ReportFaultFn function,
    LPEXCEPTION_POINTERS pointers,
    DWORD options) noexcept;
}
```

Cover empty/exact/truncated paths, same file through a hard link, different file, null/self/wrong identity/null export/failed `VirtualQuery`/self address, genuine success, null forward target, and a stub receiving exact argument values.

- [ ] **Step 2: Build and observe unresolved functions**

```powershell
cmake --build build --config Debug --target rs2_core_tests
```

- [ ] **Step 3: Implement bounded paths and file identity**

Use only caller-owned buffers. Treat `GetModuleFileNameW` return at capacity as truncation. Build System32 with `GetSystemDirectoryW` and explicit append capacity. Open identity handles with `FILE_READ_ATTRIBUTES`, all three share flags, and compare volume serial plus high/low file index.

- [ ] **Step 4: Implement fail-closed genuine resolution**

Exact order:

```text
absolute System32 path
LoadLibraryExW(path, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)
candidate != bootstrap
expected/candidate file identity equal
GetProcAddress("ReportFault") non-null
VirtualQuery succeeds
allocation base != bootstrap
return retained module/function
```

Release every rejected non-null candidate. Never use a name-only load/handle. The test invokes resolution but never calls genuine `ReportFault`.

- [ ] **Step 5: Implement and test the crash-path helper**

```cpp
if (function == nullptr) return frrvErrNoDW;
return function(pointers, options);
```

Run:

```powershell
cmake --build build --config Debug --target rs2_core_tests
ctest --test-dir build -C Debug --output-on-failure -R core
```

- [ ] **Step 6: Commit**

```powershell
git add CMakeLists.txt src/shared src/bootstrap/genuine_resolver.* src/bootstrap/forwarder.* tests/core_tests.cpp
git commit -m "feat: resolve and validate system fault reporter"
```

---

### Task 4: Companion Loader Validation and Invocation

**Files:**
- Create: `src/bootstrap/companion_loader.h`
- Create: `src/bootstrap/companion_loader.cpp`
- Modify: `tests/core_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces: `ValidateCompanionEvidence`, `BuildCompanionPath`, and `LoadAndInitializeCompanion`.

- [ ] **Step 1: Add failing companion validation/invocation tests**

Interfaces:

```cpp
CompanionLoadStatus ValidateCompanionEvidence(
    HMODULE bootstrap,
    HMODULE genuine,
    HMODULE candidate,
    FARPROC initializer,
    const FileIdentity& expected,
    const FileIdentity& actual,
    bool virtualQuerySucceeded,
    const void* allocationBase) noexcept;

bool BuildCompanionPath(
    HMODULE bootstrap,
    wchar_t* output,
    std::size_t capacity,
    DWORD* error) noexcept;

CompanionLoadResult LoadAndInitializeCompanion(
    HMODULE bootstrap,
    const BootstrapContextV1& context) noexcept;
```

Tests cover missing path, self/genuine candidate, wrong identity, null export, failed query, allocation base not exactly candidate, successful evidence, ABI mismatch, and resolver success/failure consistency.

- [ ] **Step 2: Build and observe failures**

```powershell
cmake --build build --config Debug --target rs2_core_tests
```

- [ ] **Step 3: Implement absolute companion loading**

Build exact sibling path `RS2ServerFix.dll`, call `LoadLibraryExW(absoluteCompanionPath, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)`, compare expected/candidate file identity, resolve named `RS2ServerFix_InitializeV1`, require `VirtualQuery` allocation base equal candidate, then call with the 48-byte context.

Release rejected candidates before the call. Retain a validated/called module even if initializer returns a failure code. Return module, initializer result, loader status, and Win32 error without retrying.

- [ ] **Step 4: Run tests and commit**

```powershell
cmake --build build --config Debug --target rs2_core_tests
ctest --test-dir build -C Debug --output-on-failure -R core
git add CMakeLists.txt src/bootstrap/companion_loader.* tests/core_tests.cpp
git commit -m "feat: add explicit companion loading contract"
```

---

### Task 5: Build the Bootstrap and Companion DLLs

**Files:**
- Create: `src/bootstrap/bootstrap_main.cpp`
- Create: `src/bootstrap/faultrep.def`
- Create: `src/companion/companion_init.h`
- Create: `src/companion/companion_init.cpp`
- Create: `src/companion/companion_main.cpp`
- Create: `src/companion/RS2ServerFix.def`
- Modify: `tests/core_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces: `faultrep.dll!ReportFault`.
- Produces: `RS2ServerFix.dll!RS2ServerFix_InitializeV1`.
- Produces: `InitializationClaim ClaimInitialization(LONG volatile*) noexcept`.

- [ ] **Step 1: Add failing initializer-context tests**

Factor context and non-waiting state validation behind:

```cpp
DWORD ValidateBootstrapContextV1(
    const BootstrapContextV1* context) noexcept;
DWORD RunCompanionInitialization(
    const BootstrapContextV1& context,
    LONG volatile* state) noexcept;

enum class InitializationClaim : std::uint32_t {
    Claimed,
    Running,
    Finished,
};
InitializationClaim ClaimInitialization(LONG volatile* state) noexcept;
```

Tests require invalid null/size/version/host/bootstrap, inconsistent resolver status versus module/function, host-module mismatch, and a valid current-process context returning `kInitOk`. Sequential state tests require `Claimed`, `Running`, then `Finished` after the test sets state to 2. The complete-marker behavior is exercised through the real companion in Task 7 rather than by adding a production test export.

- [ ] **Step 2: Implement inert companion entry and exported initializer**

`companion_main.cpp` contains only zero-initialized `LONG g_initializationState`, an always-`TRUE` no-work `DllMain`, and:

```cpp
extern "C" DWORD WINAPI RS2ServerFix_InitializeV1(
    const rs2fix::BootstrapContextV1* context) noexcept {
    const DWORD validation = rs2fix::ValidateBootstrapContextV1(context);
    if (validation != rs2fix::kInitOk) return validation;
    return rs2fix::RunCompanionInitialization(
        *context, &g_initializationState);
}
```

The initializer validates the context, claims state, confirms the host module, hashes/classifies the host with `GetTickCount64()+10000`, writes the marker, sets state 2, and returns the stable result. A failed genuine resolver is valid evidence when genuine module/function are both null and is recorded as partial rather than rejected as ABI-invalid.

`ClaimInitialization` uses `InterlockedCompareExchange(state, 1, 0)`. Previous 0 returns `Claimed`, previous 1 returns `Running`, previous 2 returns `Finished`; it never spins or waits.

`RS2ServerFix.def`:

```def
LIBRARY RS2ServerFix
EXPORTS
    RS2ServerFix_InitializeV1
```

- [ ] **Step 3: Implement bootstrap worker/public export/minimal `DllMain`**

Use zero-initialized `PVOID volatile g_reportFault` and saved `HMODULE g_bootstrap`. Worker order is:

```text
ResolveGenuineReportFault
InterlockedCompareExchangePointer publish when valid
construct BootstrapContextV1 with GetModuleHandleW(nullptr)
LoadAndInitializeCompanion
return
```

`ReportFault` atomically reads using `InterlockedCompareExchangePointer(&g_reportFault, nullptr, nullptr)` and calls `ForwardOrFail`.

`DllMain` on process attach saves `instance`, calls `CreateThread(nullptr, 0, BootstrapWorker, instance, 0, nullptr)`, closes a successful handle, and always returns `TRUE`. Other reasons return immediately.

`faultrep.def`:

```def
LIBRARY faultrep
EXPORTS
    ReportFault @13
```

- [ ] **Step 4: Build both DLLs and run core tests**

```powershell
cmake --build build --config Debug --target rs2_faultrep_bootstrap rs2_server_fix_companion rs2_core_tests
ctest --test-dir build -C Debug --output-on-failure -R core
```

Expected: `build\Debug\faultrep.dll` and `build\Debug\RS2ServerFix.dll`; no artifact outside build/temp.

- [ ] **Step 5: Commit**

```powershell
git add CMakeLists.txt src/bootstrap/bootstrap_main.cpp src/bootstrap/faultrep.def src/companion/companion_init.* src/companion/companion_main.cpp src/companion/RS2ServerFix.def tests/core_tests.cpp
git commit -m "feat: build bootstrap and companion DLLs"
```

---

### Task 6: PE Contract Parser and Gates

**Files:**
- Create: `tools/pe_reader.h`
- Create: `tools/pe_reader.cpp`
- Create: `tools/pe_contract.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces: bounded `ReadPeImage` data for machine, characteristics, DLL characteristics, imports, and exports.
- Produces modes: `rs2_pe_contract bootstrap <path>`, `companion <path>`, and `harness <path>`.

- [ ] **Step 1: Register failing PE tests for both outputs**

```cmake
add_test(NAME pe_bootstrap_contract
  COMMAND rs2_pe_contract bootstrap $<TARGET_FILE:rs2_faultrep_bootstrap>)
add_test(NAME pe_companion_contract
  COMMAND rs2_pe_contract companion $<TARGET_FILE:rs2_server_fix_companion>)
```

- [ ] **Step 2: Implement the bounds-checked PE reader**

Read into a tool-only byte vector. Validate DOS/NT headers, optional-header magic/size, section raw ranges, RVA conversion, descriptor/thunk arrays, all string bounds, ordinal/name flags, export arrays, and integer count/offset overflow. Malformed images return failure without exceptions or out-of-bounds access.

- [ ] **Step 3: Implement exact image-specific gates**

Common: AMD64, DLL where applicable, ASLR, NX, high-entropy VA, no dynamic VC runtime or `dbghelp`.

Bootstrap:

```text
named exports exactly {ReportFault}
ReportFault ordinal 13 reported
imports subset {KERNEL32.dll}
no RS2ServerFix.dll static import
```

Companion:

```text
named exports exactly {RS2ServerFix_InitializeV1}
imports subset {KERNEL32.dll, bcrypt.dll}
```

Harness mode requires named import `faultrep.dll!ReportFault`, not ordinal.

- [ ] **Step 4: Run Debug and Release PE gates**

```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure -R "pe_.*_contract"
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure -R "pe_.*_contract"
```

- [ ] **Step 5: Commit**

```powershell
git add CMakeLists.txt tools/pe_reader.* tools/pe_contract.cpp
git commit -m "test: enforce two-dll PE contracts"
```

---

### Task 7: Static-Import and Partial-Installation Process Tests

**Files:**
- Create: `tests/static_import_harness.cpp`
- Create: `tests/static_import_runner.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces: `rs2_static_import_harness.exe --expect-system|--expect-bootstrap [--expect-marker|--forbid-marker]`.
- Produces CTest `static_import_cases`.

- [ ] **Step 1: Build a harness with a forced name import**

```cpp
extern "C" __declspec(dllimport)
EFaultRepRetVal APIENTRY ReportFault(LPEXCEPTION_POINTERS, DWORD);
volatile auto g_reportFaultImportAnchor = &ReportFault;
```

Never call it. Validate loaded `faultrep.dll` by file identity against System32 or own directory. Marker-required mode waits at most 15 seconds for its PID-specific file and requires genuine `system32`, companion initialized, valid ABI, and terminal completion. Marker-forbidden mode waits two seconds and requires absence.

- [ ] **Step 2: Implement the isolated runner cases**

Use unique `%TEMP%\RS2ServerFix.static.<pid>.<tick>` directories, `SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX)`, `CreateProcessW(CREATE_NO_WINDOW)`, and 20-second bounded waits.

Run exactly:

```text
1 system control: harness only -> System32, no marker
2 companion only: harness + companion -> System32, no marker
3 bootstrap only: harness + bootstrap -> local bootstrap, no marker, healthy exit
4 both: harness + both -> local bootstrap, complete marker
5 invalid companion: harness + bootstrap + malformed companion -> healthy exit, no complete marker
6 invalid bootstrap: harness + malformed bootstrap -> creation/loader failure
7 rollback: remove both -> System32, no marker
```

Before recursive cleanup, resolve each case path and require it begins with the unique root; never remove outside it.

- [ ] **Step 3: Register and run the initial failing process test**

```cmake
add_test(NAME static_import_cases
  COMMAND rs2_static_import_runner
          $<TARGET_FILE:rs2_static_import_harness>
          $<TARGET_FILE:rs2_faultrep_bootstrap>
          $<TARGET_FILE:rs2_server_fix_companion>)
```

```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure -R static_import_cases
```

- [ ] **Step 4: Complete all seven assertions and run both configurations**

```powershell
ctest --test-dir build -C Debug --output-on-failure -R "core|pe_.*_contract|static_import_cases"
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure -R "core|pe_.*_contract|static_import_cases"
```

- [ ] **Step 5: Commit**

```powershell
git add CMakeLists.txt tests/static_import_harness.cpp tests/static_import_runner.cpp
git commit -m "test: prove two-dll loading and rollback"
```

---

### Task 8: Deployment Preflight and Manual Procedure

**Files:**
- Create: `tools/deployment_preflight.cpp`
- Create: `tests/preflight_fixture_test.cpp`
- Create: `docs/disposable-server-test.md`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces: `rs2_deployment_preflight.exe <selected-root>` with TSV evidence and nonzero unsafe result.
- Produces CTest `preflight_fixture`.

- [ ] **Step 1: Add unsafe/safe temporary-tree tests**

Unsafe tree contains a copied static harness whose temporary PE `Machine` field is changed to I386 while retaining its `faultrep!ReportFault` import, an `.exe.local` artifact, and a truncated `.dll`. Require all three reasons. Remove them and require the safe tree to report the AMD64 named importer and pass.

- [ ] **Step 2: Implement read-only recursive preflight**

Do not follow directory reparse points. Parse `.exe`/`.dll`, print relative path/machine and every `faultrep.dll` import. Fail if a PE extension is malformed, a `faultrep` importer is non-AMD64, imports by ordinal or requires a name other than exactly `ReportFault`, or any executable `.local` redirection is present. Never open for write.

- [ ] **Step 3: Run and commit preflight**

```powershell
cmake --build build --config Debug --target rs2_deployment_preflight rs2_preflight_fixture_test
ctest --test-dir build -C Debug --output-on-failure -R preflight_fixture
git add CMakeLists.txt tools/deployment_preflight.cpp tests/preflight_fixture_test.cpp
git commit -m "test: add deployment preflight scanner"
```

- [ ] **Step 4: Write the manual two-file control/pass/rollback document**

Include exact prerequisites, fresh-target preflight, AV/EDR/WDAC/AppLocker disposition, initial hashes/listing, normal start command, required module/marker evidence, Steam/EOS/EAC/network/map/WebAdmin comparisons, bounded idle observation, normal stop, post hashes/diff, removal of both files only while stopped, one System32 restart, evidence-retention list, and every stop condition from the specification. State explicitly that Codex did not deploy or launch the server.

- [ ] **Step 5: Commit the procedure**

```powershell
git add docs/disposable-server-test.md
git commit -m "docs: add two-file disposable-server procedure"
```

---

### Task 9: Fresh Release Verification and Code Review

**Files:**
- Modify only for verified review findings.

**Interfaces:**
- Produces verified Release hashes/transcripts and a clean non-deployed repository.

- [ ] **Step 1: Configure and build a fresh verification tree**

```powershell
cmake -S . -B build-verify -G "Visual Studio 18 2026" -A x64 `
  -DRS2_PR1_BASELINE_PATH="D:/Documents/RisingStorm2/VNGame_pr1.exe_old4" `
  -DRS2_CURRENT_STOCK_PATH="D:/Documents/RisingStorm2/Binaries/VNGame_pr3.stock-F4E38510832D1FAA.exe"
cmake --build build-verify --config Release
```

- [ ] **Step 2: Run the complete Release suite**

```powershell
ctest --test-dir build-verify -C Release --output-on-failure
```

Required tests:

```text
core
pe_bootstrap_contract
pe_companion_contract
pe_harness_contract
static_import_cases
preflight_fixture
```

No fixture may skip on this machine.

- [ ] **Step 3: Capture final offline evidence**

```powershell
$bootstrap = Resolve-Path 'build-verify\Release\faultrep.dll'
$companion = Resolve-Path 'build-verify\Release\RS2ServerFix.dll'
Get-FileHash -Algorithm SHA256 -LiteralPath $bootstrap
Get-FileHash -Algorithm SHA256 -LiteralPath $companion
& 'build-verify\Release\rs2_pe_contract.exe' bootstrap $bootstrap
& 'build-verify\Release\rs2_pe_contract.exe' companion $companion
& 'build-verify\Release\rs2_deployment_preflight.exe' 'D:\Documents\RisingStorm2\Binaries'
git status --short
```

The local analysis-directory scan is not substituted for the remote disposable-target scan.

- [ ] **Step 4: Obtain one bounded correctness/security/compatibility code review**

Provide the reviewer the goal, specification, this plan, diff from `5d5e4a8`, complete test transcript, PE transcripts, and non-deployment limitation. Require BLOCKING/IMPORTANT/MINOR plus verdict. Independently verify every finding.

- [ ] **Step 5: Fix only verified blocking/important findings and rerun all Release evidence**

Add a focused regression test for each accepted correctness failure, then run:

```powershell
cmake --build build-verify --config Release
ctest --test-dir build-verify -C Release --output-on-failure
& 'build-verify\Release\rs2_pe_contract.exe' bootstrap 'build-verify\Release\faultrep.dll'
& 'build-verify\Release\rs2_pe_contract.exe' companion 'build-verify\Release\RS2ServerFix.dll'
```

- [ ] **Step 6: Commit review corrections if a diff exists**

```powershell
git add -A
git commit -m "fix: address two-dll verification findings"
```

- [ ] **Step 7: Prove non-deployment and clean state**

```powershell
git status --short
Get-ChildItem 'D:\Documents\RisingStorm2' -Filter 'faultrep.dll' -Recurse |
  Select-Object -ExpandProperty FullName
Get-ChildItem 'D:\Documents\RisingStorm2' -Filter 'RS2ServerFix.dll' -Recurse |
  Select-Object -ExpandProperty FullName
```

Expected: only repository build paths remain; temporary cases were removed; no server/game directory received either DLL.
