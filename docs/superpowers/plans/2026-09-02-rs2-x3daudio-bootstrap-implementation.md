# RS2 Passive X3Audio Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

Status: User-approved first-runtime console-status amendment incorporated on
2026-09-02; awaiting focused Claude Opus 5 Max review. Implementation and
deployment have not begun.

**Goal:** Build and verify, without deployment, an AMD64
`X3DAudio1_7.dll` bootstrap that preserves the qualified legacy X3Audio 1.7
ABI, initializes an inert `RS2ServerFix.dll` companion outside loader lock,
emits one exact success-only console confirmation after its complete marker,
and supplies the bounded evidence tools needed for a later user-operated
disposable-server control/pass/rollback experiment.

**Architecture:** VNGame's existing normal import selects the local
`X3DAudio1_7.dll`. The bootstrap resolves both exports from the exact qualified
System32 DLL through a non-waiting asynchronous `INIT_ONCE` publication with a
bounded immutable fallback, forwards calls without observation, and starts one
non-joined worker that validates and invokes `RS2ServerFix_InitializeV2`.
The companion identifies the host, writes one schema-2 marker, and makes one
best-effort direct-standard-output write of its version/build/passive status;
separate offline tools own manifests, signature checks, PE/tree inspection,
runtime module inventory, qualification evidence, and deployment reports.

**Tech Stack:** C++17, Win32, MSVC x64/Visual Studio 18 2026, Windows CNG
(`bcrypt`), WinTrust, Version APIs, Tool Help, CMake 3.24+, CTest, and
PowerShell for build/evidence orchestration only. No third-party runtime or
serialization dependency is added.

**Spec:**
`docs/superpowers/specs/2026-09-02-rs2-x3daudio-bootstrap-design.md`

## Global Constraints

- Read the approved specification and this plan before changing code. If they
  disagree, stop and amend the reviewed documents; do not improvise a third
  behavior.
- The only deployable outputs are AMD64 `X3DAudio1_7.dll` and
  `RS2ServerFix.dll`. Nothing is copied outside repository build directories or
  unique validated system-temporary test directories.
- No step edits VNGame, a shipped DLL, configuration, a live-server tree, or
  the preserved `D:\Documents\RisingStorm2\RS2ServerFix` original.
- The production bootstrap exports named `X3DAudioCalculate @1` and named
  `X3DAudioInitialize @2`, and no other function. The companion exports only
  `RS2ServerFix_InitializeV2`.
- The legacy initializer ABI is `void (WINAPI*)(UINT32, FLOAT, BYTE*)`; the
  bootstrap does not include `x3daudio.h`. The calculate arguments remain
  opaque to the bootstrap.
- Both DLLs use `/MT` Release or `/MTd` Debug with `/DYNAMICBASE`, `/NXCOMPAT`,
  `/HIGHENTROPYVA`, no user TLS, no dynamic global constructor/destructor, and
  no `DisableThreadLibraryCalls`.
- Bootstrap direct imports are limited to `KERNEL32.dll` plus inspected
  API-set expansion. Companion direct imports are limited to `KERNEL32.dll`
  and `bcrypt.dll`. Both have empty delay-import tables and no dynamic Visual
  C++ runtime.
- Bootstrap `DllMain` stores its module, creates one worker, closes a successful
  thread handle without waiting, and returns `TRUE`. Other notifications and
  companion `DllMain` do no work.
- Genuine resolution always uses a bounded absolute System32 path and validates
  file identity, both named exports, and both allocation bases. It never uses
  a basename-only handle lookup.
- Exports never log, hash, invoke the companion, access game memory, catch a
  genuine exception, retry without bound, or fabricate X3Audio output.
- The companion's only diagnostics are its schema-2 marker and, only after a
  complete marker with result `kInitOk`, exactly one attempt to write this CRLF
  line through standard output:
  `[RS2ServerFix] v0.1.0.0 loaded; host=<eligible-build-identity>; X3Audio=System32; mode=passive; marker=complete`.
  The write runs outside `DllMain` and all X3Audio exports, uses no heap or
  logging framework, never retries or falls back, and cannot change the
  initializer result or marker.
- A worker makes one resolution attempt. An export retries exactly once only
  after a resource/API failure; validation failures fail fast immediately.
  Terminal failure is exactly `0xC0000602`.
- A successful normal dispatch and an optional successful fallback dispatch
  each retain at most one genuine-module reference until process exit. A
  transient lease releases only its own extra reference after its current
  operation.
- `config/qualified_x3audio_genuine.manifest` is dependency-free 7-bit ASCII,
  strict `key=value`, CRLF after every line including the last, no BOM, at most
  64 KiB, 32 entries, and 1,024 bytes per line. Normal tests and preflight
  accept only `qualified` entries.
- `.gitattributes` must be committed before the manifest is first staged. The
  manifest commit must also add its referenced seed evidence record. The
  checked-in manifest must report `i/crlf w/crlf` from `git ls-files --eol`;
  `/config/*.manifest -whitespace` makes `git diff --check` defer the exact byte
  grammar to the strict parser/tests instead of flagging each preserved CR.
- All CLI evidence paths are explicit absolute paths. There is no current
  directory, executable-directory, compiled-in, or basename fallback.
- Each evidence CLI accepts `--help` as its sole argument, prints its complete
  named-option grammar, exits 0, and performs no file, process, or registry
  action. Combining `--help` with another argument is usage error 2.
- All automated file writes use create-new semantics where specified, reject
  short writes, delete partial output, and operate only in validated temporary
  roots. No test mutates System32.
- The active build graph contains no `faultrep.dll` target, FaultRep import
  library search, `ReportFault`, or V1 companion export after Task 3's graph
  cutover. Final PE and source scans enforce their complete removal.
- Runtime inventory and disposable-server execution require separate explicit
  user authorization. This implementation sequence stops after preparing and
  verifying artifacts, tools, and documentation.
- Preserve the accepted residual-risk statement verbatim in the manual
  procedure and final evidence: `CreateThread` from `DllMain` remains risky;
  static import/TLS evidence cannot exclude a dynamic call from another
  DLL's `DllMain`; and an export can fail fast after two resource/API failures
  or the final publication-check micro-race.

## Final File Map

- `.gitattributes` — preserves the reviewed manifest bytes with
  `/config/*.manifest -text -whitespace`.
- `config/qualified_x3audio_genuine.manifest` — authoritative schema-1
  qualified/provisional System32 identity catalogue.
- `docs/evidence/x3audio/9460709339701AD471A5CABE6365355F4D586DC4FCB86507C1331839DC555446.md`
  — seed binary/signature/export/ABI evidence.
- `CMakeLists.txt` — static CRT, RC support, production/test-only targets,
  explicit manifests, test-only by-name import-library generation/linkage, and
  seven CTest roles.
- `src/shared/digest.h/.cpp` — uppercase SHA-256 parsing/formatting and the
  common `Sha256Digest` type.
- `src/shared/bootstrap_abi.h` — exact 40-byte C-compatible V2 context and
  stable result values.
- `src/shared/version.h` — one compile-time version quad/text source consumed
  by both VERSIONINFO resources and the console formatter.
- `src/shared/path_identity.h/.cpp` — correctly bounded path helpers, System32
  X3Audio path construction, and file identity.
- `src/companion/sha256.h/.cpp` — existing CNG file hashing over the common
  digest type.
- `src/companion/build_identity.h/.cpp` — four preserved identities and names;
  no identity exposes or authorizes a mutation capability.
- `src/companion/marker.h/.cpp` — schema-2 privacy-minimal marker, fallback,
  terminal record, and injectable short-write test seam.
- `src/companion/console_status.h/.cpp` — fixed-buffer exact success-line
  formatter and injectable one-attempt standard-output writer.
- `src/companion/companion_init.h/.cpp` — V2 validation, non-waiting claim,
  host hashing, location checks, marker orchestration, and success-line ordering.
- `src/companion/companion_main.cpp`, `src/companion/RS2ServerFix.def`, and
  `src/companion/companion_version.rc` — inert `DllMain`, the sole V2 export,
  and honest project VERSIONINFO.
- `src/bootstrap/bootstrap_types.h` — legacy function declarations, resolver
  status/classification, immutable dispatch, lease, resolver state, and
  injection operations.
- `src/bootstrap/genuine_resolver.h/.cpp` — private System32 resolution,
  validation, async normal publication, static fallback, retry policy, and
  lease release.
- `src/bootstrap/forwarder.h/.cpp` — exact argument call-through helpers and
  the production fail-fast terminal.
- `src/bootstrap/companion_loader.h/.cpp` — absolute sibling validation,
  V2 invocation, and persistent companion reference.
- `src/bootstrap/bootstrap_main.cpp`, `src/bootstrap/X3DAudio1_7.def`, and
  `src/bootstrap/bootstrap_version.rc` — two public exports, one worker,
  minimal `DllMain`, ordinals, and honest project VERSIONINFO.
- `tools/genuine_manifest.h/.cpp` — strict manifest parser, qualified lookup,
  seed evidence-path audit, qualification record formatter, and create-new
  evidence writer.
- `tools/qualification_runner.h/.cpp` — provisional-only qualification
  orchestration shared by the CLI and injected tests.
- `tools/file_evidence.h/.cpp` — file hash/size, PE identity, fixed version
  quads, System32 candidate comparison, and embedded WinVerifyTrust policy.
- `tools/tool_paths.h/.cpp` — absolute/plain-file/plain-directory checks,
  containment, and create-new report paths used only by tools/tests.
- `tools/pe_reader.h/.cpp` — bounded PE32/PE32+ normal imports, delay imports,
  exports, security flags, TLS directory, COFF timestamp, image size, and
  checksum.
- `tools/pe_contract_lib.h/.cpp` — reusable bootstrap, companion, harness, and
  proposed-artifact contracts.
- `tools/pe_contract.cpp` — CLI contract evidence.
- `tools/deployment_preflight.cpp` — read-only stopped-tree, artifact,
  manifest, trust, KnownDLL, and sanitized report gate.
- `tools/runtime_inventory.h/.cpp` and `tools/runtime_inventory_main.cpp` —
  stable two-snapshot module/import inventory and control/proxy expectations.
- `tests/test_support.h/.cpp` — temporary-root, fixture, digest, file, and
  process helpers with validated cleanup.
- `tests/core_tests.cpp`, `tests/manifest_tests.cpp`,
  `tests/companion_tests.cpp`, and `tests/resolver_tests.cpp` — the `core`
  role's focused test translation units.
- `tests/normal_import_fixture.cpp` and `tests/delay_import_fixture.cpp` —
  non-executed PE parser/importer fixtures.
- `tests/pe_reader_tests.cpp` — parser mutation cases and contract gates.
- `tests/X3DAudio1_7_named_import.def` — ordinal-free, test-only source for the
  by-name import library used by the fixtures and static harness.
- `tests/static_import_harness.cpp` — real named legacy initializer import,
  fixed initialize/calculate vector, module proof, digest, concurrent mode,
  fail-fast modes, and immediate-exit mode.
- `tests/static_import_runner.cpp` — qualified-System32 gate, nine fresh-process
  functional cases, stdout/digest comparison, and explicit qualification mode.
- `tests/preflight_fixture_test.cpp` — complete safe/unsafe preflight matrix.
- `tests/runtime_inventory_test.cpp` — fake snapshot stability/failure matrix
  plus a read-only current-process integration capture.
- `docs/disposable-server-test.md` — user-operated preflight, control,
  two-file pass, immediate shutdown, integrity comparison, and rollback.

---

### Task 1: Commit the Manifest Byte-Custody Rule First

**Files:**

- Create: `.gitattributes`

**Interfaces:**

- Produces: the repository rule that prevents Git from changing reviewed
  manifest bytes.
- Consumes: nothing; this commit deliberately precedes the manifest.

- [ ] **Step 1: Add the exact manifest attribute**

Use `apply_patch` to create `.gitattributes` with exactly:

```gitattributes
/config/*.manifest -text -whitespace
```

- [ ] **Step 2: Verify the attribute before any manifest exists or is staged**

Run:

```powershell
git check-attr text whitespace -- config/qualified_x3audio_genuine.manifest
git diff --check
```

Expected first command:

```text
config/qualified_x3audio_genuine.manifest: text: unset
config/qualified_x3audio_genuine.manifest: whitespace: unset
```

Expected second command: exit 0.

- [ ] **Step 3: Commit the byte-custody rule by itself**

```powershell
git add -- .gitattributes
git diff --cached --check
git commit -m "chore: preserve x3audio manifest bytes"
```

Do not stage the manifest in this commit.

---

### Task 2: Add the Strict Genuine Manifest and Seed Evidence

**Files:**

- Create: `src/shared/digest.h`
- Create: `src/shared/digest.cpp`
- Create: `tools/genuine_manifest.h`
- Create: `tools/genuine_manifest.cpp`
- Create: `config/qualified_x3audio_genuine.manifest`
- Create:
  `docs/evidence/x3audio/9460709339701AD471A5CABE6365355F4D586DC4FCB86507C1331839DC555446.md`
- Create: `tests/manifest_tests.cpp`
- Create: `tests/test_support.h`
- Create: `tests/test_support.cpp`
- Modify: `src/companion/build_identity.h`
- Modify: `tests/core_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**

- Produces: `Sha256Digest`, `ParseSha256Upper`, `FormatSha256Upper`.
- Produces: `GenuineManifestEntry`, `GenuineManifest`,
  `ParseGenuineManifest`, `ReadGenuineManifest`,
  `FindManifestEntry`, `AuditManifestEvidencePaths`.
- Produces: `QualificationEvidence`, `FormatQualificationEvidence`,
  `ParseQualificationEvidence`, and `WriteQualificationEvidenceCreateNew`.
- Produces: validated temporary-root/file/process helpers shared by later test
  translation units.
- Consumes: the Task 1 `-text -whitespace` attributes and existing test
  framework.

- [ ] **Step 1: Declare exact common digest and manifest types**

Add this public shape; implementations use bounded arithmetic and return a
short stable error token through `std::string* error`:

```cpp
// src/shared/digest.h
namespace rs2fix {
using Sha256Digest = std::array<std::uint8_t, 32>;
bool ParseSha256Upper(std::string_view text, Sha256Digest* digest) noexcept;
std::array<char, 65> FormatSha256Upper(const Sha256Digest& digest) noexcept;
}

// tools/genuine_manifest.h
namespace rs2fix::tooling {
enum class ManifestState { Provisional, Qualified };

struct VersionQuad {
    std::uint16_t major{};
    std::uint16_t minor{};
    std::uint16_t build{};
    std::uint16_t revision{};
};
bool operator==(const VersionQuad& left, const VersionQuad& right) noexcept;

struct GenuineManifestEntry {
    ManifestState state{};
    Sha256Digest sha256{};
    std::uint64_t fileSize{};
    std::uint32_t coffTimestamp{};
    std::uint32_t sizeOfImage{};
    VersionQuad fileVersion{};
    VersionQuad productVersion{};
    std::string evidencePath;
};

struct GenuineManifest {
    std::vector<GenuineManifestEntry> entries;
};

bool ParseGenuineManifest(
    std::string_view bytes,
    GenuineManifest* manifest,
    std::string* error);
bool ReadGenuineManifest(
    const wchar_t* absolutePath,
    GenuineManifest* manifest,
    Sha256Digest* manifestDigest,
    std::string* error);
const GenuineManifestEntry* FindManifestEntry(
    const GenuineManifest& manifest,
    const Sha256Digest& digest,
    ManifestState requiredState) noexcept;
bool AuditManifestEvidencePaths(
    const wchar_t* absoluteRepositoryRoot,
    const GenuineManifest& manifest,
    std::string* error);
}
```

Do not store machine, export, or signature strings in each entry: the parser
accepts only the fixed literals `AMD64`, `X3DAudioCalculate@1`,
`X3DAudioInitialize@2`, and
`embedded-winverifytrust-v2-cache-only`; successful parsing proves them.

- [ ] **Step 2: Write the failing manifest grammar tests**

`RunManifestTests()` must feed in-memory byte strings to the parser and assert
these exact cases independently:

```text
canonical single qualified entry accepted
provisional entry accepted by parser but not by qualified lookup
1 and 32 entries accepted; 0 and 33 rejected
65536-byte malformed input reaches grammar rejection; 65537 is rejected as oversize
1024-byte malformed line reaches field rejection; 1025 is rejected as line-too-long
BOM, NUL, non-ASCII, bare LF, blank line, and missing final CRLF rejected
duplicate, unknown, missing, misordered, trailing, and non-contiguous keys rejected
lowercase/short/long hash rejected
leading-zero and overflow decimal values rejected
bad timestamp width/case rejected
bad version component/count/leading zero rejected
wrong machine/export/signature literal rejected
absolute/backslash/empty/dot/dot-dot evidence components rejected
evidence hash-stem mismatch rejected
qualified and provisional lookups never cross states
```

The repository test also calls `ReadGenuineManifest` on the checked-in file,
asserts one entry equal to the seed record, reads the raw bytes to prove every
LF is preceded by CR and the file ends in CRLF, and calls
`AuditManifestEvidencePaths(RS2_SOURCE_DIR, manifest)`.

Every focused test translation unit exports one function in the same namespace:

```cpp
namespace rs2fix::testcases {
void RunManifestTests();
void RunCompanionTests();
void RunResolverTests();
void RunPeReaderTests();
void RunRuntimeInventoryTests();
}
```

Task 2 implements only `RunManifestTests`; later tasks supply the remaining
definitions before adding their call. Add to `tests/core_tests.cpp` now:

```cpp
// in main, before any DLL smoke test
rs2fix::testcases::RunManifestTests();
```

Move the existing temporary-file, complete-write, digest parsing, and validated
cleanup helpers into `tests/test_support.h/.cpp`. The public support interface
uses explicit prefix/path arguments and refuses recursive cleanup unless the
root is a direct child of the system temporary directory with that prefix.

Configure `rs2_core_tests` with:

```cmake
target_compile_definitions(rs2_core_tests PRIVATE
  RS2_SOURCE_DIR=L"${CMAKE_CURRENT_SOURCE_DIR}"
  RS2_GENUINE_MANIFEST_PATH=L"${CMAKE_CURRENT_SOURCE_DIR}/config/qualified_x3audio_genuine.manifest")
```

Create the development build tree against the two protected inputs. At this
pre-cutover task only, the still-current baseline CMake graph needs the exact
SDK import library already verified on this host:

```powershell
cmake -S . -B build-plan -G "Visual Studio 18 2026" -A x64 `
  -DRS2_PR1_BASELINE_PATH="D:/Documents/RisingStorm2/VNGame_pr1.exe_old4" `
  -DRS2_CURRENT_STOCK_PATH="D:/Documents/RisingStorm2/Binaries/Server/VNGame_pr3.stock-F4E38510832D1FAA.exe" `
  -DRS2_SYSTEM_FAULTREP_IMPORT_LIBRARY="E:/Windows Kits/10/Lib/10.0.26100.0/um/x64/FaultRep.Lib"
```

Run the core target and record the expected initial failure caused by the
missing parser/manifest:

```powershell
cmake --build build-plan --config Debug --target rs2_core_tests
```

- [ ] **Step 3: Implement the parser as an ordered cursor, not a key map**

Read at most 65,537 bytes so oversize is distinguishable. Reject before parsing
if size exceeds 65,536, any byte is outside `0x01..0x7F`, any LF lacks a
preceding CR, any CR is not followed by LF, or the final bytes are not CRLF.
Split without discarding empty lines; cap each pre-CRLF line at 1,024 bytes.

Consume `schema`, `entry_count`, and every `entry.N.*` key in the specification's
fixed order with an exact expected-key function:

```cpp
bool ConsumeExpectedLine(
    Cursor* cursor,
    std::string_view expectedKey,
    std::string_view* value,
    std::string* error);
```

Use manual checked decimal/hex parsers. Do not use locale, exceptions as
control flow, `std::filesystem`, JSON, regular expressions, or a generic map.
Require all input to be consumed immediately after the final evidence path.

- [ ] **Step 4: Add qualification-evidence formatting and safe writing**

Declare a fixed-field `QualificationEvidence` carrying the three digests,
candidate size/timestamp/image size, both version quads, and child exit status.
`FormatQualificationEvidence` emits the specification's 17 keys, in order:

```text
schema=1
mode=qualify-system32
manifest_sha256=<uppercase digest>
candidate_sha256=<uppercase digest>
candidate_file_size=<decimal>
candidate_machine=AMD64
candidate_coff_timestamp=0x<eight uppercase hex>
candidate_size_of_image=<decimal>
candidate_file_version_quad=<four decimal components>
candidate_product_version_quad=<four decimal components>
candidate_export_1=X3DAudioCalculate@1
candidate_export_2=X3DAudioInitialize@2
candidate_signature_policy=embedded-winverifytrust-v2-cache-only
winverifytrust_status=ERROR_SUCCESS
abi_layout=pass
child_exit_status=0x00000000
control_digest_sha256=<uppercase digest>
```

Every shown line ends in CRLF. `WriteQualificationEvidenceCreateNew` requires an
absolute non-existing path, calls `CreateFileW(..., CREATE_NEW, ...)`, loops
until all bytes are written, flushes, closes, and deletes the partial path on
any short/zero/failed write or flush/close error. Its injectable test operations
are:

```cpp
struct EvidenceFileOps {
    void* context{};
    HANDLE (*createNew)(void*, const wchar_t*, DWORD*) noexcept{};
    bool (*write)(void*, HANDLE, const void*, DWORD, DWORD*, DWORD*) noexcept{};
    bool (*flush)(void*, HANDLE, DWORD*) noexcept{};
    bool (*close)(void*, HANDLE, DWORD*) noexcept{};
    bool (*remove)(void*, const wchar_t*, DWORD*) noexcept{};
};
const EvidenceFileOps& ProductionEvidenceFileOps() noexcept;
```

Tests cover byte-for-byte round trip, existing-output refusal, a forced short
write followed by zero write, flush failure, close failure, partial deletion,
and no file on any failure.

`WriteQualificationEvidenceCreateNew` receives the operation table explicitly;
production runner/preflight/report call sites pass
`ProductionEvidenceFileOps()`.

`ParseQualificationEvidence` is a separate strict ordered cursor for exactly
these 17 lines and the same ASCII/CRLF/number/hash domains. It rejects every
unknown, reordered, duplicate, missing, trailing, or unterminated field and is
used for the byte-for-byte round-trip and Task 10 output verification.

- [ ] **Step 5: Add the exact seed manifest and evidence in the same commit**

The manifest's bytes are exactly the 14 canonical record lines from
specification lines 670-683 (excluding the surrounding fences), with CRLF after
all 14 lines. The evidence Markdown records:

```text
SHA-256: 9460709339701AD471A5CABE6365355F4D586DC4FCB86507C1331839DC555446
file size: 24920
machine: AMD64 (0x8664)
COFF timestamp: 0x4B6B06BE
SizeOfImage: 36864
checksum: 0x00008C0D
file/product fixed versions: 9.28.1886.0 / 9.28.1886.0
display FileVersion: 9.28 (DXSDK_FEB10.100204-0932)
exports: X3DAudioCalculate @1; X3DAudioInitialize @2
signature: embedded Microsoft signature accepted by timestamp-aware
  WinVerifyTrust; signer wall-clock expiry is not manually overridden
initializer: RVA 0x1268, 97-byte leaf, writes all 20 handle bytes,
  RAX is scratch at RET, legacy return contract is void
```

State that the evidence was re-derived from the local System32 file during the
approved design review and is not a universal allowlist.

- [ ] **Step 6: Verify bytes, evidence linkage, and tests before committing**

```powershell
git add -- .gitattributes config/qualified_x3audio_genuine.manifest `
  docs/evidence/x3audio `
  src/shared/digest.h src/shared/digest.cpp `
  tools/genuine_manifest.h tools/genuine_manifest.cpp `
  tests/manifest_tests.cpp tests/test_support.h tests/test_support.cpp `
  tests/core_tests.cpp CMakeLists.txt
git ls-files --eol config/qualified_x3audio_genuine.manifest
git diff --cached --check
cmake --build build-plan --config Debug --target rs2_core_tests
ctest --test-dir build-plan -C Debug -R '^core$' --output-on-failure
```

Required EOL evidence:

```text
i/crlf  w/crlf  attr/-text  config/qualified_x3audio_genuine.manifest
```

Commit only after the repository-side evidence-path assertion passes:

```powershell
git commit -m "feat: add qualified x3audio manifest custody"
```

---

### Task 3: Correct Path Bounds and Migrate the Companion to ABI V2

**Files:**

- Modify: `src/shared/path_identity.h`
- Modify: `src/shared/path_identity.cpp`
- Modify: `src/shared/bootstrap_abi.h`
- Create: `src/shared/version.h`
- Modify: `src/companion/build_identity.h`
- Modify: `src/companion/build_identity.cpp`
- Modify: `src/companion/marker.h`
- Modify: `src/companion/marker.cpp`
- Create: `src/companion/console_status.h`
- Create: `src/companion/console_status.cpp`
- Modify: `src/companion/companion_init.h`
- Modify: `src/companion/companion_init.cpp`
- Modify: `src/companion/companion_main.cpp`
- Modify: `src/companion/RS2ServerFix.def`
- Create: `src/companion/companion_version.rc`
- Delete: `src/bootstrap/faultrep.def`
- Delete: `tools/pe_contract.cpp` (Task 7 recreates it)
- Delete: `tools/deployment_preflight.cpp` (Task 11 recreates it)
- Delete: `tests/static_import_harness.cpp` (Task 8 recreates it)
- Delete: `tests/static_import_runner.cpp` (Task 9 recreates it)
- Delete: `tests/preflight_fixture_test.cpp` (Task 11 recreates it)
- Create: `tests/companion_tests.cpp`
- Modify: `tests/core_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**

- Produces: bounded `AppendPathLeaf` and `ExtractDirectoryAndLeaf` signatures.
- Produces: `BootstrapContextV2`, `InitializeV2Fn`, and V2 validation.
- Produces: schema-2 `MarkerData` and `RS2ServerFix_InitializeV2`.
- Produces: shared `0.1.0.0` version definitions and an exact one-attempt
  success-console writer.
- Consumes: common digest type and existing CNG/build-identity behavior.

- [ ] **Step 1: Write the exact path-boundary and V2 failure tests**

Change the path declarations to:

```cpp
bool ExtractDirectoryAndLeaf(
    const wchar_t* path,
    std::size_t pathCapacity,
    wchar_t* directory,
    std::size_t directoryCapacity,
    wchar_t* leaf,
    std::size_t leafCapacity,
    DWORD* error) noexcept;

bool AppendPathLeaf(
    const wchar_t* directory,
    std::size_t directoryCapacity,
    const wchar_t* leaf,
    std::size_t leafCapacity,
    wchar_t* output,
    std::size_t outputCapacity,
    DWORD* error) noexcept;

bool BuildSystemX3AudioPath(
    wchar_t* output,
    std::size_t outputCapacity,
    DWORD* error) noexcept;
```

Tests independently pass terminated and unterminated arrays at capacities 1,
2, 511, and 512 for path, directory, and leaf. Assert no function reads beyond
the supplied capacity, output starts empty on failure, and errors distinguish
`ERROR_INVALID_NAME` from `ERROR_INSUFFICIENT_BUFFER`. Assert the System32 path
ends in `\\X3DAudio1_7.dll` and fits a 512-wide-character buffer.

For the no-overread cases, place each input at the end of one committed page
followed by a `PAGE_NOACCESS` guard page. Invoke each helper through a
test-only, no-RAII SEH leaf that uses `__try`/`__except`, handles only
`EXCEPTION_ACCESS_VIOLATION`, records that exception as a failed assertion, and
continues the parent `core` role; every other exception continues search. The
allocation and cleanup stay outside the SEH leaf. Do not infer no-overread merely
from a returned error code and do not let one overread terminate the whole role.

Declare and test the exact ABI:

```cpp
inline constexpr std::uint32_t kBootstrapAbiVersion = 2;
inline constexpr std::uint32_t kGenuineInitializePresent = 1u << 0;
inline constexpr std::uint32_t kGenuineCalculatePresent = 1u << 1;
inline constexpr std::uint32_t kRequiredGenuineExports =
    kGenuineInitializePresent | kGenuineCalculatePresent;

struct BootstrapContextV2 {
    std::uint32_t size;
    std::uint32_t abiVersion;
    HMODULE hostModule;
    HMODULE bootstrapModule;
    HMODULE genuineX3AudioModule;
    std::uint32_t genuineExportsMask;
    std::uint32_t reserved;
};
static_assert(sizeof(BootstrapContextV2) == 40);
using InitializeV2Fn = DWORD(WINAPI*)(const BootstrapContextV2*);
```

`ValidateBootstrapContextV2` rejects null, wrong size/version, any null module,
an export mask not exactly `kRequiredGenuineExports`, nonzero reserved, and a
host handle unequal to `GetModuleHandleW(nullptr)`. Keep result values 0-4
unchanged.

Implement these cases in `rs2fix::testcases::RunCompanionTests()` and add its
call to the core-test main in this task.

- [ ] **Step 2: Implement the bounded path signatures and update every caller**

Replace each global-capacity `wcsnlen_s` with the capacity belonging to the
exact input. Literal call sites pass `std::size(L"RS2ServerFix.dll")` or the
equivalent compile-time array extent. Buffer call sites pass their actual array
extent. `BuildSystemX3AudioPath` uses `GetSystemDirectoryW` followed by the new
six-argument `AppendPathLeaf`; delete `BuildSystemFaultrepPath`.

Run:

```powershell
rg -n "BuildSystemFaultrepPath|wcsnlen_s\([^,]+, kPathCapacity\)" src tests
```

Expected after intended fixed-capacity workspaces are reviewed: no stale
faultrep builder and no helper reading an unrelated input with
`kPathCapacity`.

- [ ] **Step 3: Convert the marker to schema 2**

Replace resolver-specific marker fields with:

```cpp
struct MarkerData {
    DWORD processId{};
    std::uint64_t executableSize{};
    Sha256Digest digest{};
    bool digestValid{};
    BuildIdentity buildIdentity{BuildIdentity::Indeterminate};
    DWORD initializeResult{kInitInvalidContext};
    DWORD primaryWriteError{};
    bool bootstrapBesideExecutable{};
    bool companionBesideExecutable{};
    bool genuineSystem32{};
    bool genuineInitializePresent{};
    bool genuineCalculatePresent{};
    bool complete{};
    wchar_t executableLeaf[260]{};
};
```

Emit exactly one value for each field in this order: schema 2, UTC, PID,
executable leaf/size/hash/identity, bootstrap leaf
`X3DAudio1_7.dll`, bootstrap beside flag, companion leaf and beside flag,
`genuine_module=system32`, the two genuine-presence booleans,
`initialize_result`, `primary_write_error`, and terminal `completion`.
No resolver status/error remains. Keep the forbidden-content scan and add
`eac`, `eos`, `player`, `account`, `command_line`, full drive syntax, and
`\\Users\\` to it.

Expose the existing file writer through this DLL-local seam; production
adapters call Win32:

```cpp
struct MarkerFileOps {
    void* context{};
    HANDLE (*createAlways)(void*, const wchar_t*, DWORD*) noexcept{};
    bool (*write)(
        void*, HANDLE, const void*, DWORD, DWORD*, DWORD*) noexcept{};
    bool (*flush)(void*, HANDLE, DWORD*) noexcept{};
    bool (*close)(void*, HANDLE, DWORD*) noexcept{};
    bool (*remove)(void*, const wchar_t*, DWORD*) noexcept{};
};
const MarkerFileOps& ProductionMarkerFileOps() noexcept;
```

Tests force a short write, zero write, flush failure, and close failure and
assert partial deletion. Keep one fallback attempt and captured
`primaryWriteError` only. `WriteMarkerWithFallback` receives a
`const MarkerFileOps&`; companion production code passes
`ProductionMarkerFileOps()` explicitly.

- [ ] **Step 4: Write exact console-status tests**

Add one RC/C++-compatible shared version header with these single-source
definitions:

```cpp
#define RS2FIX_VERSION_QUAD 0,1,0,0
#define RS2FIX_VERSION_ASCII "0.1.0.0"
#define RS2FIX_VERSION_WIDE L"0.1.0.0"
```

Declare the DLL-local seam:

```cpp
struct ConsoleStatusOps {
    void* context{};
    HANDLE (*getStdOutput)(void*, DWORD*) noexcept{};
    bool (*write)(
        void*, HANDLE, const void*, DWORD, DWORD*, DWORD*) noexcept{};
};
const ConsoleStatusOps& ProductionConsoleStatusOps() noexcept;

bool FormatLoadedConsoleLine(
    BuildIdentity identity,
    char* output,
    std::size_t capacity,
    std::size_t* bytesUsed) noexcept;
bool TryWriteLoadedConsoleLine(
    BuildIdentity identity,
    const ConsoleStatusOps& ops) noexcept;
```

`FormatLoadedConsoleLine` returns a byte count excluding the trailing NUL and
requires room for that NUL. It emits exact 7-bit ASCII plus CRLF for each of
`Pr1CrashFullDump`, `Pr1StockBaseline`, `CurrentStock`, `CurrentFullDump`, and
`Unknown`; it rejects `Indeterminate` and an out-of-range enum. On failure it
sets `*bytesUsed` to zero and, when capacity is nonzero, starts output with NUL.

Tests assert every exact identity line, including the full current-full-dump
line, and cover null pointers, capacity zero, one byte less than the required
storage, exactly required storage, and the production `char[192]` bound; a
compile-time assertion proves the longest allowed line plus NUL fits. The
injected writer covers null operation callbacks, null and
`INVALID_HANDLE_VALUE` handles, failed/zero/short/exact writes, exactly one
`getStdOutput` call, at most one `write` call, and no retry. Scan all lines for
paths, hashes, user/account/player/network, EOS/EAC, token, command-line, and
environment content. Assert the displayed version is
`RS2FIX_VERSION_ASCII`; the final source and PE gates prove both resource
scripts consume the same header and produce the same version.

- [ ] **Step 5: Implement and order the one-attempt console status**

Build the line from bounded constant fragments and `BuildIdentityName` into one
fixed `char[192]` stack buffer. Do not use heap allocation, iostream,
`OutputDebugString`, `WriteConsole`, Unreal logging, or CRT logging. The
production adapter calls `GetStdHandle(STD_OUTPUT_HANDLE)` once and calls
`WriteFile` exactly once only for a valid handle; failed, zero, or short writes
return false with no retry or stderr fallback.

Make the injectable orchestration signature exact:

```cpp
DWORD RunCompanionInitialization(
    const BootstrapContextV2& context,
    LONG volatile* state,
    const MarkerFileOps& markerOps,
    const ConsoleStatusOps& consoleOps) noexcept;
```

The production V2 export supplies `ProductionMarkerFileOps()` and
`ProductionConsoleStatusOps()`. After `WriteMarkerWithFallback` returns a
successfully written terminal `completion=complete` marker and only when the
initializer result is `kInitOk`, call `TryWriteLoadedConsoleLine` once, then
publish the terminal initialization state. Ignore the console return value.
Marker failure, a partial marker, indeterminate identity, invalid context, and
duplicate/rejected initialization make no console call. Console failure leaves
the result `kInitOk` and the complete marker untouched. Tests inject ordering
and prove marker-before-console, no console after marker failure, one call after
success, failure nonfatality, and one line under duplicate/concurrent calls.
Do not add a marker field or increment schema 2 for this diagnostic.

- [ ] **Step 6: Migrate initialization and exports to V2 only**

Rename all V1 validation and invocation symbols to V2. The context guarantees
the genuine module and both exports, so `RunCompanionInitialization` sets the
three genuine marker booleans directly from the validated context. Completion
requires valid host hash, both DLLs beside the executable, and the three genuine
booleans. Unknown-but-valid host hashes remain `unknown` and can complete;
hash failure remains `indeterminate`, writes a partial marker when possible,
and returns 3.

`companion_main.cpp` exports only:

```cpp
extern "C" DWORD WINAPI RS2ServerFix_InitializeV2(
    const rs2fix::BootstrapContextV2* context) noexcept;
```

`RS2ServerFix.def` is exactly:

```def
LIBRARY RS2ServerFix
EXPORTS
    RS2ServerFix_InitializeV2
```

Delete V1 declarations and tests. Keep build identity limited to classification
and display names; preflight compares its two explicit current hashes and does
not add a runtime permission predicate. Add a test/source scan proving there is
no hook, patch, detour, address, offset, or write-capability field or function
associated with any identity.

Preserve the existing four digest classifications and protected-input tests:
hash PR1/current stock before and after, derive full-dump copies only in unique
temporary files, verify their expected hashes, and delete the copies. No test
writes either configured source executable.

Remove the existing `OutputDebugStringW` calls. The schema-2 marker and the
exact success-only standard-output line are the companion's only diagnostics
in this milestone; the X3Audio exports remain silent.

In the same change, remove the complete CMake target/registration blocks for
`rs2_faultrep_bootstrap`, `rs2_pe_contract`, `rs2_static_import_harness`,
`rs2_static_import_runner`, `rs2_deployment_preflight`, and
`rs2_preflight_fixture_test`, including the FaultRep import-library search and
all five non-core CTest registrations. Delete `src/bootstrap/faultrep.def`, the
three old process/preflight test sources, and the two old faultrep-specific tool
mains listed in this task. Tasks 7, 8, 9, and 11 recreate those tools/tests only
after their X3Audio contracts exist.

Remove `src/bootstrap/companion_loader.cpp`, `forwarder.cpp`, and
`genuine_resolver.cpp` from `rs2_core_tests` and remove every corresponding old
resolver/forwarder/loader test plus `TestBuiltDllSmoke` and their calls from
`tests/core_tests.cpp`. After Task 2 additions, the exact intermediate core
source set is:

```text
src/companion/build_identity.cpp
src/companion/companion_init.cpp
src/companion/console_status.cpp
src/companion/marker.cpp
src/companion/sha256.cpp
src/shared/digest.cpp
src/shared/path_identity.cpp
tools/genuine_manifest.cpp
tests/test_support.cpp
tests/manifest_tests.cpp
tests/companion_tests.cpp
tests/core_tests.cpp
```

Its only target dependency is `rs2_server_fix_companion`. The remaining old
bootstrap `.cpp/.h` files are temporarily unreferenced inputs that Tasks 4-6
rewrite; no target compiles or emits faultrep code during that interval. After
this cutover, `ctest -N` lists only the passing `core` role. Do not leave a
target or registered test that still asserts V1/faultrep.

Reconfigure the existing tree while deleting the obsolete cache entry:

```powershell
cmake -U RS2_SYSTEM_FAULTREP_IMPORT_LIBRARY -S . -B build-plan
```

CMake does not remove outputs of a deleted target. After reconfiguration,
resolve `build-plan` and verify each candidate below is a direct file beneath
its `Debug` child, then remove only the literal files that exist:

```powershell
$buildRoot = (Resolve-Path -LiteralPath 'build-plan').Path
$debugRoot = Join-Path $buildRoot 'Debug'
foreach ($leaf in @(
    'faultrep.dll', 'faultrep.lib', 'faultrep.exp',
    'faultrep.pdb', 'faultrep.ilk')) {
  $candidate = Join-Path $debugRoot $leaf
  if (Test-Path -LiteralPath $candidate -PathType Leaf) {
    Remove-Item -LiteralPath $candidate
  }
}
```

This is custody-limited cleanup of obsolete worktree build outputs, not a
source, game-tree, or recursive deletion.

- [ ] **Step 7: Add honest companion VERSIONINFO**

Enable RC in the project and add a version resource whose fixed and string
fields identify `RS2ServerFix Project`, product `RS2ServerFix`, description
`RS2ServerFix Milestone 1 Companion`, and original filename
`RS2ServerFix.dll`. Fixed, file-string, and product-string versions all consume
`RS2FIX_VERSION_QUAD`, `RS2FIX_VERSION_ASCII`, or the resource-compatible
equivalent from `src/shared/version.h`; their resulting value is `0.1.0.0`.
It must contain no Microsoft, Epic, or Tripwire authorship claim. Use one
`0409/04B0` string table plus matching translation and add it to the companion
target.

- [ ] **Step 8: Run the focused red/green cycle and commit**

Run the changed tests first to capture the expected compile/assertion failures,
then implement and rerun:

```powershell
cmake --build build-plan --config Debug --target rs2_core_tests `
  rs2_server_fix_companion
ctest --test-dir build-plan -C Debug -R '^core$' --output-on-failure
rg -n "BootstrapContextV1|InitializeV1|RS2ServerFix_InitializeV1" `
  src/shared src/companion tests CMakeLists.txt
rg -n "FaultRep|faultrep|ReportFault" CMakeLists.txt
rg -n -i "WriteProcessMemory|VirtualProtectEx|detour|hook|patch" `
  src/companion src/shared/bootstrap_abi.h
rg -n "OutputDebugString|WriteConsole|UE_LOG|GLog" src/companion
git diff --check
```

Expected final searches: no matches. Direct `GetStdHandle` and `WriteFile`
appear only in `console_status.cpp`; inspect those call sites for the one-call,
no-retry contract. Commit:

```powershell
git add -- CMakeLists.txt src/shared src/companion `
  src/bootstrap/faultrep.def tests tools/pe_contract.cpp `
  tools/deployment_preflight.cpp
git commit -m "feat: migrate companion to x3audio ABI v2"
```

---
### Task 4: Implement Private Genuine X3Audio Resolution

**Files:**

- Rewrite: `src/bootstrap/bootstrap_types.h`
- Rewrite: `src/bootstrap/genuine_resolver.h`
- Rewrite: `src/bootstrap/genuine_resolver.cpp`
- Create: `tests/resolver_tests.cpp`
- Modify: `tests/core_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**

- Produces: exact legacy function types, `X3AudioDispatch`, resolver status and
  failure classification, injectable operations, and
  `ResolveGenuineX3AudioPrivate`.
- Consumes: Task 3 path/file-identity functions.
- Build graph: add `src/bootstrap/genuine_resolver.cpp` and
  `tests/resolver_tests.cpp` to `rs2_core_tests`; the old companion loader and
  forwarder remain absent until Tasks 6 and 5 respectively.

- [ ] **Step 1: Lock the legacy ABI and result model in compile-time tests**

Use only opaque byte/void pointers in production bootstrap headers:

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

struct X3AudioDispatch {
    HMODULE module{};
    X3DAudioInitializeFn initialize{};
    X3DAudioCalculateFn calculate{};
    GenuineResolverStatus status{GenuineResolverStatus::LoadFailed};
    DWORD win32Error{};
};
```

Add `static_assert`s for both function-pointer types, `WINAPI`, the 20-byte
handle contract, and all-or-none dispatch validity. Include neither
`x3daudio.h` nor `ErrorRep.h` anywhere beneath `src/bootstrap`.

Define these stable statuses and classification:

```cpp
enum class GenuineResolverStatus : std::uint32_t {
    Ok = 0,
    SystemPathFailed,
    PathCapacityFailed,
    LoadFailed,
    SelfModule,
    CandidatePathFailed,
    FileIdentityFailed,
    WrongFile,
    InitializeExportMissing,
    CalculateExportMissing,
    InitializeAddressQueryFailed,
    CalculateAddressQueryFailed,
    InitializeWrongAllocationBase,
    CalculateWrongAllocationBase,
};
enum class GenuineFailureClass : std::uint32_t {
    None,
    ResourceApi,
    Validation,
};
```

`SystemPathFailed`, `PathCapacityFailed`, `LoadFailed`,
`CandidatePathFailed`, and `FileIdentityFailed` classify as `ResourceApi`;
all remaining non-OK statuses classify as `Validation`.

- [ ] **Step 2: Add a complete operation seam without production globals**

The operation table carries one explicit context pointer and these adapters:

```cpp
struct GenuineResolverOps {
    void* context{};
    bool (*buildSystemPath)(
        void*, wchar_t*, std::size_t, DWORD*) noexcept{};
    HMODULE (*loadSystemLibrary)(
        void*, const wchar_t*, DWORD*) noexcept{};
    bool (*getModulePath)(
        void*, HMODULE, wchar_t*, std::size_t, DWORD*) noexcept{};
    bool (*queryFileIdentity)(
        void*, const wchar_t*, FileIdentity*, DWORD*) noexcept{};
    FARPROC (*getExport)(
        void*, HMODULE, const char*, DWORD*) noexcept{};
    bool (*queryAllocationBase)(
        void*, FARPROC, const void**, DWORD*) noexcept{};
    bool (*freeLibrary)(void*, HMODULE) noexcept{};
    void* (*allocateDispatch)(void*) noexcept{};
    bool (*freeDispatch)(void*, void*) noexcept{};
    bool (*beginOnce)(
        void*, INIT_ONCE*, DWORD, BOOL*, void**, DWORD*) noexcept{};
    bool (*completeOnce)(
        void*, INIT_ONCE*, DWORD, void*, DWORD*) noexcept{};
};

const GenuineResolverOps& ProductionGenuineResolverOps() noexcept;
```

The production table is namespace-scope `constexpr` POD pointing at plain
adapter functions, so it requires no dynamic initialization. Adapters capture
`GetLastError` immediately. Tests provide one stateful fake through `context`;
they never replace a process-global function pointer.

- [ ] **Step 3: Write every private validation failure before implementation**

`ValidateGenuineEvidence` accepts bootstrap/candidate modules, expected/actual
file identities, both exports, both query-success booleans, and both allocation
bases. Add one assertion for each status, including candidate equal to
bootstrap, each export independently missing, each query independently failed,
and each base unequal to candidate or equal to bootstrap. Success requires both
bases equal the candidate.

Fake-operation tests then force, one at a time:

```text
System32 API failure
512-character path capacity failure
LoadLibraryExW failure
self module (and zero FreeLibrary calls)
candidate module-path failure
expected identity failure
actual identity failure
wrong identity
each GetProcAddress failure
each VirtualQuery failure
each wrong allocation base
complete success with one owned module reference
```

Each failure checks its status, class, exact stored Win32 error, cleared
dispatch, and exactly one `FreeLibrary` for a non-self loaded candidate.
Implement them in `rs2fix::testcases::RunResolverTests()` and add its call to
the core-test main in this task.

- [ ] **Step 4: Implement the private resolver with 512-character stack buffers**

`ResolveGenuineX3AudioPrivate(bootstrap, ops)` performs only this ordered
sequence:

```text
zero expectedPath[512] and candidatePath[512]
build absolute configured System32 leaf
LoadLibraryExW(absolute, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)
reject null or bootstrap self-module
obtain candidate full path
query expected and candidate FileIdentity
resolve X3DAudioInitialize and X3DAudioCalculate by name
VirtualQuery both and require AllocationBase == candidate != bootstrap
return one complete X3AudioDispatch plus ownsModule=true
```

Production uses exact leaf `X3DAudio1_7.dll`. A private result type carries
`X3AudioDispatch dispatch`, `GenuineFailureClass failureClass`, and
`bool ownsModule`; no failed result owns a reference. Do not allocate a path
workspace, load the companion, hash, write, publish, or retry here.

The production `buildSystemPath` adapter uses a compile-time wide array whose
default is exactly `X3DAudio1_7.dll`; only the isolated Task 6 test target
overrides it. It calls `GetSystemDirectoryW` and the capacity-aware append
helper. Map `ERROR_INSUFFICIENT_BUFFER` from this adapter to
`PathCapacityFailed`; other path API errors map to `SystemPathFailed`.

- [ ] **Step 5: Run the resolver-only tests and commit**

```powershell
cmake --build build-plan --config Debug --target rs2_core_tests
ctest --test-dir build-plan -C Debug -R '^core$' --output-on-failure
rg -n "x3daudio.h|ErrorRep.h|ReportFault" src/bootstrap/bootstrap_types.h `
  src/bootstrap/genuine_resolver.h src/bootstrap/genuine_resolver.cpp
git diff --check
git add -- CMakeLists.txt src/bootstrap/bootstrap_types.h `
  src/bootstrap/genuine_resolver.h src/bootstrap/genuine_resolver.cpp `
  tests/resolver_tests.cpp tests/core_tests.cpp
git commit -m "feat: resolve genuine system x3audio"
```

Expected source scan: no matches.

---
### Task 5: Add Non-Waiting Publication, Leases, and Exact Forwarding

**Files:**

- Modify: `src/bootstrap/bootstrap_types.h`
- Modify: `src/bootstrap/genuine_resolver.h`
- Modify: `src/bootstrap/genuine_resolver.cpp`
- Rewrite: `src/bootstrap/forwarder.h`
- Rewrite: `src/bootstrap/forwarder.cpp`
- Modify: `tests/resolver_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**

- Produces: `GenuineResolverState`, `GenuineDispatchLease`,
  `AcquireGenuineX3Audio`, `ReleaseGenuineX3AudioLease`,
  `TryForwardInitialize`, `TryForwardCalculate`, and `FailFastX3Audio`.
- Consumes: Task 4 private resolver and operation table.
- Build graph: add `src/bootstrap/forwarder.cpp` to `rs2_core_tests`; retain the
  Task 4 resolver sources and tests, but do not add `companion_loader.cpp` yet.

- [ ] **Step 1: Declare the zero-initialized state and value lease**

```cpp
enum class AcquireMode : std::uint32_t {
    WorkerSingleAttempt,
    ExportRetryOnce,
};
enum class FallbackState : LONG { Empty = 0, Writing = 1, Ready = 2 };

struct GenuineResolverState {
    INIT_ONCE normalOnce{};
    alignas(8) X3AudioDispatch fallback{};
    LONG volatile fallbackState{};
};

struct GenuineDispatchLease {
    X3AudioDispatch dispatch{};
    bool valid{};
    bool releaseModuleOnClose{};
};

GenuineDispatchLease AcquireGenuineX3Audio(
    GenuineResolverState* state,
    HMODULE bootstrap,
    const GenuineResolverOps& ops,
    AcquireMode mode) noexcept;
void ReleaseGenuineX3AudioLease(
    GenuineDispatchLease* lease,
    const GenuineResolverOps& ops) noexcept;
```

The lease copies a complete immutable dispatch by value. Persistent normal or
fallback leases set `releaseModuleOnClose=false`; a private current-operation
lease sets it true. `ReleaseGenuineX3AudioLease` calls the injected
`freeLibrary` exactly once only for a valid transient lease, then clears it.
Define the required context alignment as
`std::uintptr_t{1} << INIT_ONCE_CTX_RESERVED_BITS`; use `static_assert` on
`alignof(GenuineResolverState)` and `offsetof(GenuineResolverState, fallback)`
rather than attempting to assert a runtime address as a constant expression.
Runtime unit assertions check the low reserved bits of both an allocated normal
record and `&state.fallback`. `VirtualAlloc` supplies normal page alignment and
`alignas(8)` supplies static alignment.

- [ ] **Step 2: Write deterministic publication tests with fake operations**

Add separate tests for:

```text
CHECK_ONLY returns the normal record without resolution
normal miss followed by Ready fallback without resolution
Empty and Writing fallback readers never touch the record
ASYNC begin winner publishes one complete page-aligned record
concurrent successful callers expose no partial dispatch
InitOnceComplete false plus visible normal winner releases loser record/ref
InitOnceComplete false plus no winner claims and publishes fallback
dispatch allocation failure claims and publishes fallback
begin-initialize API failure still produces a private success then fallback
fallback claimant offers the Ready static address to InitOnceComplete
fallback completion rejection leaves Ready usable
fallback loser seeing Ready releases its private ref and uses persistent data
fallback loser seeing Writing returns a transient lease without waiting
repeated post-failure acquisitions retain at most normal plus fallback refs
failed worker attempt leaves INIT_ONCE retryable
resource/API export failure performs exactly two private attempts
validation export failure performs exactly one private attempt
failure checks normal and Ready fallback before, between, and after attempts
```

The concurrency case starts 32 threads behind one test event, gives the fake
resolver a small controlled yield, and has a strict two-second test bound.
Assert every successful lease contains all three non-null module/function fields, normal
publication count is exactly one, fallback publication count is at most one,
and `loads - frees` is at most two after all transient leases close.

- [ ] **Step 3: Implement the exact async state machine**

Use these helpers, all non-blocking:

```cpp
bool TryGetNormal(
    GenuineResolverState*, const GenuineResolverOps&,
    X3AudioDispatch*, DWORD*) noexcept;
bool TryGetReadyFallback(
    GenuineResolverState*, X3AudioDispatch*) noexcept;
GenuineDispatchLease PublishPrivateSuccess(
    GenuineResolverState*, GenuineResolverResult&&,
    bool beginSucceeded, BOOL pending,
    const GenuineResolverOps&) noexcept;
```

`TryGetNormal` calls `InitOnceBeginInitialize` with
`INIT_ONCE_CHECK_ONLY`; it accepts context only when the call succeeds,
`pending==FALSE`, and the dispatch is complete. `TryGetReadyFallback` performs
the acquire read exactly as
`InterlockedCompareExchange(&state->fallbackState, 0, 0)` and reads the static
record only when the returned value is `Ready`.

For initialization use `InitOnceBeginInitialize(INIT_ONCE_ASYNC)`. A fully
validated private success allocates one `VirtualAlloc` record, copies the
complete dispatch, and offers the aligned address with
`InitOnceComplete(INIT_ONCE_ASYNC, record)`. On completion failure, immediately
CHECK_ONLY: a visible winner releases the loser's allocation and module; no
winner frees only the allocation and carries the module into fallback.

Before allocating/offering a private success obtained after a begin-API error,
re-check normal and Ready fallback. If either appeared during resolution,
release the private module and use the persistent record. This same check runs
before entering fallback after allocation failure, so a concurrent winner is
never needlessly shadowed.

Fallback publication is exactly:

```cpp
if (InterlockedCompareExchange(
        &state->fallbackState,
        static_cast<LONG>(FallbackState::Writing),
        static_cast<LONG>(FallbackState::Empty)) ==
    static_cast<LONG>(FallbackState::Empty)) {
    state->fallback = privateResult.dispatch;
    InterlockedExchange(
        &state->fallbackState,
        static_cast<LONG>(FallbackState::Ready));
    ops.completeOnce(
        ops.context, &state->normalOnce, INIT_ONCE_ASYNC,
        &state->fallback, &ignoredError);
    // this module reference is retained through process exit
}
```

No API, allocation, loader call, external function, or fallible operation is
placed between the successful `Empty -> Writing` claim and `Ready`. A loser
does one acquire read: Ready means release its own module and copy the fallback;
Writing means return its complete private transient lease. It never spins,
sleeps, waits, or retries publication.

After a failed private resolution, re-check normal then fallback. In export
mode, only `ResourceApi` begins one second private attempt; check normal and
fallback once between attempts and once after the second failure. Preserve the
second local failure if no publication appeared. Worker mode stops after one.

- [ ] **Step 4: Implement call-through helpers and fail-fast terminal**

```cpp
bool TryForwardInitialize(
    GenuineResolverState*, HMODULE bootstrap,
    const GenuineResolverOps&, UINT32 mask, FLOAT speed,
    BYTE* instance20Bytes);
bool TryForwardCalculate(
    GenuineResolverState*, HMODULE bootstrap,
    const GenuineResolverOps&, const BYTE* instance20Bytes,
    const void* listener, const void* emitter, UINT32 flags,
    void* settings);
[[noreturn]] void FailFastX3Audio() noexcept;
```

Each try helper acquires in `ExportRetryOnce` mode, invokes the genuine function
once with bit-identical arguments, and releases only a transient lease after
the genuine call returns. It does not wrap the genuine call in `try/catch` and
is not declared `noexcept`, so a genuine exception is not translated.

`FailFastX3Audio` calls:

```cpp
RaiseFailFastException(
    nullptr, nullptr, FAIL_FAST_GENERATE_EXCEPTION_ADDRESS);
TerminateProcess(GetCurrentProcess(), 0xC0000602UL);
__assume(0);
```

Unit stubs prove mask/speed/handle and all calculate pointers/flags are exactly
the originals and output bytes are solely those written by the stub. Do not
invoke production fail-fast in the unit-test process.

- [ ] **Step 5: Run concurrency repeatedly and commit**

```powershell
cmake --build build-plan --config Debug --target rs2_core_tests
1..20 | ForEach-Object {
  & 'build-plan\Debug\rs2_core_tests.exe'
  if ($LASTEXITCODE -ne 0) { throw "core iteration $_ failed" }
}
ctest --test-dir build-plan -C Debug -R '^core$' --output-on-failure
rg -n "WaitFor|Sleep|EnterCriticalSection|AcquireSRWLock" `
  src/bootstrap/genuine_resolver.cpp
git diff --check
git add -- CMakeLists.txt src/bootstrap tests/resolver_tests.cpp
git commit -m "feat: publish and forward x3audio without waiting"
```

Expected resolver wait-primitive scan: no matches.

---
### Task 6: Integrate the V2 Companion and Cut Over to the X3Audio DLL

**Files:**

- Rewrite: `src/bootstrap/companion_loader.h`
- Rewrite: `src/bootstrap/companion_loader.cpp`
- Rewrite: `src/bootstrap/bootstrap_main.cpp`
- Create: `src/bootstrap/X3DAudio1_7.def`
- Create: `src/bootstrap/bootstrap_version.rc`
- Modify: `tests/companion_tests.cpp`
- Modify: `tests/core_tests.cpp`
- Modify: `CMakeLists.txt`
- Delete after replacement: any remaining faultrep-only declarations or source
  fragments beneath `src/bootstrap`

**Interfaces:**

- Produces: `BuildCompanionPath`, V2 companion validation/load/invocation, the
  production bootstrap DLL, and the isolated missing-genuine test DLL.
- Consumes: Tasks 3-5 V2 ABI, resolver state/leases, and forwarders.
- Build graph: return `src/bootstrap/companion_loader.cpp` to
  `rs2_core_tests`; create the production and isolated test bootstrap targets
  from the Task 4/5 resolver and forwarder sources. No generated bootstrap
  import library is linked into a test consumer.

- [ ] **Step 1: Write companion-loader V2 tests**

Keep the pure validation seam and cover null candidate, bootstrap collision,
genuine collision, missing export, bad expected/actual identity, wrong file,
failed address query, wrong allocation base, and success. Resolve only
`RS2ServerFix_InitializeV2`.

`BuildCompanionPath` must end in `\\RS2ServerFix.dll`, use the new capacities,
and reject null, unterminated, too-small, or non-module inputs. An actual
missing-companion test must return `LoadFailed` without changing a valid
genuine dispatch.

- [ ] **Step 2: Implement V2 loading with persistent successful ownership**

`LoadAndInitializeCompanion(bootstrap, context)`:

```text
validate bootstrap and context.bootstrapModule
build absolute sibling path
LoadLibraryExW(absolute, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)
reject bootstrap/genuine collisions
compare expected and candidate FileIdentity
resolve RS2ServerFix_InitializeV2
VirtualQuery and require AllocationBase == candidate
call initializer once
retain candidate for Ok, AlreadyInitialized, or initializer failure
release candidate only for pre-invocation validation/load failures
```

The function never retries and never affects genuine publication.

- [ ] **Step 3: Implement the one-worker bootstrap lifetime**

Use only zero-initialized POD globals:

```cpp
HMODULE g_bootstrapModule{};
rs2fix::GenuineResolverState g_genuineState{};
```

The worker acquires with `WorkerSingleAttempt`; on failure it returns 0 without
companion work. On success it fills exactly:

```cpp
BootstrapContextV2 context{
    sizeof(BootstrapContextV2),
    kBootstrapAbiVersion,
    GetModuleHandleW(nullptr),
    bootstrap,
    lease.dispatch.module,
    kRequiredGenuineExports,
    0,
};
```

It calls the companion loader once, then releases only a transient genuine
lease. A normally/fallback published genuine and any validated companion remain
mapped through process exit.

`DllMain(DLL_PROCESS_ATTACH)` stores `instance`, calls `CreateThread` with that
handle, closes a non-null thread handle, and returns `TRUE` regardless. Every
other reason returns `TRUE` without work. Do not call any resolver, loader,
hash, marker, logging, or wait API in `DllMain`.

- [ ] **Step 4: Define the two public exports and exact ordinals**

```cpp
extern "C" void WINAPI X3DAudioInitialize(
    UINT32 mask, FLOAT speed, BYTE* instance20Bytes) {
    if (!rs2fix::TryForwardInitialize(
            &g_genuineState, g_bootstrapModule,
            rs2fix::ProductionGenuineResolverOps(),
            mask, speed, instance20Bytes)) {
        rs2fix::FailFastX3Audio();
    }
}

extern "C" void WINAPI X3DAudioCalculate(
    const BYTE* instance20Bytes, const void* listener,
    const void* emitter, UINT32 flags, void* settings) {
    if (!rs2fix::TryForwardCalculate(
            &g_genuineState, g_bootstrapModule,
            rs2fix::ProductionGenuineResolverOps(),
            instance20Bytes, listener, emitter, flags, settings)) {
        rs2fix::FailFastX3Audio();
    }
}
```

`X3DAudio1_7.def` is exactly:

```def
LIBRARY X3DAudio1_7
EXPORTS
    X3DAudioCalculate @1
    X3DAudioInitialize @2
```

- [ ] **Step 5: Add honest bootstrap VERSIONINFO and production target**

The bootstrap resource identifies company `RS2ServerFix Project`, product
`RS2ServerFix`, description `RS2ServerFix Passive X3Audio Bootstrap`, and
original filename `X3DAudio1_7.dll`. Fixed, file-string, and product-string
versions consume the same `src/shared/version.h` definitions as the companion
resource and console formatter and resolve to `0.1.0.0`, with no third-party
authorship claim. Use one `0409/04B0` string table plus matching translation.

Create `rs2_x3audio_bootstrap` from bootstrap sources, the shared path source,
the `.def`, and `.rc`; set output name `X3DAudio1_7`. Restore the core smoke
dependency on this target and the companion. Remove the unreferenced old
faultrep implementation completely. The ordinal-bearing target-generated import
library is not a test linkage mechanism; Task 7 creates the separate by-name
test import library.

- [ ] **Step 6: Build the non-deployable missing-genuine variant in isolation**

Create `rs2_x3audio_missing_genuine_bootstrap` from the same sources with:

```cmake
target_compile_definitions(rs2_x3audio_missing_genuine_bootstrap PRIVATE
  RS2_GENUINE_X3AUDIO_LEAF=L"RS2ServerFix_missing_X3Audio1_7_for_test.dll")
set_target_properties(rs2_x3audio_missing_genuine_bootstrap PROPERTIES
  OUTPUT_NAME X3DAudio1_7
  RUNTIME_OUTPUT_DIRECTORY_DEBUG
    "${CMAKE_BINARY_DIR}/test-invalid-genuine/Debug"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE
    "${CMAKE_BINARY_DIR}/test-invalid-genuine/Release"
  LIBRARY_OUTPUT_DIRECTORY_DEBUG
    "${CMAKE_BINARY_DIR}/test-invalid-genuine/Debug"
  LIBRARY_OUTPUT_DIRECTORY_RELEASE
    "${CMAKE_BINARY_DIR}/test-invalid-genuine/Release"
  ARCHIVE_OUTPUT_DIRECTORY_DEBUG
    "${CMAKE_BINARY_DIR}/test-invalid-genuine/Debug"
  ARCHIVE_OUTPUT_DIRECTORY_RELEASE
    "${CMAKE_BINARY_DIR}/test-invalid-genuine/Release"
  PDB_OUTPUT_DIRECTORY_DEBUG
    "${CMAKE_BINARY_DIR}/test-invalid-genuine/Debug"
  PDB_OUTPUT_DIRECTORY_RELEASE
    "${CMAKE_BINARY_DIR}/test-invalid-genuine/Release")
```

No install, packaging, copy, or release-artifact target depends on this variant;
only `rs2_static_import_runner` will later depend on its explicit target path.

- [ ] **Step 7: Update the built-DLL smoke and prove the graph cutover**

The core smoke loads the absolute sibling `X3DAudio1_7.dll`, resolves both
exports, waits only in test code for a complete schema-2 marker, confirms the
V2 companion export, deletes only its PID marker, and never unloads either DLL
while the worker could run.

Run:

```powershell
cmake --build build-plan --config Debug --target rs2_core_tests `
  rs2_x3audio_bootstrap rs2_server_fix_companion `
  rs2_x3audio_missing_genuine_bootstrap
ctest --test-dir build-plan -C Debug -R '^core$' --output-on-failure
rg -n -i "faultrep|ReportFault|BootstrapContextV1|InitializeV1" `
  CMakeLists.txt src tests
Get-ChildItem -LiteralPath 'build-plan' -Filter 'faultrep.dll' -Recurse
git diff --check
```

Expected: both searches produce no matches/files. Commit:

```powershell
git add -A -- CMakeLists.txt src tests
git commit -m "feat: cut over to passive x3audio bootstrap"
```

---
### Task 7: Extend PE Evidence and Enforce Built-Artifact Contracts

**Files:**

- Modify: `tools/pe_reader.h`
- Modify: `tools/pe_reader.cpp`
- Create: `tools/file_evidence.h`
- Create: `tools/file_evidence.cpp`
- Create: `tools/pe_contract_lib.h`
- Create: `tools/pe_contract_lib.cpp`
- Create: `tools/pe_contract.cpp`
- Create: `tests/X3DAudio1_7_named_import.def`
- Create: `tests/normal_import_fixture.cpp`
- Create: `tests/delay_import_fixture.cpp`
- Create: `tests/pe_reader_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**

- Produces: complete bounded normal/delay import metadata, PE identity/TLS
  metadata, fixed-version evidence, embedded-signature result, and reusable PE
  contract checks.
- Consumes: production DLLs plus a separate test-only, by-name X3Audio import
  library; no test consumer links the ordinal-bearing production import
  library.

- [ ] **Step 1: Extend the PE model before changing the parser**

```cpp
struct Image {
    std::uint16_t machine{};
    std::uint16_t characteristics{};
    std::uint16_t optionalMagic{};
    std::uint16_t dllCharacteristics{};
    std::uint32_t coffTimestamp{};
    std::uint32_t sizeOfImage{};
    std::uint32_t checksum{};
    std::uint32_t tlsDirectoryRva{};
    std::uint32_t tlsDirectorySize{};
    std::uint32_t exportFunctionCount{};
    std::vector<ImportModule> normalImports;
    std::vector<ImportModule> delayImports;
    std::vector<ExportSymbol> exports;
};
```

Rename the old `imports` field to `normalImports` and update every retained
consumer in the same step. Task 3 deleted the old faultrep-specific PE/preflight
mains, so they are not deferred stale consumers; Task 11 creates the new
preflight against `normalImports`/`delayImports`. A whole-tree
`rg -n "\.imports\b" tools tests` must have no matches after this step.

Store image base in the internal parsed headers so VA-form delay descriptors can
be converted with checked subtraction. A data-directory entry is valid only
when RVA and size are both zero or both nonzero.

Retain checked add/multiply/map arithmetic and add explicit parser ceilings:
nonempty file at most 512 MiB, section count 1-96, at most 16 data directories,
and names at most 4,096 bytes including their terminator. Counts derived from
directories/arrays must also fit the backing file before vector reservation.

- [ ] **Step 2: Build real normal and delay fixtures**

Create `tests/X3DAudio1_7_named_import.def` exactly as:

```def
LIBRARY X3DAudio1_7
EXPORTS
    X3DAudioCalculate
    X3DAudioInitialize
```

Keep this ordinal-free file test-only. Generate its configuration-specific
import library with the MSVC archiver rather than the bootstrap target:

```cmake
get_filename_component(_rs2_archiver_name "${CMAKE_AR}" NAME)
if(NOT _rs2_archiver_name MATCHES "^lib(\\.exe)?$")
  message(FATAL_ERROR "MSVC lib.exe is required for the named X3Audio test import library")
endif()
set(_rs2_named_import_dir
  "${CMAKE_CURRENT_BINARY_DIR}/test-import/$<CONFIG>")
set(RS2_X3DAUDIO_NAMED_IMPORT_LIBRARY
  "${_rs2_named_import_dir}/X3DAudio1_7_named.lib")
add_custom_command(
  OUTPUT "${RS2_X3DAUDIO_NAMED_IMPORT_LIBRARY}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${_rs2_named_import_dir}"
  COMMAND "${CMAKE_AR}" /NOLOGO
    "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/tests/X3DAudio1_7_named_import.def"
    /NAME:X3DAudio1_7.dll /MACHINE:X64
    "/OUT:${RS2_X3DAUDIO_NAMED_IMPORT_LIBRARY}"
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/X3DAudio1_7_named_import.def"
  VERBATIM)
add_custom_target(rs2_x3audio_named_import_library
  DEPENDS "${RS2_X3DAUDIO_NAMED_IMPORT_LIBRARY}")
```

Both fixture executables declare the imported legacy initializer as:

```cpp
extern "C" __declspec(dllimport) void WINAPI X3DAudioInitialize(
    UINT32, FLOAT, BYTE*);
volatile auto g_x3audioImportAnchor = &X3DAudioInitialize;
int main() { return g_x3audioImportAnchor == nullptr ? 1 : 0; }
```

Link both to the explicit `${RS2_X3DAUDIO_NAMED_IMPORT_LIBRARY}` path and add a
dependency on `rs2_x3audio_named_import_library`. Do not link either fixture to
`rs2_x3audio_bootstrap`. For the delay fixture additionally link `delayimp.lib`
and pass `/DELAYLOAD:X3DAudio1_7.dll`. These PE fixtures are parser inputs and
are not executed. Their parsed imports must prove that this library generated a
by-name rather than ordinal thunk.

- [ ] **Step 3: Write parser mutation tests first**

Copy fixtures only into a unique temporary root. Add checked test-only helpers
that locate NT headers, data directories, section-backed RVAs, descriptors, and
thunks. Mutate copies and assert descriptive rejection for:

```text
partial normal directory
unterminated normal descriptor array
invalid normal module-name RVA
unterminated normal thunk
invalid normal import-by-name RVA
invalid normal ordinal bits
partial delay directory
unterminated delay descriptor array
unsupported delay attributes
underflowing VA-form delay field
invalid delay module-name RVA
missing/invalid delay HMODULE slot
missing/invalid delay IAT
missing delay INT
unterminated delay thunk
invalid delay import-by-name RVA
invalid delay ordinal bits
partial TLS directory
truncated export arrays
```

Patch valid normal and delay lookup thunks separately to ordinal 1 and ordinal 2
and assert the parser reports `byOrdinal=true` with the exact value. Assert the
unmodified fixtures report named `X3DAudioInitialize` in the correct normal
versus delay vector and nowhere else.

- [ ] **Step 4: Parse delay descriptors with the same bounded thunk reader**

Read `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`. For each descriptor, require a
complete all-zero terminator within the directory size. Accept only attribute
bits defined by `dlattrRva`. When RVA mode is absent, convert name/INT fields
and every other nonzero address field from VA to RVA by checked subtraction
from the optional-header image base. Require mapped name, HMODULE slot, IAT,
and INT; validate optional bound/unload tables when nonzero. Use `pINT`, never
the mutable IAT, as the lookup table. Reuse the PE32/PE32+ normal thunk parser,
including ordinal validation and a required zero terminator. Append only
complete modules to `delayImports`.

Also copy `TimeDateStamp`, `SizeOfImage`, `CheckSum`, and TLS directory
RVA/size from the correctly sized optional header.

- [ ] **Step 5: Add fixed-version, hash, and WinTrust evidence**

`tools/file_evidence.h` defines:

```cpp
struct FileEvidence {
    std::uint64_t fileSize{};
    Sha256Digest sha256{};
    pe::Image image{};
    VersionQuad fileVersion{};
    VersionQuad productVersion{};
};
bool ReadFileEvidence(
    const wchar_t* absolutePath,
    ULONGLONG hashDeadline,
    FileEvidence* evidence,
    std::string* error);
struct EmbeddedSignatureResult {
    LONG verifyStatus{};
    LONG closeStatus{};
    bool closeAttempted{};
};
struct WinTrustOps {
    void* context{};
    LONG (*invoke)(
        void*, HWND, GUID*, WINTRUST_DATA*) noexcept{};
};
EmbeddedSignatureResult VerifyEmbeddedSignatureCacheOnly(
    const wchar_t* absolutePath,
    const WinTrustOps& ops) noexcept;
const WinTrustOps& ProductionWinTrustOps() noexcept;
bool MatchesGenuineManifestEntry(
    const FileEvidence& evidence,
    const GenuineManifestEntry& entry,
    std::string* error) noexcept;
```

Use existing CNG hashing, `GetFileVersionInfoSizeW`,
`GetFileVersionInfoW`, and `VerQueryValueW(L"\\")` to read only
`VS_FIXEDFILEINFO`; display strings never enter machine comparison.

For signature verification initialize `WINTRUST_FILE_INFO` and
`WINTRUST_DATA` with no UI, `WTD_REVOKE_NONE`, `WTD_CHOICE_FILE`,
`WTD_CACHE_ONLY_URL_RETRIEVAL`, and
`WINTRUST_ACTION_GENERIC_VERIFY_V2`. Always issue paired
`WTD_STATEACTION_VERIFY` and `WTD_STATEACTION_CLOSE`; accept only when VERIFY
and CLOSE both return `ERROR_SUCCESS` and `closeAttempted` is true. Preserve
both statuses for evidence. Do not inspect certificate `NotAfter` or accept
catalogue-only trust.

Pass `reinterpret_cast<HWND>(INVALID_HANDLE_VALUE)` and set
`dwUIChoice=WTD_UI_NONE`; a provider must never display or request user input.

`MatchesGenuineManifestEntry` checks size, digest, AMD64, timestamp, image size,
both version quads, export function/name count exactly two, and exact names/
ordinals. Runner, preflight, and qualification all call this one comparator.
Targets compiling file evidence link `bcrypt`, `version`, and `wintrust`;
preflight additionally links `advapi32` for read-only KnownDLL enumeration.
Neither production DLL links `version`, `wintrust`, or `advapi32`.

- [ ] **Step 6: Centralize exact artifact contracts**

`pe_contract_lib` returns a vector of stable finding strings and exposes:

```cpp
bool CheckBootstrapContract(
    const wchar_t* path, ContractReport* report);
bool CheckCompanionContract(
    const wchar_t* path, ContractReport* report);
bool CheckHarnessContract(
    const wchar_t* path, ContractReport* report);
```

Bootstrap requirements: AMD64 PE32+ DLL, all three security flags, zero TLS,
empty delay imports, exactly two functions/names with Calculate @1 and
Initialize @2, direct modules exactly `KERNEL32.dll`, no self/companion import,
no dynamic CRT, and VERSIONINFO exactly matching company
`RS2ServerFix Project`, product `RS2ServerFix`, description
`RS2ServerFix Passive X3Audio Bootstrap`, and original filename
`X3DAudio1_7.dll`.

Companion requirements: same machine/security/TLS properties, empty delay
imports, exactly one named V2 export, direct modules exactly `KERNEL32.dll`
and `bcrypt.dll`, no dynamic CRT, and VERSIONINFO exactly matching company
`RS2ServerFix Project`, product `RS2ServerFix`, description
`RS2ServerFix Milestone 1 Companion`, and original filename
`RS2ServerFix.dll`. Reject Microsoft, Epic, or Tripwire authorship text in any
identity value. Both project DLL contracts require fixed and display version
`0.1.0.0` and exactly one `0409/04B0` translation.

Harness requirements: AMD64 PE32+ executable with all three security flags,
zero TLS, one normal `X3DAudio1_7.dll!X3DAudioInitialize` by-name import, no
X3Audio delay import, and no dynamic Visual C++ runtime. Its exact initial
direct-module allowlist is `KERNEL32.dll`, `bcrypt.dll`, and
`X3DAudio1_7.dll`; an observed API-set import is a failure requiring reviewed
amendment, not a prefix wildcard.

The PE CLI has this exact named grammar:

```text
rs2_pe_contract
  --kind <bootstrap|companion|harness>
  --file <absolute existing plain file>
```

Each option occurs exactly once; relative, duplicate, unknown, missing, or
quoted values return usage error 2 before a file is opened. Sole `--help`
prints this complete grammar and returns 0 without file access; combining
`--help` with anything returns 2.

The CLI prints separate `normal_import_` and `delay_import_` evidence,
metadata/TLS, VERSIONINFO identity, exports, all findings, and terminal
`contract=pass` only on success.

`ContractReport` contains `bool passed`, the parsed `pe::Image`, the fixed
VERSIONINFO identity strings, and an ordered `std::vector<std::string>` of
findings. Each check resets the report before use and never prints internally;
the CLI and preflight render the same findings independently.

- [ ] **Step 7: Add the parser tests to core and run the PE CTest roles**

Compile `tests/pe_reader_tests.cpp` and `tools/pe_reader.cpp` into
`rs2_core_tests`, call `rs2fix::testcases::RunPeReaderTests()` from its main,
and add dependencies on both import fixtures. Restore:

```text
pe_bootstrap_contract
pe_companion_contract
```

with these exact registrations:

```cmake
add_test(NAME pe_bootstrap_contract
  COMMAND rs2_pe_contract
    --kind bootstrap
    --file $<TARGET_FILE:rs2_x3audio_bootstrap>)
add_test(NAME pe_companion_contract
  COMMAND rs2_pe_contract
    --kind companion
    --file $<TARGET_FILE:rs2_server_fix_companion>)
```

Pass the PE tool's absolute target path to `rs2_core_tests`:

```cmake
target_compile_definitions(rs2_core_tests PRIVATE
  RS2_PE_CONTRACT_PATH=L\"$<TARGET_FILE:rs2_pe_contract>\")
add_dependencies(rs2_core_tests rs2_pe_contract)
```

In `RunPeReaderTests`, launch that path once with sole `--help` and once with
`--help --file <absolute-nonexistent-sentinel>`; require exit 0/2 respectively,
require the first output to list every option/value, and prove neither
invocation opens or creates the sentinel. This stays inside the existing `core`
role.

Run and commit:

```powershell
cmake --build build-plan --config Debug --target rs2_core_tests `
  rs2_pe_contract rs2_x3audio_bootstrap rs2_server_fix_companion
ctest --test-dir build-plan -C Debug `
  -R '^(core|pe_bootstrap_contract|pe_companion_contract)$' `
  --output-on-failure
& 'build-plan\Debug\rs2_pe_contract.exe' `
  --kind bootstrap --file `
  (Resolve-Path 'build-plan\Debug\X3DAudio1_7.dll')
& 'build-plan\Debug\rs2_pe_contract.exe' `
  --kind companion --file `
  (Resolve-Path 'build-plan\Debug\RS2ServerFix.dll')
git diff --check
git add -- CMakeLists.txt tools tests
git commit -m "feat: enforce x3audio PE contracts"
```

---
### Task 8: Build the Legacy-ABI Functional Harness and Digest

**Files:**

- Create: `tests/static_import_harness.cpp`
- Modify: `src/companion/sha256.h`
- Modify: `src/companion/sha256.cpp`
- Modify: `tools/pe_contract_lib.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**

- Produces: a real normal import of the legacy initializer, one deterministic
  functional vector/digest, exact module-set proof, concurrent/failure/exit
  modes, and the restored `pe_harness_contract` role.
- Consumes: Task 7's explicit by-name test import library and PE contract code;
  it never links the production bootstrap target's ordinal import library.

- [ ] **Step 1: Isolate the newer SDK declarations from the legacy import**

Before including the SDK header, rename only its function identifiers:

```cpp
#define X3DAudioInitialize X3DAudioInitialize_SdkDeclarationOnly
#define X3DAudioCalculate X3DAudioCalculate_SdkDeclarationOnly
#include <x3daudio.h>
#undef X3DAudioCalculate
#undef X3DAudioInitialize

extern "C" __declspec(dllimport) void WINAPI X3DAudioInitialize(
    UINT32 speakerChannelMask,
    FLOAT speedOfSound,
    BYTE* instance20Bytes);
volatile auto g_x3audioInitializeImportAnchor = &X3DAudioInitialize;
```

Compile-time checks are exact for the installed AMD64 SDK layout:

```cpp
static_assert(X3DAUDIO_HANDLE_BYTESIZE == 20);
static_assert(sizeof(X3DAUDIO_LISTENER) == 56);
static_assert(offsetof(X3DAUDIO_LISTENER, pCone) == 48);
static_assert(sizeof(X3DAUDIO_EMITTER) == 128);
static_assert(offsetof(X3DAUDIO_EMITTER, ChannelCount) == 64);
static_assert(offsetof(X3DAUDIO_EMITTER, pVolumeCurve) == 80);
static_assert(sizeof(X3DAUDIO_DSP_SETTINGS) == 56);
static_assert(offsetof(X3DAUDIO_DSP_SETTINGS, SrcChannelCount) == 16);
static_assert(offsetof(
    X3DAUDIO_DSP_SETTINGS, EmitterToListenerDistance) == 44);
```

A mismatch is a hard compile failure, not a skipped test.

- [ ] **Step 2: Implement one fully initialized fixed vector**

Zero the 20-byte handle, listener, emitter, DSP settings, matrix, delay array,
and every padding byte. Then set:

```cpp
listener.OrientFront = {0.0f, 0.0f, 1.0f};
listener.OrientTop   = {0.0f, 1.0f, 0.0f};
listener.Position    = {0.0f, 0.0f, 0.0f};

emitter.OrientFront = {0.0f, 0.0f, 1.0f};
emitter.OrientTop   = {0.0f, 1.0f, 0.0f};
emitter.Position    = {0.0f, 0.0f, 1.0f};
emitter.ChannelCount = 1;
emitter.CurveDistanceScaler = 1.0f;
emitter.DopplerScaler = 1.0f;

settings.pMatrixCoefficients = matrix; // FLOAT[2]
settings.pDelayTimes = delays;         // FLOAT[2]
settings.SrcChannelCount = 1;
settings.DstChannelCount = 2;

constexpr UINT32 kFlags =
    X3DAUDIO_CALCULATE_MATRIX |
    X3DAUDIO_CALCULATE_DELAY |
    X3DAUDIO_CALCULATE_LPF_DIRECT |
    X3DAUDIO_CALCULATE_LPF_REVERB |
    X3DAUDIO_CALCULATE_REVERB |
    X3DAUDIO_CALCULATE_DOPPLER |
    X3DAUDIO_CALCULATE_EMITTER_ANGLE;
```

Call the statically imported initializer with `SPEAKER_STEREO` and
`X3DAUDIO_SPEED_OF_SOUND`. Enumerate modules, select the exact expected local or
System32 X3Audio handle by full path and `FileIdentity`, resolve
`X3DAudioCalculate` from that handle, and call it once.

- [ ] **Step 3: Hash only defined output bytes**

Add `HashBytesSha256(const void*, std::size_t, Sha256Digest*)` using the same
CNG provider discipline as file hashing. Construct a 68-byte canonical buffer
in this order:

```text
20 handle bytes
LPFDirectCoefficient
LPFReverbCoefficient
ReverbLevel
DopplerFactor
EmitterToListenerAngle
EmitterToListenerDistance
EmitterVelocityComponent
ListenerVelocityComponent
matrix[0], matrix[1]
delay[0], delay[1]
```

Copy each float's four IEEE-754 bytes with `memcpy`; AMD64 little-endian is part
of this Windows-only harness contract. Hash no pointer, count field, unused
array element, or structure padding. Print exactly one uppercase line
`digest_sha256=<64 hex>` after success.

- [ ] **Step 4: Prove the complete X3Audio module set**

Use a complete current-process Tool Help module snapshot and full paths. With
`--expect-modules system-only`, require exactly one X3Audio basename whose
identity equals the constructed System32 path. With
`--expect-modules proxy-and-system`, require exactly two distinct identities:
the executable-directory proxy and System32 genuine. Reject pathless entries,
duplicate identities, extra X3Audio basenames, or basename-only matching.

After the vector, validate either a terminal schema-2 marker for the current PID
or continuous absence for the bounded no-marker interval. The complete marker
must contain both beside flags, system32 genuine, both genuine export booleans,
initializer result 0, and terminal completion.

- [ ] **Step 5: Add bounded harness modes**

The complete grammar is:

```text
rs2_static_import_harness
  --mode <vector|concurrent|fail-initialize|fail-calculate|immediate-exit>
  [--expect-modules <system-only|proxy-and-system>
   --expect-marker <absent|complete>]
```

`vector` and `concurrent` require exactly one `--expect-modules` and one
`--expect-marker`; every failure/immediate-exit mode forbids both. Every option
occurs at most once and unknown, duplicate, missing, quoted, or mode-incompatible
values return usage error 2 before a mode action. Sole `--help` prints the
complete grammar and returns 0; any combination with `--help` returns 2 without
running a vector or touching a marker.

`concurrent` creates 16 test threads behind one event; each owns separate zeroed
vector data, runs initialize then calculate, and all 16 digests must equal before
one digest is printed. Waits in harness test code are allowed and bounded to 20
seconds; they are not bootstrap synchronization.

`fail-initialize` calls the imported initializer once. `fail-calculate` finds
the exact local proxy and invokes its Calculate export once with zeroed opaque
buffers; both modes are used only with the missing-genuine test proxy and are
expected not to return. `immediate-exit` calls `ExitProcess(0)` as the first
mode action after argument validation. Disable critical-error UI for every
mode.

- [ ] **Step 6: Link the by-name test library and enforce the harness PE**

```cmake
target_link_libraries(rs2_static_import_harness PRIVATE
  "${RS2_X3DAUDIO_NAMED_IMPORT_LIBRARY}" bcrypt)
add_dependencies(rs2_static_import_harness
  rs2_x3audio_named_import_library
  rs2_server_fix_companion)
add_test(NAME pe_harness_contract
  COMMAND rs2_pe_contract
    --kind harness
    --file $<TARGET_FILE:rs2_static_import_harness>)
```

Do not search an SDK import library and do not link
`rs2_x3audio_bootstrap`. Run:

```powershell
cmake --build build-plan --config Debug --target rs2_static_import_harness `
  rs2_pe_contract
ctest --test-dir build-plan -C Debug -R '^pe_harness_contract$' `
  --output-on-failure
& 'build-plan\Debug\rs2_static_import_harness.exe' --help
& 'build-plan\Debug\rs2_pe_contract.exe' `
  --kind harness --file `
  (Resolve-Path 'build-plan\Debug\rs2_static_import_harness.exe')
git diff --check
git add -- CMakeLists.txt src/companion/sha256.* `
  tests/static_import_harness.cpp tools/pe_contract_lib.cpp
git commit -m "test: add legacy x3audio functional harness"
```

---
### Task 9: Implement the Qualified Fresh-Process Functional Matrix

**Files:**

- Create: `tools/tool_paths.h`
- Create: `tools/tool_paths.cpp`
- Create: `tests/static_import_runner.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**

- Produces: strict absolute-path helpers, captured child stdout, qualified host
  gate, nine functional cases, exact digest/status-line comparison, and rollback
  proof.
- Consumes: Tasks 2, 6-8 manifest, evidence, DLL, and harness outputs.

- [ ] **Step 1: Add strict tool-only path primitives and tests**

Expose helpers that normalize with `GetFullPathNameW` but reject an input that
was not already absolute, any quote, reparse-point file/directory, wrong object
type, missing input, existing create-new output, or path containment violation:

```cpp
bool RequireAbsolutePlainFile(
    const wchar_t* input, std::wstring* normalized, std::string* error);
bool RequireAbsolutePlainDirectory(
    const wchar_t* input, std::wstring* normalized, std::string* error);
bool RequireAbsoluteNewFileOutsideRoot(
    const wchar_t* input, const std::wstring& forbiddenRoot,
    std::wstring* normalized, std::string* error);
bool IsPathWithin(
    const std::wstring& root,
    const std::wstring& candidate,
    bool allowRoot) noexcept;
```

Add positive/negative temporary-root assertions to `RunManifestTests`. These
helpers are for test/evidence tools only and are never linked into either DLL.

- [ ] **Step 2: Replace positional runner arguments with an exact normal mode**

Normal mode accepts every option exactly once and no extras:

```text
rs2_static_import_runner
  --harness <absolute existing plain file>
  --bootstrap <absolute existing plain file>
  --missing-genuine-bootstrap <absolute existing plain file>
  --companion <absolute existing plain file>
  --genuine-manifest <absolute existing plain file>
```

The parser rejects relative, duplicate, unknown, missing, or quoted values and
never searches the current/executable directory. Sole `--help` prints this
complete normal-mode grammar and exits 0 before path, file, process, or marker
work; combining it with any other token returns usage error 2. Task 10 extends
the same help text when it adds the two disjoint modes.

Before creating a case root:

1. construct the System32 X3Audio path in a 512-character buffer;
2. read the strict manifest and System32 `FileEvidence`;
3. find an exact `qualified` hash;
4. compare size, AMD64, timestamp, image size, both fixed-version quads, exactly
   Calculate @1 and Initialize @2, and embedded WinTrust success;
5. check bootstrap and companion PE contracts; and
6. check the missing-genuine DLL has the bootstrap contract, lives under the
   exact `test-invalid-genuine/Debug` or `test-invalid-genuine/Release`
   directory matching the currently executed configuration, and has a hash
   different from the production bootstrap.

Any mismatch is a named test failure, not a skip or child loader error.

- [ ] **Step 3: Capture child output and exact termination**

Extend `ProcessResult` with a bounded one-MiB stdout/stderr string. For each
child create an inheritable output file inside that case directory, redirect
both handles, wait at most 20 seconds, terminate only to clean up a timeout, read
the file after handle closure, and include output in failure evidence. Reject
truncation. Preserve raw bytes so CRLF and exact success-console bytes can be
validated independently from the digest line.

Healthy children must be created, not time out, and exit 0. Missing-genuine
children must be created, not time out, and exit exactly `0xC0000602`.
Invalid-bootstrap succeeds only through the documented loader create errors or
a non-timeout loader exit with the high bit set.

- [ ] **Step 4: Run the nine cases in fresh validated directories**

Use one unique root directly beneath the system temporary directory with leaf
`RS2ServerFix.static.<pid>.<tick>`. Refuse cleanup unless the normalized root is
a one-component child with that prefix and every descendant remains within it.

Run in this exact order:

```text
01-system-control:
  harness only; run --mode vector --expect-modules system-only
  --expect-marker absent; save reference digest

02-companion-only:
  harness + RS2ServerFix.dll; run --mode vector
  --expect-modules system-only --expect-marker absent;
  require digest == reference

03-bootstrap-only:
  harness + production X3DAudio1_7.dll; run --mode vector
  --expect-modules proxy-and-system --expect-marker absent;
  require digest == reference

04-both:
  harness + production proxy + companion; run --mode vector
  --expect-modules proxy-and-system --expect-marker complete;
  require digest == reference; require exactly one exact status line
  (the single-line literal defined immediately below this matrix)

05-invalid-companion:
  harness + production proxy + malformed RS2ServerFix.dll;
  run --mode vector --expect-modules proxy-and-system
  --expect-marker absent; require digest == reference

06-missing-genuine:
  harness + isolated missing-genuine file named X3DAudio1_7.dll;
  run one child with --mode fail-initialize and one with
  --mode fail-calculate; no expectation options;
  both exact exit 0xC0000602; no complete marker

07-concurrent-first-calls:
  harness + production proxy + companion; run --mode concurrent
  --expect-modules proxy-and-system --expect-marker complete;
  require digest == reference; require exactly the same one status line

08-invalid-bootstrap:
  harness + malformed X3DAudio1_7.dll; attempt --mode vector
  --expect-modules proxy-and-system --expect-marker absent;
  require documented loader rejection before a successful vector

09-rollback:
  reuse stopped 04 directory after deleting only its captured PID marker,
  proxy, and companion; run --mode vector --expect-modules system-only
  --expect-marker absent;
  require digest == reference
```

The exact case-04/case-07 status-line bytes, including terminal CRLF, are:

```text
[RS2ServerFix] v0.1.0.0 loaded; host=unknown; X3Audio=System32; mode=passive; marker=complete\r\n
```

Before case 01, resolve the runner's own executable path and use the same child
capture helper to verify runner `--help`/`--help --harness
<absolute-nonexistent-sentinel>` exit 0/2 and harness `--help`/`--help
--expect-marker complete` exit 0/2. Require both valid help outputs to enumerate
their complete current grammar, prove the sentinel and current-PID marker remain
absent, and require that no case root or ordinary output capture exists before
the runner then creates its normal matrix root. These checks remain part of
`static_import_cases`, not new CTest roles.

Do not infer fidelity from process success: parse exactly one
`digest_sha256=` line from every functional child, reject duplicates/malformed
hashes, and compare bytes to the control digest. Capture each child PID and
delete only its named marker during cleanup. Parse success-console lines by
exact raw CRLF-delimited bytes and independently of digest order. Cases 04 and
07 require exactly one line with `host=unknown`, because the harness executable
is not a preserved VNGame identity. Cases 01-03, 05-06, 08, and 09 require zero
lines beginning `[RS2ServerFix]`; any duplicate, malformed, wrong-version,
wrong-identity, or partial line fails the matrix.

- [ ] **Step 5: Register the normal matrix with explicit target paths**

```cmake
add_test(NAME static_import_cases
  COMMAND rs2_static_import_runner
    --harness $<TARGET_FILE:rs2_static_import_harness>
    --bootstrap $<TARGET_FILE:rs2_x3audio_bootstrap>
    --missing-genuine-bootstrap
      $<TARGET_FILE:rs2_x3audio_missing_genuine_bootstrap>
    --companion $<TARGET_FILE:rs2_server_fix_companion>
    --genuine-manifest
      ${CMAKE_CURRENT_SOURCE_DIR}/config/qualified_x3audio_genuine.manifest)
set_tests_properties(static_import_cases PROPERTIES TIMEOUT 300)
```

The 300-second role timeout covers the ten functional children, four help
children, and Task 10's qualification submatrix while preserving each child's
stricter 20-second bound. Add dependencies on all four artifacts. Run twice in
Debug:

```powershell
cmake --build build-plan --config Debug --target rs2_static_import_runner
1..2 | ForEach-Object {
  ctest --test-dir build-plan -C Debug -R '^static_import_cases$' `
    --output-on-failure
  if ($LASTEXITCODE -ne 0) { throw "static matrix iteration $_ failed" }
}
git diff --check
git add -- CMakeLists.txt tools/tool_paths.* tests/static_import_runner.cpp
git commit -m "test: prove x3audio fresh-process behavior"
```

---
### Task 10: Add Qualification Evidence and the Early-Exit Race Test

**Files:**

- Modify: `tests/static_import_runner.cpp`
- Modify: `tests/manifest_tests.cpp`
- Create: `tools/qualification_runner.h`
- Create: `tools/qualification_runner.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**

- Produces: an explicit provisional-only System32 qualification mode and a
  separate 128-child immediate-exit CTest role.
- Consumes: strict manifest/evidence writer, FileEvidence/WinTrust, and harness
  modes.

- [ ] **Step 1: Add a disjoint qualification command grammar**

The runner accepts this second mode only:

```text
rs2_static_import_runner
  --qualify-system32 <64 uppercase hex>
  --harness <absolute existing plain file>
  --genuine-manifest <absolute existing plain file>
  --qualification-output <absolute non-existing plain-file path>
```

Reject every production DLL argument in qualification mode. Require the output
leaf to equal
`<requested-uppercase-sha256>.qualification.evidence` and its parent to be an
existing plain non-reparse directory. Refuse overwrite.

- [ ] **Step 2: Implement the non-circular provisional flow**

Expose the orchestration without weakening the CLI:

```cpp
struct QualificationInputs {
    Sha256Digest requestedSha256{};
    std::wstring harnessPath;
    std::wstring manifestPath;
    std::wstring outputPath;
};
int RunQualificationMode(
    const QualificationInputs& inputs,
    const WinTrustOps& trustOps,
    const EvidenceFileOps& fileOps,
    std::string* diagnostic);
```

Read the manifest, require exactly one entry with the requested digest in
`Provisional` state, and require the current System32 file to match every
recorded identity field. Run embedded WinTrust and require `ERROR_SUCCESS`.
Run only a fresh harness `vector` child with System32-only/no-marker
expectations; capture exit 0 and its one digest.

Only after all checks pass, format and create the 17-key qualification record
from Task 2. On any parse, identity, signature, ABI, child, digest, path, write,
flush, or close failure, return nonzero and leave no output file. This mode
prints `qualification=pass` but never `static_import_cases=pass` and never
loads/copies the proxy or companion.

The runner never edits or promotes the manifest. A future candidate still
requires: reviewed ABI evidence plus a provisional commit, this runner's
sanitized evidence, maintainer review, and a separate commit changing only that
entry to `qualified`. Catalogue-only signatures remain ineligible.

- [ ] **Step 3: Host qualification tests inside `static_import_cases`**

The normal-mode `rs2_static_import_runner` is the qualification-test host, so no
new executable or CTest role is introduced. After the nine normal cases and
before printing their terminal pass, obtain the runner's own absolute path with
`GetModuleFileNameW(nullptr, ...)`, reuse the already validated absolute harness
and manifest paths, and run this qualification submatrix under a distinct
validated child of the same temporary root.

Derive a provisional manifest by changing only the canonical seed state from
`qualified` to `provisional` while preserving strict CRLF. Spawn the runner's
own absolute path with the exact qualification grammar, the real harness, that
provisional manifest, and a non-existing correctly named output. Read the
emitted evidence, parse it back, and assert all fixed fields, candidate identity,
manifest hash, exit status, and control digest. Delete only that output and
validated subroot after all assertions.

Negative child invocations of that same absolute runner independently use a
qualified record, wrong requested hash, pre-existing output, wrong output leaf,
relative path, and a plain executable that returns nonzero in place of the
harness. Each must return nonzero without a new evidence file.
The extracted `RunQualificationMode(QualificationInputs, WinTrustOps,
EvidenceFileOps)`
in-process seam injects WinTrust failure, short/zero write, flush failure, and
close failure. Every case must leave no newly created evidence file; no test
modifies System32 or a trust store. These assertions execute whenever the
existing `static_import_cases` CTest role runs.

- [ ] **Step 4: Add a separate fixed early-exit mode**

A third disjoint runner mode is:

```text
rs2_static_import_runner
  --early-exit-count 128
  --harness <absolute existing plain file>
  --bootstrap <absolute existing plain file>
  --companion <absolute existing plain file>
  --genuine-manifest <absolute existing plain file>
```

Accept count exactly 128; no other value is a supported test contract. Perform
the same qualified System32 and artifact-contract gate as normal mode. For each
iteration create a fresh validated case directory, copy the harness/proxy/
companion, run harness `immediate-exit` with a five-second child timeout, and
require a created process, no timeout, and exit 0. Forced termination is cleanup
only and fails the case. Capture the PID, remove only its possible marker, and
remove the validated case root.

After this step, sole `--help` prints all three disjoint runner grammars (normal,
qualification, and early-exit), returns 0, and performs no path or process work.
Any other token combined with `--help` returns 2. Update the self-help checks at
the start of normal mode to require all three grammars.

- [ ] **Step 5: Register and exercise `early_exit_cases`**

```cmake
add_test(NAME early_exit_cases
  COMMAND rs2_static_import_runner
    --early-exit-count 128
    --harness $<TARGET_FILE:rs2_static_import_harness>
    --bootstrap $<TARGET_FILE:rs2_x3audio_bootstrap>
    --companion $<TARGET_FILE:rs2_server_fix_companion>
    --genuine-manifest
      ${CMAKE_CURRENT_SOURCE_DIR}/config/qualified_x3audio_genuine.manifest)
set_tests_properties(early_exit_cases PROPERTIES TIMEOUT 300)
```

Run and commit:

```powershell
cmake --build build-plan --config Debug --target rs2_static_import_runner
ctest --test-dir build-plan -C Debug -R '^early_exit_cases$' `
  --output-on-failure
ctest --test-dir build-plan -C Debug `
  -R '^(core|static_import_cases|early_exit_cases)$' --output-on-failure
git diff --check
git add -- CMakeLists.txt tests/static_import_runner.cpp `
  tests/manifest_tests.cpp tools/qualification_runner.*
git commit -m "test: add x3audio qualification and early-exit cases"
```

---
### Task 11: Replace Preflight with a Custody-Safe Stopped-Tree Gate

**Files:**

- Create: `tools/deployment_preflight.cpp`
- Create: `tools/deployment_preflight.h`
- Create: `tests/preflight_fixture_test.cpp`
- Modify: `tools/pe_contract_lib.h`
- Modify: `tools/pe_contract_lib.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**

- Produces: strict preflight CLI, complete stopped-tree scan, current-build
  selection, genuine/artifact/identity/trust gates, KnownDLL evidence, and one
  sanitized create-new report.
- Consumes: Task 2 manifest, Task 7 evidence/contracts, Task 9 path helpers, and
  reviewed artifact hashes supplied by the operator.

- [ ] **Step 1: Fix the complete preflight command contract**

Accept each option once, reject unknown/duplicate/missing options, and require:

```text
rs2_deployment_preflight
  --target-root <absolute existing plain directory>
  --bootstrap <absolute existing plain file>
  --bootstrap-sha256 <64 uppercase hex>
  --companion <absolute existing plain file>
  --companion-sha256 <64 uppercase hex>
  --genuine-manifest <absolute existing plain file>
  --report <absolute non-existing path outside target root>
  --av-edr-disposition <state>
  --wdac-disposition <state>
  --applocker-disposition <state>
  --eac-disposition <state>
```

Each operator-recorded state is exactly one of `not-observed-yet`,
`not-installed`, `not-enforced`, `allowed`, `alerted`, or `blocked`.
The report labels them `operator_recorded_*`. Alerted/blocked is unsafe;
not-observed-yet is permitted only as a pre-run observation and the manual
procedure requires a later runtime result. Free text is never accepted.

Require bootstrap, companion, manifest, report parent, and the running
preflight tool itself to be outside the target tree. Proposed hash arguments
must match the files. Never copy an artifact.

Sole `--help` prints the complete grammar above and returns 0 before resolving a
path, opening a file/process/registry key, or creating a report. Any token
combined with `--help` returns usage error 2 and likewise performs no evidence
action.

- [ ] **Step 2: Write the report grammar and failure ownership**

Build the report in memory, sanitize relative path components by percent-
encoding every UTF-8 byte outside `[A-Za-z0-9._/-]`, replace no content
silently, and write once with create-new/complete-write/flush/close semantics.
It contains CRLF records in this order:

```text
schema=1
mode=stopped-tree-preflight
tool_sha256=...
manifest_sha256=...
bootstrap_leaf=X3DAudio1_7.dll
bootstrap_sha256=...
companion_leaf=RS2ServerFix.dll
companion_sha256=...
genuine_sha256=...
target_build_identity=...
target_executable=<TARGET_ROOT>/<encoded relative path>
operator_recorded_av_edr=...
operator_recorded_wdac=...
operator_recorded_applocker=...
operator_recorded_eac=...
known_dll_x3audio=absent|present|query-failed
event_count=N
event.0=kind|relative-path|machine|detail
...
pe_file_count=N
x3audio_importer_count=N
unsafe_count=N
result=pass|unsafe
```

The terminal result is always last. Findings contain no command line,
environment, account, network address, token, configuration contents, or
absolute target path. A completed unsafe scan still writes `result=unsafe` and
returns 1. Usage/path failures before a trustworthy scan return 2 and do not
create a report. A partial report is deleted.

- [ ] **Step 3: Implement complete deterministic tree traversal**

Traverse the normalized root without following reparse points. Sort each
directory's entries case-insensitively before processing so reports are stable.
Any directory reparse point, PE-file reparse point, enumeration failure,
path escape, unreadable PE-like file, malformed PE, or file identity change
between pre/post parse is unsafe; no entry is silently skipped.

Bound traversal to 128 directory levels, 65,536 filesystem entries, 65,536 PE
files, 262,144 report events, and a 64-MiB in-memory report. Reaching a bound is
`scan-incomplete` and unsafe, never a truncated pass.

For every `.exe` and `.dll`, parse normal and delay imports. Emit the kind,
encoded relative path, machine, and every X3Audio symbol with its import kind.
Reject:

```text
any leaf faultrep.dll
any *.exe.local redirection directory/file
any pre-existing local X3DAudio1_7.dll
any unapproved proxy basename
any X3Audio importer outside AMD64
any X3Audio symbol except names Calculate/Initialize or ordinals 1/2
any empty, partial, or malformed import table
more or fewer than one X3Audio importer
```

Hash executable candidates and require exactly one current build:
`F4E38510832D1FAADA8AAD3B88CD2255B3EA49267EF0E874468E23BDE4EDFCC3`
or
`0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393`.
That selected file must be AMD64 PE32+, have TLS RVA/size zero, and have exactly
one X3Audio module in normal imports containing named `X3DAudioInitialize` as
its only X3Audio symbol. It must have no X3Audio delay import and must be the
sole tree importer.

- [ ] **Step 4: Gate proposed artifacts and genuine System32 evidence**

Run reusable PE contracts over both proposed DLLs and compare their calculated
hashes to the two required CLI hashes. Construct the 512-character System32
path and require:

```text
qualified manifest hash match
bootstrap/companion leaves exactly X3DAudio1_7.dll/RS2ServerFix.dll
file size match
AMD64
COFF timestamp match
SizeOfImage match
both VS_FIXEDFILEINFO quads match
exact named exports Calculate @1 and Initialize @2
embedded WinVerifyTrust ERROR_SUCCESS
configured path fits and actual file identity is unchanged during inspection
```

Read the 64-bit
`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`
view with bounded value enumeration. A query failure or any value/data naming
`X3DAudio1_7.dll` is unsafe; otherwise record `absent`. Do not modify registry
state and do not infer absence from a single expected value name.

Keep OS-state injection explicit and local to the reusable preflight function:

```cpp
enum class KnownDllState { Absent, Present, QueryFailed };
enum class SecurityDisposition {
    NotObservedYet,
    NotInstalled,
    NotEnforced,
    Allowed,
    Alerted,
    Blocked,
};
struct PreflightInputs {
    std::wstring targetRoot;
    std::wstring bootstrapPath;
    Sha256Digest bootstrapSha256{};
    std::wstring companionPath;
    Sha256Digest companionSha256{};
    std::wstring genuineManifestPath;
    std::wstring reportPath;
    SecurityDisposition avEdr{};
    SecurityDisposition wdac{};
    SecurityDisposition appLocker{};
    SecurityDisposition eac{};
};
struct PreflightOps {
    void* context{};
    bool (*queryFileIdentity)(
        void*, const wchar_t*, FileIdentity*, DWORD*) noexcept{};
    EmbeddedSignatureResult (*verifySignature)(
        void*, const wchar_t*) noexcept{};
    KnownDllState (*queryKnownDllState)(
        void*, const wchar_t*, DWORD*) noexcept{};
    EvidenceFileOps reportFileOps{};
};
const PreflightOps& ProductionPreflightOps() noexcept;
int RunDeploymentPreflight(
    const PreflightInputs& inputs,
    const PreflightOps& ops,
    std::string* diagnostic);
```

`PreflightInputs` is populated only after strict CLI parsing and path
normalization. Production adapters call the Task 2/7 primitives; tests replace
only the four listed boundaries.

- [ ] **Step 5: Build an exhaustive preflight fixture matrix**

Before creating a target root, the fixture invokes the absolute preflight path
with sole `--help` and with `--help --report <sentinel>`; require exit 0/2,
complete option/state output from the first, and no sentinel file. This help
contract remains inside `preflight_fixture` rather than adding a CTest role.

The positive CLI fixture creates an empty non-reparse target root, copies only
the current stock executable as `VNGame-current-stock.exe`, keeps proposed
DLLs/manifest/tool/report outside it, supplies their exact hashes and
`not-observed-yet` security states, and requires a terminal passing report with
one importer.

Each negative fixture starts from a new positive root and changes one fact:

```text
relative or duplicate CLI path
report inside root or already exists
wrong bootstrap or companion hash
bad bootstrap or companion PE contract
provisional or mismatching genuine manifest
unknown/PR1 target hash
two recognized target executables
patched non-AMD64 target
nonzero or partial TLS directory
renamed/missing/extra VNGame X3Audio import
second normal X3Audio importer
second delay X3Audio importer
unexpected named or ordinal import
malformed PE-like file
file and directory reparse points
faultrep.dll
*.exe.local
pre-existing X3DAudio1_7.dll
operator alerted/blocked state
injected KnownDLL present and query failure
injected WinTrust failure
file identity change during inspection
short report write and flush/close failure
```

Production KnownDLL and WinTrust adapters get one read-only positive integration
assertion. Negative OS-state cases use explicit `PreflightOps` injection in the
in-process test; tests never edit registry, trust stores, System32, or the game
tree.

- [ ] **Step 6: Register `preflight_fixture` and commit**

Pass the preflight executable, current stock executable, two DLLs, and manifest
as explicit absolute CTest arguments:

```cmake
add_test(NAME preflight_fixture
  COMMAND rs2_preflight_fixture_test
    $<TARGET_FILE:rs2_deployment_preflight>
    ${RS2_CURRENT_STOCK_PATH}
    $<TARGET_FILE:rs2_x3audio_bootstrap>
    $<TARGET_FILE:rs2_server_fix_companion>
    ${CMAKE_CURRENT_SOURCE_DIR}/config/qualified_x3audio_genuine.manifest)
set_tests_properties(preflight_fixture PROPERTIES TIMEOUT 180)
```

Run:

```powershell
cmake --build build-plan --config Debug --target rs2_preflight_fixture_test
ctest --test-dir build-plan -C Debug -R '^preflight_fixture$' `
  --output-on-failure
git diff --check
git add -- CMakeLists.txt tools/deployment_preflight.* `
  tools/pe_contract_lib.* tests/preflight_fixture_test.cpp
git commit -m "feat: add custody-safe x3audio deployment preflight"
```

---
### Task 12: Add Stable Runtime Module and Import Inventory

**Files:**

- Create: `tools/runtime_inventory.h`
- Create: `tools/runtime_inventory.cpp`
- Create: `tools/runtime_inventory_main.cpp`
- Create: `tests/runtime_inventory_test.cpp`
- Modify: `tests/core_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**

- Produces: injectable stable-snapshot capture, strict control/proxy validation,
  sanitized module/import report, and the read-only runtime CLI.
- Consumes: Task 7 PE reader/evidence, Task 9 path helpers, Task 11 report
  conventions.

- [ ] **Step 1: Define capture and validation separately**

`tools/runtime_inventory.h` exposes:

```cpp
enum class RuntimeExpectation {
    SystemControl,
    ProxyPass,
};

struct RuntimeModule {
    std::uintptr_t base{};
    std::uint32_t imageSize{};
    std::wstring fullPath;
    FileIdentity fileIdentity{};
    pe::Image image{};
};

struct RuntimeInventory {
    DWORD processId{};
    std::wstring processImagePath;
    std::vector<RuntimeModule> modules;
    std::size_t attempts{};
};

struct RawRuntimeModule {
    std::uintptr_t base{};
    std::uint32_t imageSize{};
    std::wstring fullPath;
};

struct RuntimeInventoryOps {
    void* context{};
    bool (*enumerate)(
        void*, DWORD, std::vector<RawRuntimeModule>*, DWORD*){};
    bool (*processImagePath)(
        void*, DWORD, std::wstring*, DWORD*){};
    bool (*queryFileIdentity)(
        void*, const wchar_t*, FileIdentity*, DWORD*){};
    bool (*readPe)(
        void*, const wchar_t*, pe::Image*, std::string*){};
    EvidenceFileOps reportFileOps{};
};

struct RuntimeValidationInputs {
    DWORD processId{};
    std::wstring targetRoot;
    RuntimeExpectation expectation{};
    Sha256Digest bootstrapSha256{};
    Sha256Digest companionSha256{};
    GenuineManifest genuineManifest;
    Sha256Digest genuineManifestSha256{};
    Sha256Digest toolSha256{};
    std::wstring reportPath;
};

struct RuntimeValidationResult {
    bool passed{};
    std::vector<std::string> findings;
};

bool CaptureStableRuntimeInventory(
    DWORD processId,
    const RuntimeInventoryOps& ops,
    RuntimeInventory* inventory,
    std::string* error);
bool ValidateRuntimeInventory(
    const RuntimeInventory& inventory,
    const RuntimeValidationInputs& inputs,
    RuntimeValidationResult* result);
```

`Capture` owns completeness/stability only. `Validate` owns host, expected module
set, hashes, and sole-importer rules. This lets unit tests inject snapshot
sequences without weakening the production CLI.

- [ ] **Step 2: Implement the exact three-attempt stability algorithm**

Each attempt calls 64-bit
`CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)`,
fully enumerates `MODULEENTRY32W`, and sorts by numeric base. Require for every
entry: nonzero base/size, absolute full path, readable plain backing file, file
identity before parsing, complete normal/delay PE parse, and the same identity
after parsing.

Cap a snapshot at 4,096 modules and its sanitized report at 8 MiB; reaching a
bound is an explicit incomplete hard failure.

Open the target only with `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`
for path/query APIs; request no write, operation, suspend, terminate, debug, or
handle-duplication right. Failure to obtain the read-only view is a hard stop.

A vanished module, changed base/size/path/identity, or `ERROR_BAD_LENGTH`
invalidates that complete attempt and consumes one of the three attempts. A
pathless, unreadable, malformed, reparse-backed, or PE-incomplete module is an
immediate hard failure recorded by sanitized identity; it is not skipped or
adjudicated.

Return success only when attempts N and N+1 are identical in module count and
every sorted base, size, normalized full path, and file identity. After three
non-identical attempts return unstable. Never wait or loop beyond these three
snapshots.

Query the process image path before the first snapshot and again after the
accepted pair; both normalized values must match. Store the PID and path in the
returned inventory so validation never reaches back into a changing process.

- [ ] **Step 3: Enforce control and proxy-pass module sets**

The CLI command is exact:

```text
rs2_runtime_inventory
  --pid <nonzero decimal DWORD>
  --target-root <absolute existing plain directory>
  --expect <system-control|proxy-pass>
  --bootstrap-sha256 <64 uppercase hex>
  --companion-sha256 <64 uppercase hex>
  --genuine-manifest <absolute existing plain file>
  --report <absolute non-existing path outside target root>
```

Sole `--help` prints that complete grammar and returns 0 before opening a
process, taking a snapshot, reading a file, or creating a report. Combining
`--help` with any other token returns usage error 2 with the same no-action
property.

Require the process image to be within target root, equal the stable inventory's
main module, and match one of the two current VNGame hashes. Across every
module's normal and delay imports, require VNGame to be the sole X3Audio
importer with named normal Initialize only.

`system-control` requires exactly one X3Audio basename at the qualified
System32 identity, no local bootstrap hash, and no companion module.
`proxy-pass` requires exactly two distinct X3Audio basenames: one beside VNGame
with the exact bootstrap hash and one qualified System32 genuine; it also
requires one beside-VNGame `RS2ServerFix.dll` with the exact companion hash.
Any extra basename, wrong path/hash/identity, or missing module fails.

After the inventory stabilizes, hash only the process image and the relevant
local bootstrap, companion, and System32 genuine modules. Do not hash every
loaded module during either snapshot; completeness uses path, base, size, file
identity, and parsed imports.

- [ ] **Step 4: Sanitize without weakening the in-memory full-path proof**

Comparison uses full normalized paths in memory. The report renders them as:

```text
<TARGET_ROOT>/<relative path>
<SYSTEM32>/<leaf>
<WINDOWS>/<relative path>
<OTHER>/<leaf>#full_path_sha256=<uppercase UTF-16LE path digest>
```

This preserves a stable full-path discriminator without disclosing arbitrary
account/vendor directory names. For each module record base, image size, file
identity tuple, categorized path, and every normal/delay X3Audio import. Attach
SHA-256 only to the process image and relevant local bootstrap, companion, and
System32 genuine modules. Use the Task 11 create-new CRLF report discipline and
terminal result.

The report states that Tool Help does not enumerate `LOAD_LIBRARY_AS_DATAFILE`
views; those mappings are non-executable and cannot perform a static X3Audio
call. It also repeats that no static inventory can rule out a dynamic
`GetProcAddress` call from another DLL's `DllMain`.

- [ ] **Step 5: Test every stability and validation branch**

Fake sequences cover:

```text
first two complete snapshots identical
first changes, second and third identical
all three different
ERROR_BAD_LENGTH consumes attempts and then succeeds/fails at bound
module vanishes during parse
base, size, path, and identity each change independently
pathless, unreadable, malformed, and reparse-backed module hard failures
normal and delay importer reporting
VNGame sole importer success
second importer failure
control exact module set success/failure
proxy exact local+System32+companion set success/failure
extra X3Audio basename failure
wrong artifact/genuine hash failure
report path/short-write failure
```

A production-adapter integration test loads the absolute System32 X3Audio into
the current test process, performs one bounded module enumeration, and verifies
that the current executable and exact System32 identity appear. It does not
pretend the test executable is VNGame and does not write a deployment report.
Call `rs2fix::testcases::RunRuntimeInventoryTests()` from `core`; do not add an
eighth CTest role.

Give `rs2_core_tests` the runtime tool's absolute target path and dependency:

```cmake
target_compile_definitions(rs2_core_tests PRIVATE
  RS2_RUNTIME_INVENTORY_PATH=L\"$<TARGET_FILE:rs2_runtime_inventory>\")
add_dependencies(rs2_core_tests rs2_runtime_inventory)
```

The runtime tests launch that exact path with sole `--help` and with
`--help --report <absolute-nonexistent-sentinel>`; require exit 0/2, require
complete named-option output from the first, and prove no sentinel report
appears and no target process was opened. These checks run only inside `core`.

- [ ] **Step 6: Build the tool, run core, and commit**

```powershell
cmake --build build-plan --config Debug --target rs2_runtime_inventory `
  rs2_core_tests
ctest --test-dir build-plan -C Debug -R '^core$' --output-on-failure
git diff --check
git add -- CMakeLists.txt tools/runtime_inventory.* `
  tests/runtime_inventory_test.cpp tests/core_tests.cpp
git commit -m "feat: add stable rs2 runtime inventory"
```

Do not invoke `rs2_runtime_inventory` against a server during implementation.

---
### Task 13: Replace the Disposable-Server Procedure Without Running It

**Files:**

- Rewrite: `docs/disposable-server-test.md`

**Interfaces:**

- Produces: the exact user-operated custody, preflight, control, one-line
  console-status, two-file pass, immediate-shutdown, integrity, quarantine, and
  rollback procedure.
- Consumes: reviewed Release hashes and the two evidence executables, but starts
  or changes nothing during implementation.

- [ ] **Step 1: State authority and custody boundaries first**

The document opens with these hard stops:

```text
Disposable/private server only; never a public or production server.
The operator starts/stops the process and places/removes files.
No VNGame, shipped DLL, configuration, or command-line edit.
Only X3DAudio1_7.dll and RS2ServerFix.dll may enter the game directory.
Preflight executable and genuine manifest stay in a new plain evidence
directory outside the game tree.
Runtime inventory is read-only but still requires the operator's PID/approval.
Any unsafe preflight, security alert, service regression, hang, mutation,
or rollback mismatch stops the experiment.
```

Require the operator to record exact source hashes, target path, command line,
security dispositions, evidence-directory path, and control/proxy/rollback
timestamps locally before continuing.

- [ ] **Step 2: Specify the stopped preflight command and report checks**

Give one copy/paste PowerShell invocation using named variables for paths and
reviewed hashes and every Task 11 CLI option. Before invoking it, assert the
server process is absent, target root/evidence root resolve to distinct
non-reparse directories, report does not exist, no local proxy/companion/
faultrep/`.local` file exists, and proposed DLL hashes equal the reviewed
Release hashes.

Require report `result=pass`, one current target, one stopped-tree importer,
KnownDLL absent, genuine qualified/signature success, proposed contracts pass,
and all four operator security states recorded. Preserve the report outside the
target task directory before later cleanup.

- [ ] **Step 3: Define the untouched System32 control**

The operator starts the ordinary server command with neither DLL present,
verifies Steam/EOS/EAC/network/map/WebAdmin/join behavior, and supplies its PID
to `rs2_runtime_inventory --expect system-control`. Require two stable snapshots,
one System32 X3Audio, no local proxy/companion, VNGame sole importer, and a
passing sanitized inventory report. Confirm there is no `[RS2ServerFix]`
success line. Record normal and immediate-post-readiness shutdown bounds, then
stop normally.

- [ ] **Step 4: Define the exact two-file pass**

Only while stopped, the operator copies the two reviewed hashes beside VNGame,
starts the identical command/environment, and requires:

```text
local bootstrap + qualified System32 genuine + companion in stable inventory
one terminal schema-2 marker for that PID
exactly one visible success line whose host identity matches the selected hash
Steam/EOS/EAC/network/map/WebAdmin/join/travel behavior matching control
no AV/EDR, WDAC, AppLocker, or EAC intervention
one bounded agreed idle/play interval
normal shutdown inside the control bound
a separate immediate-post-readiness normal shutdown inside the same bound
```

Use `rs2_runtime_inventory --expect proxy-pass` for both repetitions. Preserve
reports, the exact captured marker paths, and the exact console line. For the
planned current full-dump run the required visible line is:

```text
[RS2ServerFix] v0.1.0.0 loaded; host=current-full-dump; X3Audio=System32; mode=passive; marker=complete
```

For a different selected executable, derive only the `host=` value from its
already verified build identity. Direct standard output may be visible in the
attached console or its redirection; do not promise that the line enters
Unreal's `Launch.log`. Do not force termination and call a forced cleanup a
pass.

- [ ] **Step 5: Define integrity comparison and rollback**

Hash protected executable, shipped root DLL, and configuration files before and
after without publishing configuration content. Exclude only expected runtime
logs and explicitly captured PID marker files from the protected invariant.

While stopped, remove only the two added DLLs and captured task markers.
Preserve reports elsewhere, then remove only the copied preflight executable,
manifest, and named child outputs from the task evidence directory. Restart once
with the ordinary command, require `system-control` inventory and normal
services, confirm no RS2ServerFix success line, then stop normally. Record exact
control/pass/rollback hashes.

If security software quarantines either DLL, do not disable the control or add
an exclusion. Stop, preserve the alert, remove the remaining exact task files,
and prove System32 control again.

- [ ] **Step 6: Preserve residual risks and deferred scope verbatim**

Include the specification's full accepted residual-risk paragraph and state
that Milestone 1 proves no lag fix, thread offload, game hook, EOS/EAC bypass,
allocation change, logging offload, relevancy optimization, or safe Unreal
work on another thread.

- [ ] **Step 7: Review the document without executing commands and commit**

Check every command against the actual CLI `--help` output, but do not supply a
server path or PID and do not copy either DLL.

```powershell
& 'build-plan\Debug\rs2_deployment_preflight.exe' --help
& 'build-plan\Debug\rs2_runtime_inventory.exe' --help
& 'build-plan\Debug\rs2_static_import_runner.exe' --help
rg -n -i "production deployment|disable.*(eac|av|edr)|exclusion" `
  docs/disposable-server-test.md
git diff --check
git add -- docs/disposable-server-test.md
git commit -m "docs: add x3audio disposable-server procedure"
```

Read each search hit in context; only prohibitions are acceptable.

---

### Task 14: Perform Fresh Offline Release Verification and Code Review

**Files:**

- Modify only for independently verified implementation-review findings.
- Record raw build/review ledgers outside the repository.
- Do not create a release, push, package, copy, or deploy.

**Interfaces:**

- Produces: a clean reviewed branch, exact Release hashes, complete seven-role
  test evidence, PE transcripts, and a non-deployment proof.
- Consumes: all preceding tasks.

- [ ] **Step 1: Configure a new Release verification tree**

From the isolated worktree:

```powershell
cmake -S . -B build-verify -G "Visual Studio 18 2026" -A x64 `
  -DRS2_PR1_BASELINE_PATH="D:/Documents/RisingStorm2/VNGame_pr1.exe_old4" `
  -DRS2_CURRENT_STOCK_PATH="D:/Documents/RisingStorm2/Binaries/Server/VNGame_pr3.stock-F4E38510832D1FAA.exe"
cmake --build build-verify --config Release
```

No FaultRep cache variable is supplied or discovered. Confirm the two input
hashes before interpreting tests and confirm both remain byte-identical after.

- [ ] **Step 2: Prove the exact seven CTest roles**

```powershell
ctest --test-dir build-verify -C Release -N
ctest --test-dir build-verify -C Release --output-on-failure
```

The list and passing run contain exactly:

```text
core
pe_bootstrap_contract
pe_companion_contract
pe_harness_contract
static_import_cases
preflight_fixture
early_exit_cases
```

No skip is accepted. A timeout, forced child termination, missing qualified
System32 match, or absent fixture is a failure.

- [ ] **Step 3: Capture built-PE, hash, manifest, and source evidence**

```powershell
$bootstrap = Resolve-Path 'build-verify\Release\X3DAudio1_7.dll'
$companion = Resolve-Path 'build-verify\Release\RS2ServerFix.dll'
Get-FileHash -Algorithm SHA256 -LiteralPath $bootstrap
Get-FileHash -Algorithm SHA256 -LiteralPath $companion
& 'build-verify\Release\rs2_pe_contract.exe' `
  --kind bootstrap --file $bootstrap
& 'build-verify\Release\rs2_pe_contract.exe' `
  --kind companion --file $companion
git ls-files --eol config/qualified_x3audio_genuine.manifest
rg -n -i "ReportFault|BootstrapContextV1|InitializeV1|rs2_faultrep_bootstrap|RS2_SYSTEM_FAULTREP" CMakeLists.txt src tests tools
rg -n -i "faultrep\.dll" CMakeLists.txt src tests tools
rg -n "x3daudio.h" src/bootstrap
rg -n "RS2FIX_VERSION_(QUAD|ASCII|WIDE)" `
  src/shared/version.h src/companion/console_status.cpp `
  src/companion/companion_version.rc src/bootstrap/bootstrap_version.rc
rg -n "OutputDebugString|WriteConsole|UE_LOG|GLog" src
git diff --check
git status --short
```

Required: exact export/ordinal/import/TLS/VERSIONINFO contracts pass; manifest
reports `i/crlf w/crlf`; the first banned-symbol scan and bootstrap-header scan
have no matches. Every `faultrep.dll` hit from the second scan must be an
explicit preflight rejection or negative test, never a target, import, export,
or runtime loader path. The version scan proves both resource scripts and the
console formatter use the shared definitions; the logging-framework scan has no
matches. Direct `GetStdHandle`/`WriteFile` calls exist only in the reviewed
console-status and marker/file adapters. Diff check exits 0.
The only uncommitted paths permitted during this step are ignored
`build-verify` outputs.

- [ ] **Step 4: Prove test-only artifacts cannot be mistaken for release DLLs**

Record the production and missing-genuine hashes and resolved paths. Require the
test DLL to be beneath
`build-verify/test-invalid-genuine/Release/X3DAudio1_7.dll`, to differ in hash,
and to be absent from the production Release directory. Inspect CMake install/
package targets and require none exist.

```powershell
Get-ChildItem -LiteralPath 'build-verify\Release' -File |
  Select-Object Name,Length
Get-ChildItem -LiteralPath 'build-verify\test-invalid-genuine\Release' -File |
  Select-Object Name,Length
cmake --build build-verify --config Release --target help |
  Select-String -Pattern 'install|package'
```

No command copies artifacts outside the worktree build tree or validated system
temporary test roots.

- [ ] **Step 5: Obtain one bounded cross-model implementation review**

After all evidence passes, follow the governing cross-model workflow active for
the implementation session. At this plan's approval checkpoint, that workflow
uses free Devin GLM-5.2 High (`glm-5-2`) in dangerous mode for one bounded
read-only correctness, security, and compatibility review, with Claude Code
only if that model is unavailable. Give it the approved spec, this
implementation plan, implementation diff, test/PE transcripts, known residual
risks, and the no-deployment constraint. Forbid tracked edits, commits,
deployment, server access, and a second reviewer. Do not claim that this target
repository contains its own `AGENTS.md`.

Persist streamed stdout/stderr and final exit status to a timestamped system
temporary ledger, announce it before launch, and inspect it at least once per
minute. Findings must be classified BLOCKING/IMPORTANT/MINOR plus verdict.

- [ ] **Step 6: Resolve only verified material findings and rerun full evidence**

Independently reproduce each blocking/important finding. Add a focused
regression only for a real high-value failure, make the smallest correction,
rerun the full Release build, all seven tests, PE transcripts, EOL/source
scans, and input immutability checks. At most one focused re-review follows.

If a real correction is required, first amend this task's execution checkpoint
with the exact reviewed file paths and reproduction command. Stage only those
literal paths, inspect `git diff --cached`, and commit with
`fix: address x3audio verification findings`; never use `git add -A` for review
corrections. If there is no verified material finding, create no correction
commit.

- [ ] **Step 7: Prove clean non-deployment and stop**

```powershell
git status --short
Get-ChildItem -LiteralPath 'D:\Documents\RisingStorm2\Binaries\Server' `
  -Filter 'X3DAudio1_7.dll' -File -Recurse
Get-ChildItem -LiteralPath 'D:\Documents\RisingStorm2\Binaries\Server' `
  -Filter 'RS2ServerFix.dll' -File -Recurse
```

Expected: clean tracked worktree; no added DLL in the preserved/local server
tree. Do not push or begin disposable runtime validation without a new explicit
user instruction.

---

## Requirement Traceability

| Approved design requirement | Implemented and proved by |
|---|---|
| Zero-EXE-edit local X3Audio architecture and rejected faultrep/V1 path | Tasks 3, 6, 7, 14 |
| Exact legacy void ABI, two exports, and argument/output fidelity | Tasks 4-9 |
| Absolute genuine resolution and exact validation | Tasks 3-5, 7, 9, 11 |
| Async INIT_ONCE, immutable fallback, bounded references, no waits | Task 5; Task 10 early-exit evidence |
| Minimal DllMain and one non-joined worker | Tasks 6, 10, 13 |
| Companion V2, host identity, marker schema 2, privacy/fallback | Tasks 3, 6, 8, 9 |
| Exact one-time success console line, shared version, and nonfatal failure | Tasks 3, 6, 9, 13, 14 |
| Resource retry, validation fail-fast, exact 0xC0000602 | Tasks 4, 5, 9 |
| Strict qualified manifest and non-circular qualification | Tasks 1, 2, 9, 10 |
| Normal and delay import parsing, TLS, PE contracts, VERSIONINFO | Task 7 |
| Qualified System32 functional control and nine-process matrix | Tasks 8-10 |
| Stopped-tree preflight, trust, KnownDLL, artifact hashes, report | Task 11 |
| Stable complete runtime module/import inventory | Task 12 |
| User-operated control/pass/integrity/rollback and quarantine | Task 13 |
| Seven-role Release suite, external code review, no deployment | Task 14 |
| Hooks, performance work, logging offload, EOS/EAC interception deferred | Global Constraints and Task 13 |

## Plan Self-Review Gate

Before sending this plan for external review:

1. Walk every section of the approved specification against the traceability
   table and add a concrete task for any uncovered requirement.
2. Search the plan for incomplete-action language and replace it with exact
   files, interfaces, values, commands, and expected outcomes.
3. Compare every type/function/CLI name at first declaration and every later
   use; one spelling and ownership rule must be used throughout.
4. Verify every code-bearing task has a red/failing observation, minimal
   implementation, passing command, and scoped commit; custody/documentation
   tasks instead have an exact byte/content gate.
5. Verify the final CTest set is exactly seven roles and that no task requires a
   live server, System32 mutation, game-tree write, deployment, or push.
6. Send the complete plan plus approved design to Claude Opus 5 at maximum
   effort with no turn cap. Resolve each supported blocking/important finding,
   record minor follow-ups explicitly, and repeat until Claude returns
   `APPROVE` with no unresolved architectural decision.

Implementation remains prohibited until this reviewed plan is separately
handed off after the current planning goal.
