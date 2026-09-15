# RS2ServerFix

Targeted crash fixes and diagnostic tools for **Rising Storm 2: Vietnam dedicated servers**.

RS2ServerFix loads alongside the Windows 64-bit server, validates the executable
and startup state, and applies a narrowly scoped correction in memory. It keeps
the existing server launch command and does not rewrite the executable on disk.

This is an independent community project, not an official Tripwire Interactive
release. It is not a general performance patch or a fix for every server crash.

## What is implemented

The current source version is **0.2.0.0**.

- **Recon crash correction** — the `recon-exclusive-scale-v1` fix, guarded by an
  exact executable hash, expected instruction bytes and startup checks.
- **Passive mode** — performs qualification without applying the recon correction.
- **Startup diagnostics** — a console status line and a per-process
  `RS2ServerFix.loader.<PID>.log` marker identifying the build, mode and outcome.
- **Verification tools** — PE/import checks, deployment preflight, runtime module
  inventory and isolated startup/rollback fixtures.

Steam-maintenance investigation and an observation-only Steam interface design
are ongoing work. **The current DLL does not repair Steam browser counts or
provide the planned Steam observer.** It does not bypass authentication or
anti-cheat checks.

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

For a first deployment:

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

Full qualification testing also requires locally supplied, preserved executable
inputs. Set the CMake cache paths `RS2_PR1_BASELINE_PATH`,
`RS2_CURRENT_STOCK_PATH` and `RS2_CURRENT_FULLDUMP_PATH` to the matching evidence
files before building all test targets and running:

```powershell
cmake --build build
ctest --test-dir build -C Release --output-on-failure
```

The suite uses local fixtures and read-only production-byte evidence. Passing it
does not establish gameplay, Steam backend or anti-cheat compatibility on a live
server. See [the retained profile evidence](tests/evidence/README.md) for the
scope of the static checks.

## Reporting problems and contributing

[Open an issue](https://github.com/MadMaxMangos/RS2ServerFix/issues) with the project
version, Windows version, executable SHA-256, passive/active mode and relevant
loader status. Include reproduction steps and whether removing the package
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
