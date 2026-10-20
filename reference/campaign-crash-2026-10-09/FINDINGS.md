# Production server 2 campaign crash — 9 October 2026

> Archived 9 October 2026 analysis. See the [publication scope](../leech-reference-2026-10-09/FAILURE-CATALOGUE.md).
> Supporting artifacts and further notes cited below remain in the private archive;
> their names are provenance references, not files bundled with this repository.

Read-only investigation. Times are Europe/London (BST, UTC+1), unless marked UTC. No fixes, builds, deployment, configuration changes, live attachment, process control, or database edits were performed.

## Finding

**This is a recurrence of the native ADF analytics chunk-cycle / buffer-overflow failure documented on PR1 in August. It is not the earlier aerial-recon indexing crash.**

The analytics packer followed a corrupt list ending **114 -> 114**, repeatedly processed that chunk, overflowed its descriptor array, overwrote its own raw-data length, and copied beyond its aggregate allocation. The terminal access violation occurred in memcpy because the caller supplied an out-of-bounds destination. Current-build instructions and byte-for-byte reconstruction of captured memory establish this, independently of debugger blame.

The immediate mechanism is confirmed. Within the enumerated nominal writers, the allocator created the self-link when a producer carried a stale owner tail of 114 into a later pool pop that returned 114; cross-thread producer activity racing snapshot/recycling is the best-supported way to reach that invalid ownership. The dump does not preserve the unique earlier interleaving or gameplay trigger. The last bot addition, artillery request, authentication denial and campaign transition are not established causes.

## Code provenance

The failing implementation is **not stock Unreal Engine 3 code**. It is a native backend/diagnostic component statically linked into `VNGame.exe`. UE3's online-subsystem update reaches the component, but the affected producer, fixed pool, snapshot and packer use the separate `ADF_STREAM`, `l3h`, `BackEnd`, `LEECH` and `HYDRA` namespaces and identifiers.

The 2020 PDB records component objects under `D:\PerforceK\leech\build\x64\Retail Client\leech\`, including `leech_facts.obj`, `http_agent.obj`, `BackEnd.Interfaces.obj` and `hydra_faces_wrappers.obj`. Both the 2020 server and the authenticated 2026 server contain `LEECH/HYDRA/DiagnosticDataService/WriteADFPack`, `ADF/SERVICE:ADF_STREAM_TERM` and `rsv-auth.hydrapi.net` strings. This supports a separately built Leech/Hydra backend library integrated into the game executable.

The evidence does not identify the library's author or legal owner. It is reasonable to describe it as RS2-specific backend middleware integrated by the game/publisher, but the PDB does not prove that Tripwire authored its implementation.

References: 22-historical-symbol-map.txt; 23-code-provenance.txt; 12-current-native-disassembly.txt.

## Evidence identity and dates

Original directory: D:\Documents\RisingStorm2\dumps\PR2_CampaignCrash-09-10-26

| Original | Bytes | SHA256 |
|---|---:|---|
| Launch-backup-2026.10.09-10.30.09.log | 101,647,582 | D29CD0D639F142C85FB98F517FFFBE84737065AF0F58D58F4E5433847CD02C77 |
| unreal-v7258-2026.10.05-09.29.05.dmp | 2,831,001,510 | C237F1A61152BE59FA726C129BC334FF4A076761666094561BFC8487FC29CE97 |

Dump header timestamp 1791538192 = **2026-10-09 09:29:52 UTC / 10:29:52 BST**. Captured shared system time is 09:29:52.639392 UTC. Header flags are 0x2 (full process memory), with 34 threads and 102 loaded modules. The dump's own `MiscInfo.ProcessCreateTime` is 1791188945 = **2026-10-05 08:29:05 UTC**, 4 days 1:00:47 before capture.

The filename's 2026.10.05-09.29.05 exactly matches that dump-internal process start and log line 1: **5 October 09:29:05 BST**. EOS boot at log line 25 independently says 2026-10-05T08:29:06.055Z. Thus the filename reflects startup, not a 5 October crash paired with a 9 October log.

Filesystem metadata agrees: dump created 09:29:52.2393012 UTC and last written 09:30:01.5100256 UTC on 9 October. Log last write 09:30:06.2943427 UTC; backup creation 09:30:09.5794506 UTC. The log tail's addresses match the dump stack.

Use WinDbg .time and the raw dump header for capture time. The initial MCP .lastevent printed an analysis-session “debugger time” of 11:42:16; that is not the dump timestamp. Fatal logging occurs approximately 13 seconds after capture, after dump writing. The provided log ends with the failed process; the BAT relaunch is user-reported, not independently logged here.

References: 00-evidence-hashes.txt; 01-debugger-initial.txt; 02-debugger-identity-full.txt; 04-dump-metadata.json; log-findings.md.

## Actual crash build and loaded fixes

The dump names **E:\servertwo\Binaries\Win64\VNGame_pr2.exe**, PID 7284 / 0x1C74. Image base 0x7FF65EA70000; PE timestamp 0x6A8E3C02, checksum 0x016EF965, SizeOfImage 0x1A12000. The instance filename does not establish the build.

The local canonical EXE D:\Documents\RisingStorm2\Binaries\Server\VNGame_pr3.exe hashes to **0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393**. After applying PE base relocations to a comparison buffer, all **15,281,093 executable .text bytes** match the captured EXE except three bytes at RVA **0xB45328**, precisely the deployed recon correction (04 02 36 -> 84 3E 74). The companion's captured immutable status independently records the same host digest. This verifies the crash build; a disk-file hash was not fabricated from a loaded-memory image.

| Loaded custom module | Captured version | Preserved package SHA256 | Executable code comparison |
|---|---|---|---|
| X3DAudio1_7.dll bootstrap | 0.2.0.0 | 292AB4742F9FDDDFF809DECA411251A00E52BC97D551BDB2920A44546976C4F9 | All 75,824 .text bytes match after relocation |
| RS2ServerFix.dll | 0.4.2.0 | DEBC6E5D9252731DFAFCA85FC32F45A8148134BC83777D1EFDC9BE175E2B81FB | All 255,280 .text bytes match after relocation |

Matching package:
D:\Documents\RisingStorm2\.ai\steam-maintenance-2026-09-14\count-admission-implementation-2026-09-23\RS2-CountAdmission-0.4.2.0-20260924-r3\deploy

The genuine System32 X3DAudio1_7.dll 9.28.1886.0 and System32 Faultrep.dll were also loaded. The dirty current repository is later development, not the deployed source. All 17 preserved release source changes pass custody hashes and match published commit 1b61f0b994b6d26f3fcc24b7f2a45ecef9329fa7 after newline normalization.

Captured RS2SteamReport_StatusV2 at companion RVA 0x5C210 has valid magic/schema/size, complete header identity, matching PID/digest and an even owner sequence. It reports repair mode, phase Repairing, builderBound=1, no revoke/loss/stopping flags, 17,260 normal builder attempts and returns, zero native unwinds. Its owner thread ID is 7264, the faulting game/update thread. Its bound task is slot 2, ID 5, holder 0x2B0000 (type 43), builder at DLL RVA 0x25C20. These are captured diagnostic counters, not independent proof of all earlier behavior.

Deployed code modifies recon, selected Steam import cells, a qualified reporting task builder and selected reporting/count fields. It does not patch the ADF packer. The captured 128-slot service table has only slots 1 and 2 occupied; neither slot's builder or callbacks point into the ADF native range `VNGame+0xBA0000..0xBB0000`. Reporting shares native service infrastructure, so indirect interaction is not categorically excluded. No evidence identifies the DLL as the corrupting writer; the same ADF failure was documented in August before these DLLs were deployed.

References: 05-image-code-comparison.json; 11-companion-runtime-state.json; dll-identity/DLL-IDENTITY-FINDINGS.md and its source references.

## Exception and current-build call path

- Exception: **0xC0000005**, write access violation.
- Instruction: **msvcr110!memcpy+0x296**, runtime **0x7FFD1FD1C616**, **mov qword ptr [rcx-8], r10**.
- RCX=0x23B68AD1008; attempted write **0x23B68AD1000**, an unavailable page.
- R14=manager **0x23B6810F050**; RBX=traversal record **0x23B41950110**, current chunk **114**.
- R11=initial copy destination **0x23B68AD0687**; R8=0x1690 remaining after the first alignment byte.
- RSP=0x456E6F7378; exception thread 0x1C60 / 7264.

| Runtime address | Server RVA / preferred address | Meaning |
|---|---|---|
| 0x7FFD1FD1C616 | msvcr110+0x3C616 | Failing store |
| return 0x7FF65F61CCA6 | 0xBACCA6 / 0x140BACCA6 | Copy at 0x140BACCA1, inside packer 0x140BAC7E0 |
| return 0x7FF65F61D5AF | 0xBAD5AF / 0x140BAD5AF | Internal pack call at 0x140BAD5AA |
| return 0x7FF65F61E875 | 0xBAE875 / 0x140BAE875 | Native update |
| return 0x7FF65F615A3D | 0xBA5A3D / 0x140BA5A3D | Native service update into engine tick |

The debugger's enormous AK::Monitor::GetTimeStamp+ offsets are nearest exported-symbol labels, not reliable function names or evidence of an audio fault. File 12 disassembles the hash-matched disk image; file 05 proves its executable bytes match the dump after relocation outside the unrelated three-byte recon operand, including every ADF range used here.

Historical 2020 server EXE SHA256 865D5E92EEBBE5DFDC69F0E8320025627CCB464AD07E3582CFD30F72D0F5A81F, PE timestamp 2020-10-07, supplies PDB-derived labels **ADF_STREAM::MergeChunksEx** at 0x140BA1600 and **ToMergeOrNotToMerge** at 0x140BA2300. Historical entry bytes match its actual EXE; current instructions independently establish the corresponding roles. Historical addresses were not treated as current addresses. No client database was used.

References: 01-debugger-initial.txt; 03-adf-initial-state.txt; 08-current-packer-bn.txt; 09-current-wrapper-bn.txt; 10-current-packer-debugger.txt; 12-current-native-disassembly.txt; 13-historical-server-identity.json; 14-historical-merge-bn.txt; 22-historical-symbol-map.txt.

## Confirmed causal chain

Chunk i begins at manager+8+i*0x8C20. Its allocation tick, state, fact count, raw length and next index are at chunk+0, +8, +0xC, +0xC10 and +0x8C18. The captured list is:

127 -> 126 -> 125 -> 124 -> 123 -> 122 -> 121 -> 120 -> 119 -> 118 -> 117 -> 116 -> 115 -> **114 -> 114**

All 14 distinct chunks are snapshotted (state 2). Chunk 114 has **90 facts**, **5,777 raw bytes**, and a self-link. The other 114 slots are marked free; the physical pool head at manager+0x461008 is **-1** and count at manager+0x461010 is **100**. These are also allocator-base `(manager+8)+0x461000/+0x461008` respectively. A healthy pool preserves `reachable-free-list length == stored count`; head -1 means zero reachable while the counter says 100, a hard invariant violation. The stored count is also exactly 14 below the 114 state-derived free slots: those 14 missing increments equal the live-chain size, so the pressure heuristic over-reports 28 used chunks where the state map shows 14. Across all 128 `next` fields, chunk 114 is the only deviation from the initializer pattern `next[i]=i-1`: 127 through 115 are pristine, and 113 through 0 remain the pristine tail ending at -1. Replacing only `114.next=114` with the initialized value 113 would make the traversal cover all 128 chunks and terminate. The pool was therefore inconsistent before the terminal output overflow; destination writes lie above the chunk pool and cannot explain the prior link.

The distinct chain totals only **3,119 facts / 368,867 raw bytes**, comfortably within normal aggregate capacities. Legitimate traffic did not simply exceed a correctly sized buffer.

1. The packer does not reject repeated chunks or enforce descriptor/raw output limits.
2. It completes 1,098 chunk-copy visits, including **1,085 visits to chunk 114**, producing **100,679 descriptors** for a capacity of **32,768**. The faulting copy is visit 1,099 overall and the 1,086th visit to chunk 114.
3. Descriptor index **32,768**, chunk 114 local fact 39, overwrites the raw-length DWORD at manager+0x4C108C with timestamp **888,469**. Previous raw length: 2,275,277.
4. Another **754 copies** of the same payload yield **888,469 + 754*5,777 = 5,244,327**.
5. Raw capacity is **4,194,304**. Next destination raw-base+5,244,327 = **0x23B68AD0687**.
6. Only **2,425 mapped bytes** remain before **0x23B68AD1000**. The next 5,777-byte copy faults there.

Independent replay exactly reproduces the **1,208,148-byte written descriptor region**, all 754 subsequent repeated payload copies, and the final 2,425-byte copied prefix. This directly verifies both overflows. By the fault, **1,052,448 bytes beyond the 4 MiB raw buffer end** had been written; the last written byte is manager+0x9C1FAF, corrupting later manager members from +0x8C1090 through the producer region that includes +0x9C1120. The final 3,727 bytes at +0x9C1121..+0x9C1FAF lie above every manager displacement in the audited ADF disassembly and plausibly fall outside the manager object. No field at or above the descriptor output start +0x46108C is treated as intact pre-crash state. Every pool/link/timer value used in the origin and trigger analysis is below that boundary; the companion status is in a separate module. Chunk 114 contains user_stats_v2 facts; player/account payload details are omitted.

References: 06-adf-memory-proof.json (all 128 slots); 07-adf-overflow-replay.json; adf_proof.py; adf_replay.py. Scripts mmap the original read-only and write only derived notes.

## Terminal trigger versus corruption origin

**Terminal trigger:** the normal packing check selected this invocation. Current wrapper code uses GetTickCount64 and compares elapsed time to 900,000 ms. The saved caller RDI is at packer-frame RSP+0x168; its low byte DIL is **0**, excluding the wrapper's requested/force-dump branch, which sets DIL=1. Return address 0x140BAD5AF proves the internal call at 0x140BAD5AA; the pressure branches are tail jumps and cannot leave that return. The pressure test uses the stored counter and therefore computes 128-100=28 used chunks, below its greater-than-84 threshold, even though head/count are inconsistent. This leaves the timer branch. Last-pack tick 348,427,546 and the later captured tick 349,327,984 give **900,438 ms**; slot 127's allocation tick also equals that last-pack tick exactly. These values corroborate the route but do not serve as the decisive timing proof because capture followed the exception by roughly 400 ms. The packer's own force argument was also zero.

**Origin trace:** the historical PDB names the producer `ADF_STREAM::Fact`, the owner snapshot `SwitchChunkStates`, the pool pop `FIXED_POOL<THREAD_CHUNK,128>::Allocate`, and the packer `MergeChunksEx`. Their corresponding 2026 instructions were verified. Despite the `GetThreadId` name, the producer uses one process-global slot index (2026 RVA 0x14AADA0), not Windows TLS. The dump has index 0 and a one-element owner vector. A real HTTP background thread and the main/update path can both reach `Fact`, so they share the same head/tail pair.

Snapshot clears that pair and changes state-1 chunks to state 2 without a producer lock. Recycling tests and clears state before taking the free-pool lock. Allocation and recycling do share the same physical pool controls, although their displayed displacements differ because allocator `this = manager+8`: allocator lock/head/count `(this+0x461004/+0x461000/+0x461008)` equal recycler/manager `(manager+0x46100C/+0x461008/+0x461010)`. The constructor at 0x140BABB28 passes `manager+8` to the initializer/allocator layout. Allocation pops under that shared lock, releases it, and only then performs all chunk reinitialization: `allocated.next=-1`, zeroed state/count/raw length, allocation tick, and `previous.next=allocated`. It has no `previous == allocated` or membership check. A direct-branch and exact-field writer audit found initialization, allocation and recycling as the nominal link writers; its limits are documented in `current-writer-trace/CURRENT-WRITER-FINDINGS.md`.

The current generation of chunk 114 was allocated at tick 349,309,265. Within the bounded audit, the allocator at 0x140BAC2B9 is the only nominal writer of a nonzero allocation tick; recycling zeroes it at 0x140BACDD8, while the packer and producer read it at 0x140BAC8F2 and 0x140BAC7A0. This tick-field conclusion comes from inspecting those functions, not from the exact-displacement scan used for the link/pool fields. The most recent allocation therefore followed any nominal recycle, reset `114.next=-1`, and then wrote `previous.next=allocated`. The captured `114.next=114` means one producer invocation first read owner tail `previous=114` at 0x140BAC5E2 and later popped `allocated=114` at 0x140BAC25B. Those are two unprotected moments, so this proves stale/invalid ownership across the interval rather than simultaneous membership at one instant. The pop used the then-existing `114.next=-1`, explaining the captured free head -1: no nominal pool write occurred between that pop and capture, because an empty-head allocation fails without changing head/count and the terminal packer faulted before its recycler loop. The rollover path left the pre-existing owner head 127 intact and wrote tail 114. The allocator thereby produced the complete captured self-link/head/tail state.

The dump cannot identify what changed ownership between the producer's tail read and pool pop, or which earlier activity first broke the head/count invariant. Cross-thread producers racing snapshot/recycle are the best-supported defect class; a concrete instruction-valid schedule proves that one producer plus one packer can form a self-link. Duplicate recycling by overlapping/re-entered packing remains a possible older route to the invalid ownership, while the current generation's final self-link is the allocator's `previous==allocated` write. Earlier arbitrary-pointer corruption remains possible because the writer audit cannot exclude non-nominal addressing.

The 2020 PDB-backed build contains the same unsafe design and traversal. Its vulnerable 254-byte loop is identical to 2026 after masking only the relative `memcpy` displacement; the calls are 0x140BA1AC1 and 0x140BACCA1 respectively. This establishes a longstanding native weakness, while not proving that every build experienced the same historical interleaving.

The 438 ms timer excess is measured at capture, not a measured exception-to-dump delay or rigorous game-thread stall bound. Detailed evidence and address mapping are in `ORIGIN-TRACE.md`.

## Log correlation

Line numbers use LF delimiters, matching rg -n. Embedded control characters in names make other counting methods disagree. Full bounded analysis and redacted extracts are alongside this report.

| Time, 9 October | Log reference | Observation |
|---|---|---|
| ~10:13:04 | L1110243, L1110284–1110288 | HueCity result and campaign calculation |
| ~10:14:52.201 | Dump ticks; L1110385–1110387 context | Previous ADF pack during campaign voting |
| 10:16:08 | L1110499 | QuangTri world up |
| ~10:18:03 | L1110973–1111000 | Already-in-progress online start and bot state warnings; gameplay continues |
| ~10:28:22 | L1111378–1111380 | Artillery/barrage request, ~91 s before capture |
| ~10:28:34 | L1111396–1111397 | Single Steam denial; EAC completions follow |
| ~10:29:13.5 | L1111403 | Mutator reports health OK, 29 players, OSS OK, no consecutive timeouts |
| 10:29:29 | L1111404–1111405 | Connection close / EAC unregister |
| ~10:29:36.5 | L1111406–1111407 | Last gameplay log: bot addition |
| **10:29:52.639** | Dump shared system time | Capture with saved access violation |
| ~10:30:05.5–10:30:06.1 | L1111408–1111431 | Fatal reporting, shutdown-after-error, appRequestExit(1) |

This was QuangTri gameplay, ~13m45s after world-up, not immediate map travel. No final-window queue/connection storm, persistent stats/auth timeout, out-of-world artillery failure or OOM message appears. These are bounded observations, not exclusions of every indirect cause.

Logged mutators: IDBanMutator, SeedMutator, TKLMutatorv2 and XPFixesMutator. Startup labels/settings are in log-findings.md; exact bytecode hashes were not supplied. Main-log DLL silence is supplemented by captured module and status evidence.

The match to August PR1 is demonstrated cyclic topology, descriptor overwrite, repeated raw copies, CRT fault site and periodic packing path. It does not assume identical original threads or reuse old-build addresses. The recon correction is present; this mechanism is not its RNG endpoint failure.

## Mitigation feasibility and next step

**A narrow, build-qualified DLL mitigation is feasible in principle. It requires separate approval and offline qualification.** Target ADF traversal/output and its ownership lifecycle, not memcpy or a global exception handler.

A guard should reject invalid/repeated indices and enforce real descriptor/raw bounds before writes, using a stable snapshot or synchronization so validation cannot become stale. Corrupt telemetry needs a proven discard/quarantine and cleanup path. Returning after snapshot detached lists, truncating payloads, or rebuilding a corrupt free list is not yet proven safe. A root guard should reject `previous == allocated`, validate returned-slot state/membership, and reconcile head/count invariants; with head -1 the current allocator fails closed and drops a fact once chunk 114 fills. A complete correction should also give producers real per-thread ownership or serialize `Fact` against snapshot/recycling. Enlarging buffers or swallowing the access violation does not address the mechanism.

**Recommended next step:** prepare an offline ADF guard design for this exact EXE; audit pack/snapshot/recycle entrypoints and cleanup; then qualify synthetic copies of the captured self-cycle and normal/full-capacity/concurrent cases. Present the design for approval before code modifications or deployment.

No additional artifact is needed to establish this mechanism. Matching native companion/bootstrap side logs and any existing earlier dump could help investigate the original corruption; decisive earlier-writer proof likely needs separately approved targeted telemetry or an isolated reproduction. Launch.log proximity cannot supply it.

## Verification and custody

- Originals opened read-only and SHA256 inventoried; the final recheck in 24-final-custody-check.txt confirms the originals and canonical EXE/PDB/IDA database hashes remained unchanged.
- WinDbg/CDB opened the saved dump only; no production attachment.
- Binary Ninja primary: already-open Server/BinaryNinja/VNGame_pr3.exe_Enriched.bndb and Server/.HistoricalWithPDB/BinaryNinja/VNGame.exe_enriched.bndb. Historical analysis was already running when discovered and later became ready. No analysis was requested; no symbols/types/comments/bytes changed; no database save or close. The open current database's file lock blocked a hash attempt; no verified before/after database-hash claim is made.
- IDA MCP initially had zero sessions. For the deeper origin trace, the historical 2020 `.i64`, EXE and PDB were hash-copied to `C:\Users\Mark\AppData\Local\Temp\rs2-campaign-historical-ida-20261009`; only that independent `.i64` copy was opened headlessly and queried read-only. No types, names, comments, bytes or canonical databases were changed. Copy/canonical custody hashes are recorded with the origin-trace evidence.
- PE relocation/code comparison and memory replay are the decisive checks. No runtime mitigation test or claim of server repair.
- Cross-model review status: see REVIEW-RESULT.md.
