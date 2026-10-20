# ADF corruption-origin trace

> Archived 9 October 2026 analysis. See the [publication scope](../leech-reference-2026-10-09/FAILURE-CATALOGUE.md).
> Supporting artifacts and further notes cited below remain in the private archive;
> their names are provenance references, not files bundled with this repository.

Read-only follow-up to the 9 October 2026 campaign-server crash. Addresses are preferred virtual addresses unless explicitly called RVAs. The historical 2020 PDB supplies names and semantics; every material instruction pattern was checked against the authenticated 2026 executable before being applied to this incident.

## Result

The trace identifies a concrete concurrency defect class in the ADF producer/snapshot design. It does not recover the unique historical instruction interleaving that first made chunk 114 invalid.

The process has a real background HTTP thread and the game/update thread. Both can reach `l3h_fact` / `ADF_STREAM::Fact`. Despite the PDB name `ADF_STREAM::GetThreadId`, the producer uses one process-global integer, not Windows TLS. In 2026 it is RVA `0x14AADA0`; the dump contains value 0 and the associated `THREAD_INFO` vector contains one element. All producers therefore share one head/tail pair.

`SwitchChunkStates` copies that shared head into the packer's traversal vector, clears the head/tail pair with a 64-bit `-1` store, and changes every state-1 chunk to state 2. Those operations are not serialized against `Fact`. The fixed-pool free-list pop/push has a spin lock. Allocator `this` is `manager+8`, so allocator lock/head/count offsets `+0x461004/+0x461000/+0x461008` are the same physical fields as recycler manager offsets `+0x46100C/+0x461008/+0x461010`. The constructor proves the bias by passing `manager+8` at 0x140BABB28-2F. Consequently manager+0x461000 is chunk 127's `next` field (captured value 126), not the pool head; the pool head is manager+0x461008 (captured `-1`). The producer reads the shared tail and later updates it outside the lock; allocation also writes `previous.next = allocated` outside the lock and does not reject `previous == allocated`.

This makes stale-tail, lost-tail and dual-ownership states reachable. A single producer racing one snapshot/recycle is sufficient to create a self-link in an instruction-valid schedule. That minimal schedule leaves the owner head at `-1`, however, and therefore is a proof of the primitive rather than a complete reconstruction of the captured state.

The best-supported origin class is now **cross-thread ADF producer activity racing snapshot/recycling through a shared owner slot**. Overlapping/re-entered packers remain one possible way to create duplicate recycling or active/free dual ownership, but they are no longer the only or most concrete explanation. Earlier unrelated memory corruption remains possible and is not excluded by this bounded writer audit.

## Historical names and current mapping

| Role | 2020 PDB name/address | 2026 verified address |
|---|---|---|
| Fact producer | `ADF_STREAM::Fact` `0x140BA11C0` | `0x140BAC3A0` |
| Fixed-pool allocate | `ADF_STREAM::FIXED_POOL<THREAD_CHUNK,128>::Allocate` `0x140BA1060` | `0x140BAC240` |
| Snapshot owner slots | `ADF_STREAM::SwitchChunkStates` `0x140BA2240` | `0x140BAD420` |
| Pack/merge | `ADF_STREAM::MergeChunksEx` `0x140BA1600` | `0x140BAC7E0` |
| Periodic/pressure decision | `ADF_STREAM::ToMergeOrNotToMerge` `0x140BA2300` | `0x140BAD4E0` |
| Normal update wrapper | `l3h_fact_update` `0x140BA3660` | `0x140BAE840` |
| Explicit flush | `l3h_fact_flush` `0x140BA3320` | `0x140BAE500` |
| Termination flush | `l3h_fact_term` `0x140BA35F0` | `0x140BAE7D0` |

The 254-byte vulnerable traversal block is byte-identical between 2020 and 2026 after masking only two bytes of the relative `memcpy` call displacement. The call is `0x140BA1AC1` in 2020 and `0x140BACCA1` in 2026. Both versions follow `next` without cycle detection and emit descriptors/raw data without aggregate bounds checks.

## Current-build writer enumeration

Whole-`.text` direct-branch searches and instruction-bound scans found the following nominal writers of the chunk `next` field and pool controls:

- initializer `0x140BABA90`;
- allocator `0x140BAC240`, including `previous.next = allocated` at RVA `0xBAC2CD`;
- packer's inlined recycler `0x140BACDD0..0x140BACE34`.

No other exact field-displacement writer was found. This is a bounded result: an arbitrary-pointer overwrite, stale in-flight producer, external module or an already-corrupt descriptor/payload index could write the same memory without using those exact displacements.

The allocation-tick field at `chunk+0` cannot be enumerated by that displacement scan. Separate function inspection found allocator write `0x140BAC2B9`, recycler zero `0x140BACDD8`, packer read/min-reduction `0x140BAC8F2`, and producer read `0x140BAC7A0`; no state-0 slot in the dump has a nonzero tick. References: `12-current-native-disassembly.txt` lines 26, 102 and 398; `current-writer-trace/expanded-functions.txt` line 252.

The nine direct calls/tails to allocator, packer, snapshot and periodic wrapper were also exhaustively found for relative `E8`, `E9` and `EB` encodings. Full details and limits are in `current-writer-trace/CURRENT-WRITER-FINDINGS.md`.

## Confirmed background producer

In 2020, `httpREQUEST_MANAGER::Init` stores `httpREQUEST_MANAGER::UpdateThread` in a heap thunk and starts it with `CreateThread`. The 2026 equivalents are:

- init `0x140C0BDE0..0x140C0BE4C`;
- `CreateThread` call RVA `0xC0BE3C`, 1 MiB stack, flags 0;
- dispatch thunk `0x140C0C380`;
- worker `0x140C0C0F0..0x140C0C1F3`.

The dump captures thread `0xC90` waiting at worker return RVA `0xC0C1AE`, with thunk return `0xC0C39B`, proving this worker existed in the crashing process. Its greater-than-5000-ms iteration diagnostic calls the same producer through `0x140BAE440 -> 0x140BAC3A0`.

Normal HTTP response processing also runs through this worker's virtual `Update`, CURL completion, `OnRequestComplete`, the HTTP agent, and response parsing. The historical PDB shows many response-path `l3h_fact` call sites, including `RawResponse::FromHBP`. The captured ADF data alternates SetData request and response facts, often 234-250 ms apart. That content is consistent with main/backend and response processing sharing the ADF stream, but the dump does not attach a thread ID to each individual fact, so it is not used as per-fact thread proof.

## Minimal corruption primitive

One valid schedule, using one producer and one packer, is:

1. The producer reads a full tail 114 and pauses before allocator call RVA `0xBAC656`.
2. The packer snapshots and clears the owner pair, marks the old chain state 2, then recycles 114 to the free-list head.
3. The producer resumes with stale `previous=114`; the allocator returns 114, clears its `next`, then RVA `0xBAC2CD` writes `114.next=114`.

This proves that the code can create the exact link value without an arbitrary memory overwrite or two simultaneous packers. It is a primitive demonstration, not the unique incident schedule: the tail read and allocator pop are separate unprotected moments, and the dump does not record what changed ownership between them.

Immediately before the terminal snapshot, the captured state was one owner chain with head 127 and tail 114, 14 state-1 chunks, free head `-1` and stored free count 100. Head -1 means zero reachable free chunks while the counter says 100; normal pop/push preserves equality, so this is a separate hard invariant violation. The stored count is also exactly 14 below the 114 state-derived free slots: those 14 missing increments equal the live-chain size, causing the pressure heuristic to report 28 used chunks rather than the 14 shown by state. The terminal snapshot changed those 14 states to 2 and cleared the owner pair. The dump then captured the packer while following the already-present self-link.

Chunk 114's captured allocation tick is 349,309,265 ms and its new generation has 90 facts / 5,777 raw bytes. Within the bounded audit, `0x140BAC2B9` is the only nominal writer of a nonzero chunk allocation tick: recycler code zeroes it at `0x140BACDD8`, while the packer and producer read it at `0x140BAC8F2` and `0x140BAC7A0`. This tick-field result comes from the separate function inspection described above. The most recent allocation therefore followed any nominal recycle, first reset `114.next=-1` at `0x140BAC29E`, and then wrote `previous.next = allocated` at `0x140BAC2CD`. Under the enumerated nominal writers, the current-generation self-link means that invocation read `previous=114` and later returned `allocated=114`.

That narrows the immediate corruption event one stage further without claiming simultaneity: the producer read owner tail 114 at `0x140BAC5E2`; later, allocator `0x140BAC25B` popped slot 114. The pop used the then-current `114.next=-1`, explaining captured free head `-1`: no nominal pool write occurred between that pop and capture, because an empty-head allocation fails without changing head/count and the terminal packer faulted at `0x140BACCA6` before its recycler loop at `0x140BACDD0`. The rollover path leaves owner head unchanged and writes only state/tail, so it preserves the captured head 127 while producing tail 114 and `114.next=114`. The allocator therefore produced the complete captured self-link/head/tail state from stale or otherwise invalid ownership across that interval. This conclusion remains conditional on the bounded nominal-writer set; an arbitrary-pointer overwrite is an alternative.

The dump cannot show what changed ownership between the tail read and pool pop or which earlier event first broke head/count. Cross-thread producers racing snapshot/recycle can create stale owner fields and lost/orphaned links; overlapping/re-entered packers can duplicate recycling. Both are compatible with the missing synchronization. The verified background producer makes the former concrete, while the exact earlier schedule remains unresolved.

## Consequence for mitigation

A traversal-only cycle/bounds guard can stop this crash family, but it treats the consequence. A root guard should reject `previous == allocated`, validate returned-slot state/membership, and reconcile the free head/count invariant. A complete correction should also separate producer ownership by real thread or serialize `Fact` with snapshot/recycle. Cleanup must be proven before any patch: snapshot detaches owner lists and later recycling affects pool ownership, so simply returning from the packer can leak or duplicate chunks.

No mitigation was implemented or deployed.
