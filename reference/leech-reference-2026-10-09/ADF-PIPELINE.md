# ADF diagnostic pipeline

> Archived 9 October 2026 analysis. See the [publication scope](FAILURE-CATALOGUE.md).
> Supporting artifacts and further notes cited below remain in the private archive;
> their names are provenance references, not files bundled with this repository.

Read-only static evidence; reference closure review APPROVE, with scope in REVIEW-RESULT.md. All unprefixed addresses below are server RVAs. The authenticated binaries are identified in REFERENCE.md and evidence/00-identities.json. The October9 crash mechanism is inherited from the separately reviewed incident report; this chapter extends the surrounding lifecycle without proposing a patch.

## Boundary and current-build changes

ADF records formatted diagnostic facts and context, snapshots fixed-pool chunks, builds a packed descriptor/raw-data representation, compresses it and submits `IDiagnosticDataService::WriteADFPack`. It is not the normal Launch.log writer or a player-membership API.

The historical PDB names16 selected implementations whose complete original code-contribution spans have unique current structural counterparts. Each matches after masking external call/branch targets and RIP-relative addresses while preserving constants and internal branches. This includes the1077-byte producer,2051-byte merge function,1061-byte request builder,396-byte uploader update and651-byte UploadOrQueue. See evidence/19-adf-contribution-map.json and20-adf-contribution-map.csv. Correspondence does not automatically prove all callees or remote semantics unchanged.

The separate `l3h_fact_init` and `l3h_fact_update` wrappers do change: current init registers component policy2 instead of1, and update requires a valid diagnostic endpoint proxy before state1->2 promotion. Component dispatcher and error-policy local bodies match across builds (evidence/18-policy-pair-comparison.json). ADF is therefore no longer a critical-readiness prerequisite, and its ordinary error policy differs if generic component escalation is reached.

Do not infer every upload error used to disconnect the server: normal uploader error callback returns true and suppresses generic escalation in both builds. The policy change is a supported conditional behavior, not evidence of an incident effect or a fix for the ownership race.

## Collection and packing

The producer and fixed-pool/snapshot/packer design are covered by the incident ORIGIN-TRACE.md. Key invariants relevant to the broader system are:

-128 fixed chunks, each with256 fact descriptors and32768 raw bytes.
- A shared owner-slot index is process-global in this build, despite its GetThreadId name. Game/owner and HTTP-worker paths can both produce facts.
- Pool pop/push uses a common lock, but producer-tail reads, post-pop reinitialization/linking and snapshot owner clearing are not covered by that same lock.
- The aggregate descriptor area has32768 entries and raw area4MiB; traversal does not independently reject cycles or enforce aggregate capacity before writes.
- Normal packing uses a900000ms check; pressure/requested/termination paths also exist. The crash's periodic route was proved separately, not inferred from this generic catalogue.

Current MergeChunksEx BAC7E0 recycles snapshotted chunks before constructing/submitting the packed request. Its tail checks stream phase/endpoint and availability of a diagnostic token to choose immediate submission versus queueing. The request records a usable pack/core kernel GUID; it is distinct from the standalone game-session ID and the main authorization token. Failure to upload does not imply the original chunks remain available for reconstruction.

## Request construction

Historical PACK::SetupRequest BA1E10 maps to current BACFF0. The output request is0xC0 bytes, containing header/context and two vectors. It labels the raw format `PRINTF_RAW`, copies fact/context metadata, and separately compresses descriptors and raw bytes into a shared1MiB scratch area. Nonzero compression status emits a diagnostic fact; this is not the terminal overrun observed on October9, which happened earlier during packing.

The request stores a core/kernel GUID from the pack when valid, otherwise the current local kernel GUID getter, otherwise a fixed invalid identifier. These identity fields must not be equated to Leech AuthorizationToken, server game-session ID or a player's membership.

## Queue and callback semantics

Uploader begins at manager+0x9C1100. Its vector is at+0/+8/+0x10; busy byte at+0x18; finalization bookkeeping DWORD at+0x1C. These offsets are relative to the uploader, not the manager or task.

Normal UploadOrQueue BADA90 starts a request when not busy and not forced to queue. It marks busy first, constructs a typed request handle, copies request data and calls typed submit BAB9B0. Otherwise it appends an owned request copy to the vector. Before appending, if the current count is greater than10 it removes the oldest entry. Thus the ordinary steady maximum is11 queued requests, not10; this bounds retained packs, not native transport attempts.

Uploader Update BAD5D0 does nothing when busy or the vector is empty. Otherwise it marks busy, copies the last vector entry into a typed request and submits it, then destroys/removes that last queued entry. It is newest-first at this layer. The queue entry is removed on submission, not remote acceptance.

Success callback BAE890 and error callback BAE8B0 both load the current global manager and clear manager+0x9C1118 if nonnull. Error returns true. These callbacks do not retain the dequeued pack or reinsert it after terminal failure; generic native task retry is a separate layer. The callback bodies do not themselves compare a saved uploader generation/request ID, so surrounding manager/task lifetime and shutdown delivery suppression remain important.

A separate branch with request flag0x10 and the caller's allowed-send boolean uses immediate submit BAB8F0 and finalization bookkeeping, without the ordinary busy-byte admission. Its error callback BFB310 also returns true. The flag's remote meaning is not inferred. This branch must be included in a capacity/lifetime audit rather than assuming the busy byte serializes every ADF request.

## Relation to maintenance and safe interpretation

Successful authorization requests an ADF dump through BFC4D6 -> BAE7B0. That leaf writes byte [manager+0x9C10D8]=1, not the uploader's busy byte. Its historical PDB name is l3h_fact_queue_force_dump, and its 21-byte implementation matches current. This establishes a connection between auth and diagnostics; it does not change the October9 terminal path, which was independently proved periodic from captured state. See authorization/AUTHORIZATION.md.

Loss of endpoint/token readiness can cause queueing and eventual local diagnostic drops. Lack of a particular ADF fact is therefore not proof that the underlying game action did not occur. Native success/error callbacks, physical HTTP retries and remote acceptance must remain separate observations.

The uploader callback and queue behavior do not identify the earlier corruption writer in the crash. The confirmed self-cycle/overflow mechanism remains the incident result. No association between this ADF defect and Tuesday protected-count decline has been established.

Full file-backed bytes and disassembly for19 historical/current pairs, including the callback leaves, are in evidence/21-adf-file-bytes.json and22-adf-current-disassembly.txt. The transport chapter establishes the ordinary delivery/suppression path and a conditional shutdown lifetime hazard; it does not prove all indirect producer sites or eliminate concurrency hazards. Those are explicit boundaries, not attributed maintenance causes.
