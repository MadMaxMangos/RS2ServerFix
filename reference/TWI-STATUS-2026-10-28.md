# RS2ServerFix: fixes and investigation status for Tripwire Interactive

**Updated: 28 October 2026.** Community investigation of the Windows 64-bit dedicated server.

RS2ServerFix currently provides a targeted aerial-recon crash correction and experimental server-reporting/backend recovery tools. The recon correction is in operator-reported production use. Manual Leech recovery has produced encouraging healthy-server training results; repair after a real Steam outage remains unproven. The separate ADF telemetry crash and performance work have no implemented fix.

## Status at a glance

| Area | What is established | Current status |
| --- | --- | --- |
| Aerial-recon crash | An inclusive random endpoint can select beyond the recon output array. | Targeted in-memory correction implemented; deployed on the operator's five servers. |
| Native reporting freshness | Query/reporting counts and in-game browser counts can disagree. The earlier refresh trial did not resolve the observed incident; a full publication after recovery was not established. | Earlier reporting repair exists; it is insufficient as a complete count-recovery solution. |
| Leech session recovery | Native session recreation can run while players remain connected; earlier healthy trials showed subsequent browser-count convergence. | Manual trial feature. The 0.7.1.0 bot-inclusive trial has raw-record confirmation of native session replacement/local publication, followed by operator-reported correct counts. Metadata follow-up remains unresolved. |
| Queued map-travel slot loss | Admission includes travellers and reservations, which WebAdmin/browser population does not fully describe. | Concrete bookkeeping/lifecycle candidates identified; incident-specific cause and fix remain unresolved. |
| ADF telemetry crash | A cyclic chunk list causes an analytics packing overflow. | Crash mechanism established; no mitigation implemented. |
| Busy-server/lag investigation | Historical CPU traces put replication/relevancy ahead of main-thread PhysX CPU. | Investigation only; no performance improvement claimed. |

## 1. Implemented: aerial-recon crash correction

### Defect and correction

In `UROSeqEvent_AerialRecon::TriggerRecon`, the random scaling admits the upper endpoint. With three candidate links per team, it can produce index 3 rather than 0-2. Adding the second team's offset then produces index 6 for an array containing only six entries. The native function can dereference data beyond that array and crash.

A full-memory crash dump independently preserved the endpoint, team offset, array length and invalid dereference. The DLL's `recon-exclusive-scale-v1` correction changes the recon function's constant reference to use an exclusive upper bound. It does not change the shared random constant globally.

The correction is guarded by executable SHA-256, expected instructions and startup checks. The operator has deployed it across five servers and reported successful recon calls and map travel. This is evidence for the specific corrected failure path, not a guarantee against every recon/server crash.

**Suggested native fix:** use an exclusive bounded index, validate the group/count inputs, and check the final index against `OutputLinks.Num` before dereferencing.

A separate reported case where a recon call resets its cooldown without producing a plane has not been diagnosed or fixed by this correction.

## 2. Experimental: recovery of maintenance-related browser undercounts

### Observed problem

During Steam maintenance, the in-game browser's count can decline while players remain on the server and WebAdmin still reports their presence. After Steam recovers, newly joining players count immediately, while players who stayed connected can remain absent from the browser count. The operator reports that map travel and successful authentication do not reliably repair it; a manual disconnect/rejoin or server restart does.

Client analysis establishes that the in-game browser can replace Steam query counts with a count from a Leech backend record. Correct WebAdmin or A2S query counts therefore do not establish a correct in-game count.

The exact failure across server session state, client session selection, backend membership and count projection is still unresolved. We have not established an intentional anti-spoofing action, a specific backend defect, or a failure of Steam authentication as the root cause.

### What the recovery feature does

The manual recovery path submits Finish for the existing standalone server session, waits for the matching successful response, then follows the game's native cleanup/Start/Create lifecycle. It checks replacement session identity, publication into the local game cache and heartbeat binding.

Its purpose is to replace stale standalone-session state while preserving connected players. It does not reset Steam authentication or manufacture a player count. This is different from the earlier reporting `mode=repair`, which requests fresh native advertisement data.

In the separately prepared **0.7.x operator trial kits**, recovery ships disabled. Once explicitly configured, an operator can request it through authenticated PowerShell or the opted-in WebAdmin command below. These WebAdmin commands are not present in the older published 0.6.2 source:

```text
rs2leech status
rs2leech recover <current-run-confirmation>
```

There is no automatic outage detector or automatic recovery loop.

### Results and current limits

- **Earlier healthy two-player trials:** native session replacement completed; the browser temporarily showed zero, then one, then two players after a propagation/catch-up delay estimated at roughly one minute, without player reconnects. Exact browser latency was not measured.
- **27 October production maintenance trial, 0.7.0.0:** the request was rejected before native entry. Bots were a confirmed precondition blocker, although the composite refusal does not prove they were the only one. This did not test the native recovery recipe under outage conditions.
- **28 October training trial, 0.7.1.0:** matched process/module-file inventories and runtime recon checks identify the qualified candidate. All 23 collector inventories report native PI=32, bots=30 and maximum=32, with two Steam players present according to the operator. Raw records show matched successful Finish/Create callbacks, changed and matching SDK/cache session fingerprints, local publication about **0.94 seconds after the server's recovery owner picked up the request**, and a renewed heartbeat binding. This is lifecycle elapsed time, not a single blocking pause. The operator subsequently reported that counts were all correct. This healthy-baseline exercise does not establish recovery from outage damage.

The 0.7.1.0 candidate permits bots under the schema-2 policy while preserving native count semantics. A preflight-only refusal can permit a fresh explicit request. Once native recovery starts, another attempt remains unavailable for that process; some failures can require a normal restart.

The latest trial ended with reason 65, `metadata-timeout`, approximately **30 seconds after local publication**. Raw flags confirm that the explicit follow-up metadata Update was **not attempted** and metadata coherence was not established within that window; the last sampled in-progress reason was `MetadataCountsNotReady`. The captured diagnostics do not directly identify the specific unmet readiness/pump-scheduling condition. This is a local follow-up deadline, not measured browser propagation or confirmation of backend delivery. The operator's count observation must not erase that diagnostic.

A later builder diagnostic observed a valid local prepared snapshot with 32 members and no prepared-state mismatch about **31.6 seconds after publication**. The first recorded normal builder after publication occurred at about 30.17 seconds, just after the local deadline, and still showed the members-only mismatch with zero prepared members. The native interval is 30 seconds. The deadline/cadence relationship is now a concrete follow-up; these local observations do not establish backend count projection or client adoption.

**Remaining work:** reconcile the follow-up deadline with native rebuild cadence and remaining local readiness conditions; establish client adoption and backend membership/count behavior during an actual outage; then assess wider deployment and any automatic triggering.

## 3. Diagnosed, not fixed: ADF analytics packing crash

This is separate from recon and maintenance recovery.

The 9 October full dump shows a native analytics chunk list ending in a self-cycle, `114 -> 114`. Repeated packing overruns the descriptor array, corrupts the raw-data length and leads to an out-of-allocation copy. A stale producer tail surviving snapshot/recycling is the best-supported route among the examined writers; the unique earlier thread interleaving is not captured.

**Suggested native investigation/fix:** correct producer/snapshot/recycle ownership and synchronization, and validate list bounds, cycles, descriptor totals and byte totals before packing. A mitigation must validate under a coherent ownership model; a terminal memcpy check alone would not repair the underlying corruption.

See the [crash findings](campaign-crash-2026-10-09/FINDINGS.md) and [origin analysis](campaign-crash-2026-10-09/ORIGIN-TRACE.md). No ADF mitigation is present in the deployed recon or recovery DLL.

## 4. Investigation only: replication, collision and PhysX performance

Historical full-server, no-helicopter CPU traces attribute approximately 47-56% of sampled main-thread CPU to `ServerTickClients`. Collision/line/point checks within that category account for approximately 20-27% of main-thread samples, and actor serialization about 14-16%. These are nested categories, not independent totals.

PhysX appears in approximately 1.0-1.3% of main-thread CPU samples in those windows. Physics on other threads and time blocked waiting for simulation are separate; the evidence does not establish PhysX as the dominant bottleneck.

Current leads are avoiding redundant relevance/collision work, coalescing genuinely redundant server-information publications during connection/queue churn, and evaluating safe copied-data preparation on workers. Existing collision routines use shared scratch state and cannot simply be called concurrently unchanged.

The exact bundled Epic PhysX 2.8.4.1 runtime implements internal workers, but the inspected primary scene does not enable them. That creates a feasibility lead, not evidence of a speedup. Shell/ordinary-particle server guards already exist; APEX/opt-in effects and ragdolls need workload-specific checks. No PhysX replacement, worker change or blanket cosmetic-physics removal has been implemented.

## 5. Investigated, not fixed: player slots lost around queued map travel

The reported symptom is a server showing, for example, 59/64 or 60/64 while every new arrival is immediately queued, particularly around a map change with an existing queue.

The local SDK source gives a concrete mechanism: ordinary admission includes raw `NumPlayers`, engine `NumTravellingPlayers`, reserved entries and travelling entries; the final pre-login decision also accounts for the arriving player's pending-queue position. Thus 59 players plus five admission reservations can fill a 64-slot server even though those reservations are not playing clients. That is a mechanical explanation, not proof of those exact numbers in the reported incident.

Map travel preserves logged-in identities as priority travel claims. The source expires unreturned travel claims after about 120 game-time seconds and authenticated reservations after 300 seconds, checked on a five-second timer. Repeated admission attempts can renew reservation timestamps. Persistent loss therefore needs a stale/duplicate/renewed reservation, counter imbalance or another established branch; the existence of reservations alone is insufficient.

There are specific leads and competing explanations:

- The browser may underreport an actually full server. The original ghost-slot report lacked a simultaneous actual-player/admission census, so a low displayed count alone does not establish spare capacity.
- Repeated-login paths can structurally leave logged/reserved overlap. Occurrence during a failing incident is unproven.
- Native connection Close notifies the current GameInfo by player identity without a connection generation, potentially repeatedly. Old/new connection ownership across travel/rejoin deserves checking; premature removal alone does not explain excess occupancy.
- A separate probe observed raw `NumPlayers=65` with a 64-player maximum and negative spectators. Such drift can block admission independently of the displayed count, but was not tied conclusively to a ghost-slot incident.

**Suggested native/script investigation:** reconcile actual connected humans, raw player/traveller counters and all queue memberships at the rejecting join, including reservation ages and connection/world generation. Correct the demonstrated ownership/count imbalance rather than clearing queues or bypassing capacity.

The executing script package still needs matching to the inspected SDK source. No permanent queue leak, unique root cause or DLL fix is claimed. Genuine admission bookkeeping faults must be distinguished from browser-only undercounts. Earlier DLL changes to reporting qualification do not repair gameplay admission counters or queue ownership.

## 6. What would help from Tripwire

1. Review and incorporate a native recon bounds correction.
2. Correlate an affected server's standalone session, retained clients and browser record across Steam maintenance. Establish why manual rejoin restores counting when authentication/map travel alone does not.
3. Review the ADF producer/snapshot/recycle ownership failure independently of the count investigation.
4. Review queued map-travel admission bookkeeping and connection-generation ownership alongside the raw player/traveller counters.
5. With source/profiling access, inspect replication/relevancy fan-out and physics wait time under representative player/vehicle load.

Other tracked reports include Workshop download/name-resolution failures. They have no fix claimed in this update.

## 7. Scope, source and supporting material

The recon profile targets a qualified, locally full-dump-patched copy of the Steam server executable. That pre-existing dump patch is separate from the DLL and is not created by it:

```text
SHA-256: 0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393
```

The DLL changes memory in the running process; the executable's on-disk contents and ordinary launch command remain unchanged. Other builds require separate qualification. These trial observations do not include a matching clean-stock control.

The 0.7.x versions above refer to separately prepared operator trial kits. This document does not promote those source snapshots or publish a native-recovery binary release. The repository's existing build/release instructions describe its published variants. Pushing this documentation also triggers the existing CI workflow to build and publish new recon-only/read-only-probe prereleases; that workflow does not publish the native-enabled recovery kit.

- [Project and published-source scope](../README.md)
- [Recon patch profile](../src/companion/recon_profile.h)
- [Leech/ADF failure catalogue](leech-reference-2026-10-09/FAILURE-CATALOGUE.md)
- [ADF pipeline](leech-reference-2026-10-09/ADF-PIPELINE.md)
- [Leech error taxonomy](leech-reference-2026-10-09/errors/ERROR-TAXONOMY.md)

The linked October 9 analysis is historical; its package-version references predate the later trials summarized here. Private dumps, credentials, player data and proprietary binaries are not included.
