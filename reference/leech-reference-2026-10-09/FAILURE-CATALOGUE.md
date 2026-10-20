# Failure paths and diagnostic decisions

> Archived analysis from 9 October 2026, not a patch or runtime approval.
> Only this catalogue and the five Markdown documents it explicitly names are
> published here. Other evidence/notes mentioned in these documents refer to the
> retained private investigation archive and are not included. Package versions
> and operational state below describe that investigation, not today's release.

Published supporting documents:

- [ADF crash findings](../campaign-crash-2026-10-09/FINDINGS.md)
- [ADF corruption-origin trace](../campaign-crash-2026-10-09/ORIGIN-TRACE.md)
- [ADF diagnostic pipeline](ADF-PIPELINE.md)
- [Server core status and component consumers](delegates/SERVER-CORE-DELEGATES.md)
- [Error taxonomy and escalation](errors/ERROR-TAXONOMY.md)

This catalogue distinguishes observed failures, statically established branches and unresolved hypotheses. Server RVAs apply only to the authenticated current build. A compiled path is not proof that it ran during Tuesday maintenance.

| Path / condition | Supported local consequence | Evidence | Status / missing observation |
|---|---|---|---|
| ADF owner chunk self-cycle 114 -> 114 | Repeated packing overruns descriptors, corrupts raw length and copies out of allocation | ../campaign-crash-2026-10-09/FINDINGS.md; 06-adf-memory-proof.json; 07-adf-overflow-replay.json | Confirmed October 9 immediate failure, same August family; unique earlier interleaving unknown |
| Producer stale tail survives snapshot/recycle then same chunk is popped | Allocator can install self-link through otherwise nominal writes | Incident ORIGIN-TRACE.md and current-writer-trace | Best-supported causal route among enumerated writers; not an observed scheduler history |
| Critical components ready | Core publishes CONNECTED_CRITICAL / online log before dependents start | BF6240; delegates/SERVER-CORE-DELEGATES.md | Log cannot certify standalone membership/count health |
| Full-core OFFLINE notification | Adapter terminates core, waits 10 caller-delta seconds, reinitializes and rediscovers | A599F0 / A4B2F0 / A48990 | Actual maintenance branch requires time-correlated runtime evidence |
| Component-policy3 generic escalation | Cancel/stop that component and request auth refresh scheduling | BF8160 / BFCE70 | Does not immediately reauthenticate or guarantee standalone Create |
| Error-policy5 or component-policy1 escalation | Request whole-core disconnect | BF8160; errors/ERROR-TAXONOMY.md | Private callback true or suppression flags may intercept earlier |
| CURL timeout28 / other CURL error | Transport status1 / 2 maps to Leech104 / 103 | C0BEB0 / C00E70 | Must retain physical attempt, task ID and later retry history |
| HTTP408 / 503 / other non200 | Leech115 / 113 / 107 respectively | C00E70 | HTTP503 and backend Maintenance retCode200 are different domains |
| HTTP200 with backend nonzero retCode | Typed failure still occurs | BD3C30 and typed result chain | HTTP success alone does not mean operation success |
| Retryable task error | Scheduling/backoff may retain task and eventually clear counters on success | BF6420, task-state evidence | A clean final task snapshot cannot prove no outage |
| Auth success has empty Endpoints | Disconnect150 CS_NoServiceEndpoint | BFBF80 | No observation that this occurred on Tuesday |
| Refresh UpdatePolicy1 | Disconnect149 "Update policy disconnect" | BFC8D0 | Remote policy/input required to explain why |
| Refresh OldValue mismatch or empty NewValue | No replacement through that entry's guarded branch | BFC8D0 | Need redacted identity/equality metadata, not token contents |
| Reusing provider callback input | Auth Start copies cached/static credential material | BFBB70 -> BA5AB0 -> A59DD0 | Restart is not proof of fresh Steam/EOS credential acquisition |
| Auth reset leaves diagnostic/ACL strings | Nonempty data remains after local auth reset | Authorization reset bytes | Retention alone proves neither validity nor intentional fallback |
| Standalone Finish terminal failure | Stock local cleanup can still occur | October 6 final DESIGN and lifecycle evidence | Local state0 is not accepted remote Finish or old-member removal |
| Server publication precedes peer eligibility | Ineligible peer receives no copy/pending state from that publication pass | 693130 | Later resend does not enroll it; initial Welcome may deliver separately |
| Pending ID sent and control34 logged | Serializer submission and acknowledgement handler entry | 68AC70 / 696810 / 96DC9D | Matching comparison, delivery, selection and remote effect remain distinct |
| Preferred-list ID remains nonempty | Client selects it ahead of fallback | Authenticated current-client audit | Need actual selected ID at failed/recovered notification |
| Same-ID control33 | No forced replay solely from receiving same ID | Current-client control33 branch | A repeated server broadcast is not a general membership repair |
| Client session errors1053/54/55/57/58 | Current-client filter requests list refresh | CLIENT A7FBE4..A7FBFC; original enum | Exact current-backend response to stale ID still unobserved |
| Full metadata returns retCode0 | Request accepted by typed success path | Prior42 paired requests/responses | No committed count/revision echo; cannot certify protected count |
| Prepared Members populated | UUID placeholders and count produced locally | Count/source chapter; prior native audit | Not authenticated identities or proof of membership admission |
| Client finds no Leech row by IP + connection port | Writes Players=0 and retains incoming max/bots; caller still processes result | CLIENT A84772 -> A84B07; `SetLeechServerPlayerCount: NOT FOUND Steam server...` | Verified local display mechanism; not observed as the Tuesday incident cause |
| Exactly two client endpoint rows match | Cancels selection, lookup returns false and takes the same zero write | CLIENT A7D870 / A7DE52; `FindLeechServer: dublicate found` | Need actual candidate rows and match outcome in the failure window |
| Third match follows a cancelling pair | Can select again; duplicate handling is not unconditional rejection | CLIENT A7DE47..A7DE4C and A7DE8E..A7DEA3 | Static control flow; not dynamically exercised in this investigation |
| ADF unavailable endpoint/token or busy upload | Queue retention, newest-first drain, bounded local drops | ADF-PIPELINE.md | Missing ADF fact is not proof an action never happened |
| ADF upload private error | Busy cleared and generic escalation suppressed | BAE8B0; normal uploader path | No automatic reinsertion of removed queue entry; native retry separate |
| Unknown generic completion task ID | Lookup can reach null read at BF7442 | BF7400; transport chapter | Invariant hazard, not observed in this crash or maintenance evidence |
| Termination overlaps an unsynchronized late HTTP worker | Raw handler/payload/multi lifetime might be exceeded | C00C30 / C0ECB0 / C0BFE0 ordering | Conditional longstanding hazard; outer quiescence and real overlap unproved |
| Nonserver UserHeartbeat success arrives after lifecycle change | No local role/raw guard before enabling polling | C09800 | Generic cancellation/lifetime may exclude it; no server occurrence observed |

## What the two investigations establish

The October 9 crash is an ADF diagnostic packing failure, not the aerial-recon indexing failure. Its full-memory dump establishes the terminal corruption topology and exact overflow. The authenticated deployed reporting DLL does not patch the packer, and no evidence identifies it as the corrupting writer. The same ADF family predates that DLL. This does not logically exclude every indirect timing interaction, but there is no basis to blame one.

Tuesday count loss has no equivalently complete causal proof. We know the local state machines, count sources, success/error boundaries and client selection rules. Existing accepted full metadata publications weaken simple "nothing was sent" or blanket metadata-rejection explanations for those captured requests. They do not establish protected membership eligibility, revision projection or the selected session ID of a client who failed to restore its count.

## Recommended next evidence

The most discriminating next step is one synchronized before/during/after-maintenance observation, or one paired automatic-travel/manual-rejoin case during an existing failure. Align all samples to UTC plus a monotonic offset and preserve exact EXE/DLL/config/package identities. Collect only fields needed to answer these branches:

1. **Publication:** server standalone ID, adapter cache ID, raw standalone/core/auth states, metadata revision/content hash, task ID, full/partial heartbeat decision, retry/HTTP/retCode and timestamp. Record count inputs separately rather than one merged number.
2. **Client row-match outcome using existing diagnostics:** correlate endpoint, matched / `dublicate found` / `NOT FOUND`, and `m_nPlayers old -> new` before drawing a backend conclusion. Keep browser row lookup separate from the endpoint-to-session lookup's FOUND/DUBLICATE messages. Existing DevOnlineSpam (category4006) sites expose these outcomes and count replacement. Start with retained `steam-maintenance-2026-09-14/evidence/paired-logs-2026-10-05/selected-markers.json`: it contains healthy-baseline44->60,60->60,1->1 and0->0 samples, not failed-incident selected IDs. Preserve all matching candidate rows and their parsed op values when available in retained captures; ordinary logs do not expose the full selected record.
3. **Delivery and exact session selection, requiring extra evidence:** whether Welcome/control33 sent a fallback, peer eligibility/pending state and matched control34 comparison are distinct from the client preferred-list/fallback/started IDs and the ID actually put in Start/Heartbeat/Finish. The October2 supported-diagnostics audit found no complete supported local route exposing those selected IDs. Exact ID/cache/request correlation and any missing parsed row payload therefore require separately authorized targeted instrumentation/capture or a pre-existing suitable artifact; they must not be requested as if an ordinary log switch already provides them. ID equality labels or keyed digests can preserve correlation without credentials.
4. **Remote result and projection:** paired notification response, any returned member/count/revision data, the browser's row-match outcome, and time-matched browser/A2S/game counts. If no count/revision is returned, record its absence; do not infer it from retCode0. A local zero-write branch must be ruled in or out before attributing a zero display to backend projection.
5. **Recovery distinction:** compare the same player's travel and manual reconnect under the same server session, with elapsed time and intervening publications recorded. Existing observations taken at different times are not a controlled comparison.

No tokens, raw provider credentials or authentication headers are needed for the first pass. Existing retained artifacts should be checked first. Adding hooks, capturing a live process/network stream, forcing an outage or exercising recovery requires separate authorization; none was done for this reference.

Diagnostic availability source: `steam-maintenance-2026-09-14/client-followup-2026-09-30/supported-diagnostics-2026-10-02/findings.json`, fields conclusion/native_logging. A redacted extract and hashes of these prior artifacts are preserved in evidence/24-review-closure.json. This plan does not authorize changing log suppression or enabling broad credential-bearing categories.

## Mitigation feasibility

**ADF crash:** a narrow native/DLL guard is technically plausible if it validates bounded pool membership, cycles, descriptor totals and raw-byte totals before packing writes. Dropping a malformed diagnostic batch could contain the confirmed overflow. A guard must account for producer/snapshot concurrency; walking mutable lists and then trusting them later can leave a race. Correct synchronization/ownership needs a broader design than a terminal memcpy check. No patch is implemented here; the incident ORIGIN-TRACE.md specifies the proof gaps.

**Count recovery:** the reviewed default-disabled 0.6.1 package follows the standalone native lifecycle rather than inventing backend membership. It is a candidate for a separately authorized controlled trial, not established recovery. This reference makes its success criteria stricter: new local session, delivery acknowledgement and native retCode0 are intermediate events; clients must select the new ID and the remote browser projection must recover. Provider credential reacquisition is outside that standalone sequence.

**Transport hazards:** do not combine speculative lifetime fixes with a count or ADF mitigation. First establish the actual shutdown ownership invariant or capture a concrete violation. The observed local ordering is shared with 2020 and is not itself evidence of a new regression.
