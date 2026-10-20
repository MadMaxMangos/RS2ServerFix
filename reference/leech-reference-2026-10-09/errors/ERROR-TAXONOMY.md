# Leech error taxonomy and escalation - read-only evidence

> Archived 9 October 2026 analysis. See the [publication scope](../FAILURE-CATALOGUE.md).
> Supporting artifacts and further notes cited below remain in the private archive;
> their names are provenance references, not files bundled with this repository.

Date: 2026-10-09. No database queries, native execution, server operation, source edits, builds or tests. Two scripts in this directory read original PE/PDB files and write derived data here. Original files remain read-only inputs.

## Identity and evidence

- Historical SERVER PDB: `D:\Documents\RisingStorm2\Binaries\Server\.HistoricalWithPDB\VNGame.pdb`, SHA256 `C4DAE3CAD0C8C0FECA39221575E0521C298DA17F2D63C9A8391BF5AC94AB9B14`; GUID `777c3a2d-40b1-4d67-8163-afbbcba4b67b`, age1. This agrees with primary PE/PDB custody evidence.
- Historical SERVER EXE: sibling `VNGame.exe`, SHA256 `865D5E92EEBBE5DFDC69F0E8320025627CCB464AD07E3582CFD30F72D0F5A81F`.
- Current SERVER EXE: `D:\Documents\RisingStorm2\Binaries\Server\VNGame_pr3.exe`, SHA256 `0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393`.
- Current CLIENT EXE: `D:\Documents\RisingStorm2\Client\Binary\VNGame.exe`, SHA256 `805E0D61951CB9E87901E490283583C3401462068E3C6780F52929FE9C5B458C`.
- `historical-error-enums.json`: complete 341-member `BackEnd::ErrorCode`, TPI type0x52ED7, field list0x52ED6, plus other selected enums. Parser visited522664 TPI types and26422 enums with zero enum-field parse failures. `historical-enum-names.txt` and `historical-udt-names.txt` contain all discovered names.
- `historical-selected-udts.json`: public Leech structure record bytes. `leechDEFER_ERROR` complete type0x4A2AC, size40, field list0x4A2AB; `code` is signed int32 at+0 and `message` at+8. Internal service/category type names are absent from TPI despite their appearance in public symbol signatures.
- `current-error-evidence.json`: fresh body bytes, instructions, hashes, error-category tables, historical/current comparisons and current-EXE verification of every body in the existing `deeper-recovery-2026-09-16\sdk-query-population\leech-heartbeat-failure-v1.json` packet.
- Both server category tables are exactly808 bytes/101 entries with SHA256 `AE6AC2648EB7E80C292086BA7D60011BEFCB67A2577D335B2289D563B8283C48`. Historical RVA1266C00..1266F28; current1279C20..1279F48. Exact byte equality establishes preserved code/category association, not the remote backend's present behavior.

## Missing/finished game-session codes

These are original 2020 SERVER PDB enum spellings. Current CLIENT A7FB70 uses the same five-number filter; current SERVER category table keeps the historical associations. Names are strong historical semantics and useful current guidance, not a server-side backend contract obtained from source.

| Code | Original PDB spelling after ErrorCode_ | Current client refresh flag | Current server category |
| --- | --- | --- | --- |
|1052|SCS_Fatal|not selected|4|
|1053|SCS_SessionNotFound|selected|4|
|1054|SCS_SessionFinishedNormal|selected|4|
|1055|SCS_SessionFinishedRejected|selected|4|
|1056|SCS_SessionFinishNoMatchingDsm|not selected|4|
|1057|SCS_SessionFinishTimeoutActivate|selected|4|
|1058|SCS_SessionFinishTimeoutDS|selected|4|
|1059|SCS_DSMTimeout|not selected|4|
|1060|SCS_ServerWarning|not selected|0|
|1061|SCS_QueueTimeout|not selected|0|

Current CLIENT A7FBE4..A7FBFA compares code-1053<=2 or code-1057<=1; A7FBFC writes byte184AC44=1. Its error object layout matches code+0/message+8. Matching source-export lines are `Client\Binary\ida\VNGame.exe.c:2455085-2455120`; list-refresh meaning/consumer was traced by the prior membership investigation. This callback does not itself clear selected/session IDs, establish list refresh completion, or prove a newly adopted session. Why1056/1059 are excluded is not established.

No evidence here proves which code a real GameStart/GameHeartbeat notification naming an old server session will receive. The backend may respond differently based on request type, identity or lifecycle. No captured current request was used to assert this mapping as a live contract.

## Separate error domains

1. Lower libcurl result is not a Leech enum. Current C0EAC0 (`httpREQUEST_MANAGER_CURL::RequestFinished`, historical C03AC0) maps CURL result28 to transport completion byte1 and other nonzero results to byte2. Success retrieves HTTP status separately; getinfo/body-length failures also use byte2. Do not mix this byte with HTTP status or BackEnd::ErrorCode.
2. Current C00E70 (`l3hHTTP_AGENT::OnRequestResult`, historical BF5D00) translates completion byte and HTTP status into a Leech error passed to `PrepareResponse`:

| Input | Leech result | 2020 name |
| --- | --- | --- |
|completion byte0, HTTP200|0|Success|
|completion byte0, HTTP408|115|CS_HTTPManager_TimeOut|
|completion byte0, HTTP503|113|CS_Throttling|
|completion byte0, other HTTP status|107|CS_HTTPManager_UnexpectedStatusCode|
|completion byte1|104|CS_TimeOut|
|other nonzero completion byte|103|CS_HTTPManager_Error|

Relevant current instructions C00ED7..C00F10 and C011EA..C0122C. HTTP429 follows the generic107 branch in this bridge; the existence of enum108 `CS_HTTPManager_TooManyRequests` does not prove429 maps to108 here.

3. `l3h_HTTP_QUERY_PAYLOAD::PrepareResponse` currentC01270, historicalBF6100, can turn decompression failure into112 atC017EA or invalid binary response framing into103 atC01A4C/C01A77/C01AAC. These are local processing failures, even after transport success.
4. Typed response `retCode` is distinct again. Current BD3C30 bool-defer conversion: retCode0 sets true; nonzero copies the retCode into a deferred error (`+30`) and marks error state2 (`+2C`), rather than treating HTTP200 as semantic success. Existing service-descriptor binding supplies which typed operation uses this converter.
5. Private task error callback ABI is `(int code, uint32 requestId) -> bool`; BF5CD0 adapts ECX/EDX. Boolean true suppresses generic/global escalation. A true callback return is NOT an operation success.

`BackEnd::ErrorCode` shares one numeric vocabulary across local/client-side and remote service categories. Important historical names:102 InvalidACLToken;103 HTTPManager_Error;104 TimeOut;105 ParseError;107 UnexpectedStatusCode;108 HTTPManager_TooManyRequests;109 RequestCanceled;110 RequestRetry;111 CompressionError;112 DecompressionError;113 Throttling;114 TimeOutSpike;115 HTTPManager_TimeOut;149 UpdatePolicyReconnect;150 NoServiceEndpoint;151 NotFound;152 NoSpaceLeft;153 InvalidUserId;154 NotInitialized;155 Busy;156 InvalidProviderToken;160 InvalidInputParameters;161 RequiredComponentIsNotConnected;162 UnavaliableInThisConfiguration;163 TooManyRequests;164 NotReady (all prefixed CS_). Preserve spelling as shipped.

Backend enum200 means `Maintenance` and201 `Maintenance_SliceNotFound`; HTTP200 means transport success. They are different domains. Neither proves a particular Tuesday incident involved backend maintenance.

## Generic retry and escalation

Current BF6200/historical BEB0C0 `BackEnd::ERROR_CATEGORY_HELPER::CanRetry` returns false for category4 or5, true otherwise. A code absent from the table defaults to category1/retryable. Category names beyond these observed behaviors were not recovered from original TPI.

Current BF7400 completion:

- A nonnull success result clears both ordinary and throttle counters (`+68/+6C`) atBF7450. A surviving periodic task returns to state2 with a new schedule anchor; nonperiodic/completed/cancelled tasks are disposed.
- Error113 increments throttle counter atBF74EC. Before20 throttle hits it requeues a nonperiodic task in state3 or periodic task in state2, adds a nonnegative delay capped at15000 native units/half metadata timeout, and bypasses error callbacks. At20 or more, it falls through to callback/escalation; periodic retention can still occur afterwards.
- Other errors increment ordinary counter atBF752F. Retry eligibility uses the metadata retry limit and CanRetry. Bit1 of metadata flags admits state3 retry; periodic tasks can requeue state2 without callbacks when category0 or a retryable attempt remains. A separate retention threshold is max(100,retryLimit).
- Otherwise BF6420 runs the error callback/escalation path. If it leaves the task executing and the periodic/retention predicates still hold, BF7701 requeues state2 anyway. Thus state2 alone does not establish last-success or zero error history.
- State3's nominal delay ladder uses retry counters; state2 uses ordinary polling interval. Prior `NATIVE-SCHEDULER-DIAGNOSTICS.md` documents precise fields and floors. Do not conflate retry, periodic repoll and lower libcurl transport retry.

BF6420 first invokes the private error callback via metadata+80; true exits immediately atBF6467. Metadata flag0x80 suppresses generic escalation for categories other than5; category0 only logs. Other errors reach component dispatcherBF8160. A private callback can therefore prevent even category5 global handling.

Component policy is a DIFFERENT number space from error category. BF8160 looks up component definition, reads+20, and acts as follows, if reached:

| Component policy+20 | Behavior |
| --- | --- |
|1|Whole-session disconnect pathBF79B0, regardless error category|
|any with error category5|Whole-session disconnect pathBF79B0|
|2|No additional component-level action for non-category5|
|3|Dispose/cancel that component's tasks; invoke its stop callback+8; request authorization token refresh|
|4|Request authorization token refresh without the preceding component stop|

The refresh request is BFCE70, matched to original PDB-named `l3h_authorization_component_refresh_tokens_force` atBF1C10: it zeros qword17AEAC0. It does not directly clear the standalone game-session ID. Whole-session BF79B0 cancels/disposes all128 task slots (executing states4/5 become5), records disconnect code/message and clears the connected flag if previously connected.

The root's independently verified Fact component policy change1->2 consequently removes ordinary error escalation to whole-session disconnect at this dispatcher; category5 remains global if the dispatcher is reached. This is a control-flow consequence, not a causal link to the ADF chunk race or maintenance undercount.

## Historical/current and source checks

Five complete pairs preserve internal branch displacements, instruction/constants and bytes after masking only RIP-relative and external direct-call/jump displacements: CanRetry53bytes; refresh-token-force12; HTTP result bridge1024; PrepareResponse2832; CURL RequestFinished496. External targets/data roles remain verified separately; masking does not establish arbitrary callee equivalence.

Reviewed0.6.1 source archive `leech_recovery.cpp:166-194` deliberately records any Finish error as `FinishRejected/MechanicsFailed` and its private error callback returns true. This suppresses native generic escalation while preserving one-shot failure state; do not treat it as a successful Finish. It is candidate-source behavior, not proof of deployment/runtime execution.

## Unresolved

- Original PDB has no TPI definition for `leechSERVICE_CONNECTION_STATE` or `s_l3h_session_component_definition`; only public signatures refer to them. All enum and UDT names were scanned, including internal l3h/category variants.
- Original public enum `leechCONNECTION_STATE` is0OFFLINE,1INITIALIZED,2CONNECTING,3CONNECTED_CRITICAL,4DISCONNECTING (type52DB4). Separate UE3-facing `LeechState` is0NotInitialized,1Initialized,2ConnectInProgress,3Connected,4Disconnecting,5Offline (type52D3E). Do not merge these states.
- The full341-value enum is not a proof every code remains implemented/current or possible for this game. This SDK contains unrelated service families.
- Actual finished-session response semantics, remote cleanup/isolation, notification adoption, list convergence and protected PI_COUNT effects remain backend/runtime unknowns.
- No evidence establishes actual occurrence of any of these errors in the Tuesday incident. Prior success retCode0 observations remain separate.
