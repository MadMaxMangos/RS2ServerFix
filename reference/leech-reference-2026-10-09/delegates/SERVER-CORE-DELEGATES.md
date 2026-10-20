# Current server core status and component consumers

> Archived 9 October 2026 analysis. See the [publication scope](../FAILURE-CATALOGUE.md).
> Supporting artifacts and further notes cited below remain in the private archive;
> their names are provenance references, not files bundled with this repository.

2026-10-09. Offline read-only investigation. No database tools, live process,
server/backend calls, code changes or tests. All new material is in this unique
system-temporary directory. Address shorthand below is an RVA unless prefixed
with 0x140/0x141. Descriptive names are inferred from code and log strings, not
claimed current-build PDB symbols.

## Identity and byte evidence

Target: D:/Documents/RisingStorm2/Binaries/Server/VNGame_pr3.exe

SHA256: 0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393

AMD64; preferred base 0x140000000; SizeOfImage 0x1A12000.

Source refs below mean D:/Documents/RisingStorm2/Binaries/Server/VNGame_pr3.exe.asm.
Fresh export SHA256 E98DD1EDA8715D20CC7C4A6D5F0E3AA7A1AA8616040083B05A3AF3F3B30E488A.
LST SHA256 F81D49959AAE61EA276DEDF082F8726BB341F5F721CC7423CBD61FEDC72401EA.
MAP SHA256 778271EBE91ADE52679C03E7DA93094B1E63191E40A3349F57928DC184C57354.

`bodies.json` contains independently decoded file-backed bytes, hashes, pdata
records where exact-start records exist, and corresponding numbered ASM text.
`extract.py` uses pefile fast_load and Capstone. Leaf spans use the next exported
sub_ procedure as an upper bound and include alignment; these are explicitly
labelled and are not claims about language function/unwind extents. Pdata spans
also do not automatically include every C++ funclet. No global addresses are
transferred from a client or historical build.

## Decisive conclusions

1. The core status callback has a positively resolved stock consumer. A494A0
   installs A599F0 via BA5BA0 into qword14179D398; BA5AE0 tail-jumps that slot.
   This is separate from the optional standalone-status slot14179D3C8.
2. The logged `Everything is on-line` is the core's category-1 readiness event,
   not proof all services or memberships are healthy. BF6240 can emit it before
   the same invocation starts dependent components, including StandaloneServer.
3. A server offline event0 updates adapter state to5, terminates the native core,
   and starts a 10.0 caller-delta-second reconnect countdown. Subsequent adapter
   tick reinitializes and enables environment discovery from states1/5. This is
   a concrete stock recovery chain, not proof that any incident took it.
4. StandaloneServer errors can stop only that component without whole-core
   offline notification. Component category3 and error-policy category5 are
   different namespaces; their meanings must not be conflated.
5. No nonzero stock binding of optional standalone slot14179D3C8 was identified.
   Therefore no extra game/cache clearing callback may be assumed from it.
   Bounded explicit-reference evidence is not proof that arbitrary indirect or
   external writes are impossible, or proof of a live null value.

## Callback registration and consumers

At A494A0, command-line `server` selection is stored in byte141798621. Init then
constructs two two-pointer callback structures:

| Installed slot | Consumer | Purpose demonstrated by body |
| --- | --- | --- |
| 14179D390 | A59880 | Assertion callback, converts supplied condition/file text and logs; returns false. No reference-reader found in the explicit RIP scan. |
| 14179D398 | A599F0 | Core connection-status consumer described below. |
| 14179D3A0 | A59DD0 via BA5AB0 | Fills login/provider output strings. Server-role branch copies persistent configured values; client-role branch uses separate EOS-associated cached fields. No new ticket acquisition is in this body. |
| 14179D3A8 | A5A170 via BA5AC0 | Fills alternate/test provider outputs, including TEST and empty fields; not a connection-status notification. |
| 14179D3B0/B8/C0/C8/D0 | no nonzero stock binding found | Optional callback readers BA5B50/BA5B30/BA5B10/BA5B70/BA5AF0 each null-check before tail call. |

Source: ASM3630411-3630434 (registration), 3655300-3655471 (assert),
3655893-3656336 (credential/provider callbacks), 4109405-4109517 (readers/setters),
5247476-5247487 (E77400 zero initialization).

`callback-region-explicit-refs.json` records19 decoded explicit RIP references
to 14179D380..14179D3DF across executable sections, including initialization and
the16-byte registration stores. It corroborates the source references. Method
is linear decoding with skipdata; computed/base-relative/foreign writes are not
covered by a negative conclusion.

## Core status callback A599F0

Input: ECX notification state, EDX error code, R8 message. The positive core
producer BA53A0 changes dword1414AAB74 only when state changes, accepts0..4,
then forwards the triple through BA5AE0. The callback is installed before
server/client-role branching in adapter init.

| Notification | Dedicated-server behavior |
| --- | --- |
| 1 | Logs initialized; does not set adapter state1 itself. |
| 2 | Logs connecting; adapter connection helper independently sets2. |
| 3 | Logs core online/provider and KSIVA; takes server branch and sets adapter dword141798650=3. The client-only B9CF60/A5DF10-related branch is skipped. |
| 4 | Logs disconnect error/message; sets adapter state4. |
| 0 | Logs offline; sets adapter state5; calls BA58C0; loads10.0 into float1417986DC from file constant EC6550. |
| other | Logs numeric state only. |

No stock dedicated-server branch here calls A53560, changes game adapter session
cache1414A4A08, sends control33, or replays player/game presence notifications.
This is a statement about the inspected complete body, not all transitive
behavior of logging/allocators or external hooks.

Source: ASM3655511-3655580,3655656-3655870; BA53A0 at4108796-4108864.
Re-read float EC6550 directly from the authenticated PE:10.0.

## Positive reconnect chain

A34180 calls A4B2F0, later A49430, and only then tail-jumps Steam callback pump
A34910. On dedicated server A4B2F0 subtracts tick delta from positive countdown,
calls A48990, and ticks BA59D0 whenever adapter state is nonzero.

A48990 permits connection initiation only in adapter states1 or5 and only when
countdown is not positive. It calls genuine BA5590 initialization then BA87B0
environment-discovery setup, passing A5A200 as notification callback, and sets
adapter state2. A5A200 only logs its success/error notification; it is not the
core-status callback and does not independently reset adapter state.

BA87B0 enables an environment-discovery polling object. BA8920 sets its stored
interval to5000ms on an empty result and60000ms on a nonempty result; BA8B20
resets the interval to5000ms on most errors. This does not establish an actual
wall-clock request/completion deadline. Thus the fact that adapter
state2 does not rerun A48990 does not itself establish a stuck connection.
Upon successful environment selection BA8920 calls BF72A0, which sets desired
online byte1417AA9D2=1 and publishes core notification2 through BA53A0.
The polling machinery remains a separate retry clock from the adapter countdown.

Source: ASM3598692 and independently decoded A34180; 3633048-3633078;
3629239-3629388; 3656343-3656442; 4113721-4114003; 4227445-4227451.

## State namespaces and component table

| Storage | Namespace |
| --- | --- |
| byte141798621 | Adapter command-line server-role flag. |
| dword141798650 | Adapter login/recovery state0..5, not native core raw state. |
| float1417986DC | Adapter reconnect countdown in supplied tick delta. |
| dword1414AAB70 | Native core operating phase:1 normal update,2 shutdown drain,0 terminated. |
| dword1414AAB74 | Core connection-status notification state0..4. |
| byte1417AA9D2 | Task/component desired-online flag. |
| bytes1417AA9D0/D1 | Previous critical-ready and previous desired-online snapshots. |
| dword1417AEA10 | AuthorizationComponent raw state; BFC510 maps raw7 to component status1; raw1..6 to2; others to0. |
| byte1417AEB78 | Authorization role field returned by BFCDC0; not raw auth completion. |
| dword1414AAD20 | Standalone raw state0..4; BAB350 maps raw3→component1, raw1/2→component2, raw4→component3, otherwise0. |

Component table begins1417AA9F8,16 slots of0x28. Each slot stores start+0,
stop+8,status+0x10,name+0x18,component category+0x20. BF7A90 copies a descriptor
into the first slot whose category is0; no slot availability status is returned.

| Component | Current component category | Start / stop / status RVAs |
| --- | ---: | --- |
| AsyncDeferOperationsComponent | 1 | BA4C40 / BA4C90 / BA4CE0 |
| AuthorizationComponent | 1 | BFBB70 / BFC4E0 / BFC510 |
| FactComponent | 2 | BAE3E0 / BAE400 / BAE420 |
| StandaloneServer | 3 | BAB210 / BAB230 / BAB350 |
| Presence | 3 | BFAA50 / BFAC40 / BFAD60 |
| UserHeartbeatComponent | 3 | C09A30 / C09BA0 / C09C60 |
| MessagingComponent | 3 | C0A7F0 / C0AB20 / C0AE60 |
| GlobalEssentialComponentHack | 4 | BF60A0 / BF60A0 / BF6090; registered inline by BF7830 |

There are seven positive literal BF7A90 registration calls plus the eighth
inline registration in BF7830, found by the root investigator and independently
byte-verified in INLINE-COMPONENT-TEARDOWN.md. BF6090 loads a field initialized1;
BF60A0 is a no-op. Category4 is not a critical category1 contributor. These eight
positive stock registrations do not prove that no other dynamic registration can
occur. Registration initializer
bodies and material status leaves were independently decoded in bodies.json.
Source: ASM4108400-4108411;4115790-4115801;4121454-4121465;
4232448-4232460;4235486-4235498;4254342-4254354;4256049-4256061;
4228261-4228289 (slot layout/copy).

## Dispatcher and error escalation

BF6240 first checks only component-category1 entries and requires each status
callback return1 for critical-ready. If desired-online is true and critical
readiness newly becomes true, it emits BA53A0(3,0,empty) BEFORE the component
start/stop pass. This is the source of `Everything is on-line`.

If previously desired-online becomes false, or critical-ready drops after being
true, it invokes BF6EC0 task cancellation and BA5450 shutdown. BA5450 changes
core1→2, publishes notification4, begins shutdown work. BA59D0 core2 continues
task/component pump and drains completion work; when C00AA0 returns false it
publishes0 and terminates BA58C0. That drain predicate's full internal semantics
were not independently audited in this subtask. The adapter callback then
permits the timed full-core reconnect above. BA58C0 also terminates standalone,
authorization and other components; it is broader than manual session repair.

The second pass selects desired state:

- Component-category1 follows desired-online alone.
- Any other nonzero component category follows desired-online AND critical-ready.
- Desired true and status0 calls registered start.
- Desired false and status1/2 calls registered stop; status3 is already stopping.

Source: ASM4226046-4226200,4227078-4227112,4108871-4108915,
4109327-4109385,4109265-4109316. BF8130 pumps tasks before BF6240.

Error route BF6420 can pass a task's component-name pointer,error and text to
BF8160 (ASM4226827-4226833). BF8160 resolves the registered component by pointer
and makes these decisions:

- Component-category1 OR error-policy category5: BF79B0 whole-session disconnect.
- Otherwise component-category3: cancel/dispose matching-component tasks or mark
  inflight states4/5 as5, call registered stop, then BFCE70 resets one auth scalar.
- Component-category4: log ignored component disconnect, then BFCE70.
- Component-category2: no separate stop branch here if error-policy category5
  did not apply. This is not a claim that a preceding handler did nothing.

StandaloneServer is component-category3, so it can stop/restart without a core
offline event. Once its stop path completes to status0, the still-online
dispatcher can start it again. A subsequent actual Create still depends on the
game registration path and readiness; start itself only performs raw0→1.

Source: ASM4228892-4229013; BF79B0 at4228173-4228254. The101-entry error-policy
table1279C20..1279F48 was independently read only to qualify the category5 edge;
taxonomy and historical table comparison belong to the separate error audit.
Do not conflate error-policy categories with component categories.

Direct whole-session disconnect callers also include explicit BA54E0, an
authorization no-endpoint path, authorization check-policy/update-policy paths,
and UserHeartbeat version-data mismatch. These are positive routes, not an
incident explanation (ASM4108920-4108928,4234416-4234425,4234920-4234929,
4235120-4235126,4254811-4254819).

## Relation to standalone recreation and remaining gaps

The core online callback on the server sets its adapter state but does not itself
force Create or clear the separate game session cache. A34180 also calls
A49430→A550B0. Metadata wrapper A52070 can call A53560 directly or arm countdown
141798A04, whose positive-to-nonpositive crossing in A550B0 calls A53560. Current
A53560 clears game cache only when public getter BA9420 returns0 (raw0 or raw1), before an attempted Create that still requires raw1; its already-
active branch refreshes metadata/Members. No new claimed cache-invalidation
delegate was found. Source: ASM3630243-3630263,3643758-3643767,
3648234-3648245; previously closed A53560 logic3645529 onward.

The parent's independently verified historical finding is that FactComponent
changed component-category1→2. Current semantics above establish that category2
is dependent on critical readiness but does not contribute to it. Historical
dispatcher/error bodies must also be checked before promoting this into a
complete cross-build error-policy claim. No effect on protected count follows.

Still open / limits:

- Prove historical names/enums and matching dispatcher semantics separately.
- Establish actual incident transition sequence: component-local stop versus
  full core shutdown/reconnect versus unchanged core with stale projection.
- No runtime pointer/slot/global values were read in this task.
- No positive nonzero binding for optional callbacks3B0..3D0; computed/foreign
  writes remain a bounded static-analysis limitation.
- Metadata/caller cadence and network sender68AC70 are separate analyses; this
  task does not turn source tick structure into delivery/completion deadlines.
- Core recovery does not prove selected client ID adoption, old-membership
  cleanup, protected PI_COUNT repair, authentication/ranking/XP recovery.
