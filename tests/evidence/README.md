# PR3 production-profile byte evidence

These small uppercase-hex files were independently extracted on September 13,
2026 from the preserved physical full-dump PR3 executable only after its entire
in-memory file read matched SHA-256
`0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393`.
No full executable, dump, configuration or player data is copied here.

| File | RVA | Physical file offset | Decoded bytes |
|---|---:|---:|---:|
| pr3-recon-function.hex | B452D0 | B446D0 | 641 |
| pr3-recon-constant.hex | 12891B0 | 12881B0 | 16 |
| pr3-startup-0.hex | D27C90 | D27090 | 18 |
| pr3-startup-1.hex | D27CA4 | D270A4 | 319 |
| pr3-startup-2.hex | D27DE3 | D271E3 | 5 |
| pr3-startup-3.hex | D281A6 | D275A6 | 6 |
| pr3-startup-4.hex | E72D30 | E72130 | 12 |
| pr3-startup-5.hex | A69EF0 | A692F0 | 31 |

`production_profile_tests.cpp` reads these bytes independently of the compiled
profile arrays, compares both exact preserved stock and full-dump sources, and
recreates `pr3-profile-audit.txt`. It walks every base-relocation block through
the bounded PE reader, requires the initializer-table slot's DIR64 relocation,
and rejects any relocation overlapping the six startup spans, complete recon
function, operand, or constant vector. It also checks physical section access,
the CRT table/call/return/state relationships, the named X3 IAT slot, the exact
CVTTSS2SI opcode and the expected corrected function hash after changing only
the four-byte displacement in a local vector. Three byte values differ because
the displacement's high zero byte stays zero.

This is static evidence. It does not execute either preserved executable or
claim runtime startup, protection, gameplay or EOS/EAC compatibility. The prior
native arithmetic result remains separate evidence; these tests do not repeat
that exhaustive computation.
