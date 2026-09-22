"""Mechanically embed an explicitly approved reporting inventory, never a PE.

No target execution or analysis dependency is needed. The external inventory is
not packaged. Its path is an input only: generated product data contains hashes,
RVAs and expected bytes, never private evidence paths or native payloads.
"""
import argparse
import hashlib
import json
from pathlib import Path

PARENT_INVENTORY_SHA256 = "4b450f0b57dbf2b2dad70872b21ef5615ccfc639d831ac54c68f12e09b83fdd4"
SCHEDULER_GETTERS = ((0xBF5940, "0fb7410ac3", 0x1276D98),
                     (0xBF5930, "488b4110c3", 0x1276DA8),
                     (0xBF5950, "488b4118c3", 0x1276DB8))


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def generate(document, digest):
    spans = document["selectors"]
    pointers = document["pointer_rva_recipes"]
    exceptions = document["runtime_function_entry_recipes"]
    imports = document["named_import_recipes"]
    if len(spans) != 59 or len(pointers) != 12 or len(exceptions) != 14 or len(imports) != 1:
        raise ValueError("The scheduler-diagnostics profile requires 59/12/14/1 selectors")
    if (document.get("inventory_revision") != 3 or
            document.get("parent_inventory_sha256") != PARENT_INVENTORY_SHA256):
        raise ValueError("The extension must name the unchanged accepted v2 parent")
    # Exactly three whole leaves and vslot recipes extend the accepted profile.
    # No instruction masks, prologue prefixes, or arbitrary new selector family.
    for index, (target, expected, slot) in enumerate(SCHEDULER_GETTERS):
        leaf, pointer = spans[56 + index], pointers[9 + index]
        if (leaf["kind"] != "code" or number(leaf["start_rva"]) != target or
                number(leaf["end_rva_exclusive"]) != target + 5 or
                leaf["expected_hex"] != expected or number(pointer["slot_rva"]) != slot or
                number(pointer["expected_target_rva"]) != target):
            raise ValueError("Unexpected scheduler getter contract")
    output = ["// Mechanically generated; edit the approved inventory, not these bytes.",
              f'// Inventory SHA256: {digest}',
              f'// Parent inventory SHA256: {PARENT_INVENTORY_SHA256}',
              f'// Host SHA256: {document["host_sha256"]}',
              f'constexpr char kInventorySha256[] = "{digest.upper()}";']
    ranges = []
    total = 0
    for index, item in enumerate(spans):
        start = number(item["start_rva"])
        end = number(item["end_rva_exclusive"])
        data = bytes.fromhex(item["expected_hex"])
        if (start <= 0 or end > 0xFFFFFFFF or end - start != len(data) or
                len(data) != item["size"] or not 0 < len(data) <= 8192 or
                item["kind"] not in ("code", "unwind", "literal") or
                item["base_relocations"] or
                hashlib.sha256(data).hexdigest() != item["sha256"].lower()):
            raise ValueError(f"Invalid or relocated byte selector {index}")
        ranges.append((start, end))
        total += len(data)
        output.append(f"constexpr std::uint8_t kReportingBytes{index}[] = {{")
        for offset in range(0, len(data), 16):
            output.append("    " + ",".join(f"0x{v:02x}" for v in data[offset:offset + 16]) + ",")
        output.append("};")
    ordered = sorted(ranges)
    if total != 38927 or total > 65536 or any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
        raise ValueError("Invalid byte budget or overlapping ranges")
    output.append("constexpr ReportingSpan kReportingSpans[] = {")
    for i, item in enumerate(spans):
        kind = "Code" if item["kind"] == "code" else "ImmutableData"
        output.append(f"    {{{{0x{number(item['start_rva']):X},sizeof(kReportingBytes{i}),kReportingBytes{i}}},SpanKind::{kind}}},")
    output.append("};\nconstexpr PointerRvaRecipe kReportingPointers[] = {")
    seen = set()
    for item in pointers:
        slot, target = number(item["slot_rva"]), number(item["expected_target_rva"])
        relocs = item["base_relocations"]
        if (slot in seen or slot & 7 or item["width"] != 8 or not 0 < target < 0xFFFFFFFF or
                len(relocs) != 1 or number(relocs[0]["rva"]) != slot or
                relocs[0]["type"] != 10 or relocs[0]["width"] != 8):
            raise ValueError("Invalid pointer-RVA relocation recipe")
        seen.add(slot)
        output.append(f"    {{0x{slot:X},0x{target:X}}},")
    output.append("};\nconstexpr RuntimeFunctionRecipe kReportingExceptions[] = {")
    seen = set()
    for item in exceptions:
        entry, begin, end, unwind = [number(item[k]) for k in
                                    ("entry_rva", "begin_rva", "end_rva", "unwind_rva")]
        data = bytes.fromhex(item["expected_hex"])
        if (entry in seen or len(data) != 12 or not 0 < begin < end <= 0xFFFFFFFF or
                unwind <= 0 or hashlib.sha256(data).hexdigest() != item["sha256"].lower() or
                data != b"".join(x.to_bytes(4, "little") for x in (begin, end, unwind))):
            raise ValueError("Invalid runtime-function recipe")
        seen.add(entry)
        output.append(f"    {{0x{entry:X},0x{begin:X},0x{end:X},0x{unwind:X}}},")
    imp = imports[0]
    if (number(imp["slot_rva"]) != 0xE95570 or imp["import_module"].lower() != "steam_api64.dll" or
            imp["import_name"] != "SteamGameServer_RunCallbacks"):
        raise ValueError("Wrong server pump import")
    output.extend(["};", "constexpr ReportingProfile kReportingProduction{",
                   "    kReportingSpans, sizeof(kReportingSpans)/sizeof(kReportingSpans[0]),",
                   "    kReportingPointers, sizeof(kReportingPointers)/sizeof(kReportingPointers[0]),",
                   "    kReportingExceptions, sizeof(kReportingExceptions)/sizeof(kReportingExceptions[0]),",
                   '    {0xE95570,"steam_api64.dll","SteamGameServer_RunCallbacks"}', "};", ""])
    return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="Compare existing output without writing")
    args = parser.parse_args()
    data = args.inventory.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != args.expected_sha256.lower():
        raise SystemExit("Inventory SHA256 does not match explicitly approved input")
    content = generate(json.loads(data.decode("utf-8-sig")), digest)
    if args.check:
        if args.output.read_text(encoding="utf-8") != content:
            raise SystemExit("Generated profile differs from approved inventory")
    else:
        # Mechanical generation is deliberate; never overwrite an unrelated file.
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
    print(f"Reporting profile verified: 59 spans, 12 pointers, 14 exception records; inventory {digest}")


if __name__ == "__main__":
    main()
