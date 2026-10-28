"""Embed an explicitly selected native-logging inventory; never execute a PE."""
import argparse
import hashlib
import json
from pathlib import Path

HOST = "0d8f3222ad796b024fb525118658bb1ce946e4357e35ba6e5ecd127883757393"

def generate(document, digest):
    if document.get('schema') != 2 or document.get('host_sha256', '').lower() != HOST:
        raise ValueError('Unsupported host/inventory schema')
    spans, pointers, exceptions, imports = [document[k] for k in
        ('spans', 'pointer_recipes', 'exceptions', 'imports')]
    if not (0 < len(spans) <= 128 and 0 < len(pointers) <= 32 and
            0 < len(exceptions) <= 64 and 0 < len(imports) <= 16):
        raise ValueError('Native profile bound exceeded')
    lines = ['// Mechanically generated; expected native inputs, not native-call approval.',
             f'// Inventory SHA256: {digest}', f'// Host SHA256: {HOST}',
             f'constexpr char kNativeInventorySha256[] = "{digest.upper()}";']
    ranges = []
    total = len(pointers) * 8 + len(exceptions) * 12 + len(imports) * 8
    for index, item in enumerate(spans):
        data = bytes.fromhex(item['expected_hex'])
        rva, size, kind = item['rva'], item['size'], item['kind']
        if (not 0 < rva < 0xffffffff or not 0 < size <= 8192 or len(data) != size or
                kind not in ('code', 'immutable') or
                hashlib.sha256(data).hexdigest() != item['sha256'].lower()):
            raise ValueError('Invalid byte selector')
        ranges.append((rva, rva + size))
        total += size
        lines.append(f'constexpr std::uint8_t kNativeBytes{index}[] = {{')
        for offset in range(0, size, 16):
            lines.append('    ' + ','.join(f'0x{b:02x}' for b in data[offset:offset+16]) + ',')
        lines.append('};')
    ordered = sorted(ranges)
    if total > 65536 or any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
        raise ValueError('Overlapping or oversized profile')
    lines.append('constexpr ReportingSpan kNativeSpans[] = {')
    for index, item in enumerate(spans):
        kind = 'Code' if item['kind'] == 'code' else 'ImmutableData'
        lines.append(f'    {{{{0x{item["rva"]:X},sizeof(kNativeBytes{index}),kNativeBytes{index}}},SpanKind::{kind}}},')
    lines.append('};\nconstexpr PointerRvaRecipe kNativePointers[] = {')
    occupied = list(ranges)
    for item in pointers:
        slot, target = item['slot_rva'], item['target_rva']
        if (slot & 7 or not slot or not target or item['relocation_type'] != 10 or
                item['width'] != 8 or any(a < slot + 8 and slot < b for a, b in occupied)):
            raise ValueError('Invalid pointer recipe')
        occupied.append((slot, slot+8))
        lines.append(f'    {{0x{slot:X},0x{target:X}}},')
    lines.append('};\nconstexpr RuntimeFunctionRecipe kNativeExceptions[] = {')
    for item in exceptions:
        slot, begin, end, unwind = [item[k] for k in ('entry_rva','begin_rva','end_rva','unwind_rva')]
        if (slot & 3 or unwind & 3 or not begin < end or
                bytes.fromhex(item['expected_hex']) != b''.join(v.to_bytes(4, 'little') for v in (begin,end,unwind)) or
                any(a < slot+12 and slot < b for a, b in occupied)):
            raise ValueError('Invalid exception recipe')
        occupied.append((slot,slot+12))
        lines.append(f'    {{0x{slot:X},0x{begin:X},0x{end:X},0x{unwind:X}}},')
    lines.append('};\nconstexpr PumpImportRecipe kNativeImports[] = {')
    for item in imports:
        slot, module, name = item['slot_rva'], item['module'], item['name']
        cpp_throw = module.lower() == 'msvcp110.dll' and name in (
            '?_Xout_of_range@std@@YAXPEBD@Z', '?_Xlength_error@std@@YAXPEBD@Z', '?_Xbad_alloc@std@@YAXXZ')
        plain_import = module.lower() in ('kernel32.dll','advapi32.dll','msvcr110.dll') and name and all(
            c.isascii() and (c.isalnum() or c == '_') for c in name)
        if (slot & 7 or not (cpp_throw or plain_import) or
                any(a < slot+8 and slot < b for a, b in occupied)):
            raise ValueError('Invalid named import')
        occupied.append((slot,slot+8))
        lines.append(f'    {{0x{slot:X},"{module}","{name}"}},')
    lines.extend(['};', 'constexpr NativeLoggingProfile kNativeProduction{',
        '    {kNativeSpans,std::size(kNativeSpans),kNativePointers,std::size(kNativePointers),',
        '     kNativeExceptions,std::size(kNativeExceptions),kNativeImports[0]},',
        '    kNativeImports,std::size(kNativeImports)', '};', ''])
    return '\n'.join(lines)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    data = args.inventory.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != args.expected_sha256.lower():
        raise SystemExit('Inventory hash does not match the selected input')
    output = generate(json.loads(data.decode('utf-8-sig')), digest)
    if args.check:
        if args.output.read_text(encoding='utf-8') != output:
            raise SystemExit('Native profile differs from selected input')
    else:
        with args.output.open('x', encoding='utf-8', newline='\n') as stream:
            stream.write(output)
    print('Native profile input/generation verified: ' + digest)

if __name__ == '__main__':
    main()
