#!/usr/bin/env python3
import sys

SELF = sys.argv[1] if len(sys.argv) > 1 else \
    r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\80010008.self'
d = open(SELF, 'rb').read()

for base in (0x00, 0x80, 0x100):
    print(f"--- {base:#06x} ---")
    for o in range(base, base + 0x80, 0x10):
        hx = ' '.join(f'{b:02x}' for b in d[o:o + 0x10])
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in d[o:o + 0x10])
        print(f"  {o:04x}  {hx}  {asc}")
    print()

print("segments (entries at 0x20 + i*0x20)")
n = int.from_bytes(d[0x18:0x1a], 'little')
for i in range(min(n, 5)):
    o = 0x20 + i * 0x20
    props = int.from_bytes(d[o:o + 4], 'little')
    off = int.from_bytes(d[o + 8:o + 16], 'little')
    fsz = int.from_bytes(d[o + 16:o + 24], 'little')
    msz = int.from_bytes(d[o + 24:o + 32], 'little')
    print(f"  seg{i}: props={props:#010x} off={off:#x} filesz={fsz:#x} memsz={msz:#x}")

print()
print(f"u16[hdr+0xb8] = {int.from_bytes(d[0xb8:0xba],'little'):#x}")
print(f"u32[hdr+0x90] = {int.from_bytes(d[0x90:0x94],'little'):#x}")
print(f"byte[hdr+0x110] = {d[0x110]:#04x}")
print(f"byte[hdr+0x120] = {d[0x120]:#04x}")
print()
print("every plausible 0x38-stride table header in 0x80..0x160:")
for o in range(0x80, 0x160, 0x10):
    v = int.from_bytes(d[o:o + 2], 'little')
    if v and v < 0x40:
        print(f"  u16[{o:#05x}] = {v}   ({v} * 0x38 = {v*0x38:#x}, align16 +0x4f = {(v*0x38+0x4f) & ~0xf:#x})")
