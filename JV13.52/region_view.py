"""Hex + qword view of the region around the one module-name record."""
import struct, sys

DUMP = r'C:\Users\Kinan\Downloads\JV13.52\v11_kmem_img.bin'
KOFF = 0x1520000
d = open(DUMP, 'rb').read()

A = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x2680780
B = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x2680900

print(f"koff 0x{A:x} .. 0x{B:x}\n")
print("--- qwords (aligned) ---")
for a in range(A & ~7, B, 8):
    fo = a - KOFF
    if fo < 0 or fo + 8 > len(d):
        continue
    v = struct.unpack_from('<Q', d, fo)[0]
    tag = ""
    if 0xffffffff80000000 <= v < 0xffffffff85680000 + 0x2834af0:
        tag = "  .image"
    elif 0xffffc00000000000 <= v < 0xffffc20000000000:
        tag = "  arena"
    elif 0xffff800000000000 <= v < 0xffff900000000000:
        tag = "  dmap"
    print(f"  0x{a:08x}  0x{v:016x}{tag}")

print("\n--- hex + ascii ---")
for a in range(A & ~0xf, B, 16):
    fo = a - KOFF
    if fo < 0 or fo + 16 > len(d):
        continue
    row = d[fo:fo + 16]
    hx = ' '.join(f'{b:02x}' for b in row)
    asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
    print(f"  0x{a:08x}  {hx}  {asc}")
