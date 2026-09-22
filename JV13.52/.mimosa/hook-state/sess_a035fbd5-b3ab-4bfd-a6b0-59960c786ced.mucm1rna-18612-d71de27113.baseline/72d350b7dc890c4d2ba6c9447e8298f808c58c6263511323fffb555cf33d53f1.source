"""Walk the SBL module-descriptor pointer graph inside the dumped arena window."""
import struct

DUMP = r'C:\Users\Kinan\Downloads\JV13.52\v12_kmem_img.bin'
BASE = 0xffffc18716000000
d = open(DUMP, 'rb').read()


def show(va, span=0x50):
    fo = va - BASE
    if fo < 0 or fo + 8 > len(d):
        print(f"--- 0x{va:x}  OUTSIDE dumped window ---")
        return
    print(f"--- 0x{va:x} (file 0x{fo:x}) ---")
    for i in range(0, span, 16):
        row = d[fo + i:fo + i + 16]
        hx = ' '.join(f'{b:02x}' for b in row)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
        print(f"  0x{va+i:016x}  {hx}  {asc}")
    print()


print("=== descriptor at 0xffffc18716072780: what do its pointers lead to? ===\n")
for target in (0xffffc18716076f00, 0xffffc18716076f20, 0xffffc1871604e180,
               0xffffc18715b5e300, 0xffffc18715b5e320):
    show(target)

print("=== second-level: pointers found at 0xffffc18716076f00 ===\n")
fo = 0xffffc18716076f00 - BASE
if 0 <= fo < len(d) - 0x40:
    ptrs = [struct.unpack_from('<Q', d, fo + i)[0] for i in range(0, 0x40, 8)]
    for i, v in enumerate(ptrs):
        print(f"  +0x{i*8:02x}  0x{v:016x}")
    for v in ptrs:
        if 0xffffc00000000000 <= v < 0xffffc20000000000:
            show(v, 0x30)
