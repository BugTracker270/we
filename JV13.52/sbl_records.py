"""Mine the SBL / secure-module bookkeeping region of the dump for load info.

The 19 MB dump contains exactly one secure-module name string, "8001000B", at
koff 0x2680848. If the SBL keeps per-module records anywhere, they are here, and
they should carry a load address and size -- which would let us target the
AuthMgr's decrypted image directly instead of dumping 64 MB of arena blind.
"""
import re, struct

DUMP = r'C:\Users\Kinan\Downloads\JV13.52\v11_kmem_img.bin'
KOFF = 0x1520000
KBASE = 0xffffffff85680000

d = open(DUMP, 'rb').read()


def ko(fo):
    return KOFF + fo


print("=== every '8001' occurrence in the dump ===")
for m in re.finditer(rb'8001[0-9A-Fa-f]{4}', d):
    print(f"  file 0x{m.start():x}  koff 0x{ko(m.start()):x}  {m.group().decode()!r}")

print("\n=== every '80010' occurrence (broader) ===")
for m in re.finditer(rb'80010', d):
    print(f"  file 0x{m.start():x}  koff 0x{ko(m.start()):x}")
