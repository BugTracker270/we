#!/usr/bin/env python3
"""Read the AuthMgr/SBL state out of the v11 20 MB dump (koff 0x1520000 base)."""
import struct, os

P = r'C:\Users\Kinan\Downloads\JV13.52\v11_kmem_img.bin'
BASE = 0x1520000
d = open(P, 'rb').read()
print(f"{P}: {len(d):,} B  covers koff 0x{BASE:x}..0x{BASE+len(d):x}")

def q(koff, n=8):
    o = koff - BASE
    if o < 0 or o + n > len(d):
        return None
    return d[o:o + n]

def dump(koff, n, label):
    b = q(koff, n)
    if b is None:
        print(f"  {label:<34} koff 0x{koff:08x}  <outside dump>"); return
    print(f"  {label:<34} koff 0x{koff:08x}  {b.hex(' ')}")

dump(0x269C098, 16, 'SM_FLAG(0x98)/.. ')
dump(0x269C0A0, 16, 'AUTHMGR_HANDLE 0x269C0A0')
dump(0x269C0B0, 0x30, 'BUF_A/BUF_B')
dump(0x269C0C8, 0x20, 'SM_MTX 0x269C0C8')
dump(0x269C0E8, 0x20, 'LOCK2 0x269C0E8')
dump(0x269C108, 0x28, 'flag 0x269C108 + status')
dump(0x269C130, 16, 'CTX_STATUS[4] 0x269C130')
dump(0x269C140, 0x60, 'self_contexts[0]')
dump(0x269C1A0, 0x60, 'self_contexts[1]')
dump(0x269C200, 0x60, 'self_contexts[2]')
dump(0x269C260, 0x60, 'self_contexts[3]')
dump(0x269C2C0, 0x20, 'ctx buf base')

print("\ninterpretation")
for i in range(4):
    o = 0x269C130 - BASE + i * 4
    v, = struct.unpack_from('<I', d, o)
    print(f"  ctx_status[{i}] = {v}")
b = q(0x269C0A0, 8)
if b:
    v, = struct.unpack('<Q', b)
    print(f"  module_id (SM handle) = 0x{v:x}")
b = q(0x269C098, 1)
if b:
    print(f"  sm_flag byte = {b[0]}")
b = q(0x269C108, 1)
if b:
    print(f"  flag@0x269C108 byte = {b[0]}")
for i in range(4):
    o = 0x269C140 - BASE + i * 0x60
    fmt, = struct.unpack_from('<I', d, o)
    etyp, = struct.unpack_from('<I', d, o + 4)
    ths, = struct.unpack_from('<I', d, o + 8)
    seg, = struct.unpack_from('<Q', d, o + 0x10)
    cid, = struct.unpack_from('<I', d, o + 0x1c)
    print(f"  ctx[{i}] format={fmt} elfauth=0x{etyp:x} total_hdr=0x{ths:x} seg={seg:#x} ctx_id={cid}")
