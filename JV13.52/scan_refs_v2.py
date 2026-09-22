#!/usr/bin/env python3
"""Stage-4 : include movabs (48 B8+r imm64) reference form + dump the lock-name table."""
import struct, re

P = r"C:\Users\Kinan\Downloads\czdji0\1352k.elf"
data = open(P, "rb").read()
BASE = 0xffffffff82200000
e_phoff, e_phnum = 0x40, 6
segs = []
for i in range(e_phnum):
    t, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", data, e_phoff + i*56)
    segs.append((t, off, va, fsz, msz))
def v2o(v):
    for t, off, va, fsz, msz in segs:
        if t == 1 and va <= v < va + fsz: return off + (v - va)
    return None
def o2v(o):
    for t, off, va, fsz, msz in segs:
        if t == 1 and off <= o < off + fsz: return va + (o - off)
    return None

ANCH = {"sdt":0xffffffff82a036b1,"SblDrvSendSx":0xffffffff82ce6207,
        "req mtx":0xffffffff82ceaca8,"req msg cv":0xffffffff82ceac9d,
        "req cv":0xffffffff82ceacb0}

# ---- movabs r64, imm64  = REX.W (48/49/4C/4D) B8..BF imm64
print("=== movabs imm64 references to anchors (whole file) ===")
moved = {k: [] for k in ANCH}
for i in range(len(data) - 10):
    b = data[i]
    if b in (0x48, 0x49, 0x4c, 0x4d) and 0xb8 <= data[i+1] <= 0xbf:
        imm = struct.unpack_from("<Q", data, i+2)[0]
        for k, va in ANCH.items():
            if imm == va:
                v = o2v(i)
                moved[k].append(v)
for k in ANCH:
    print(f"  {k!r:14}: {len(moved[k])} site(s) {[hex(x) for x in moved[k] if x]}")

# ---- full lock-name table around 0x82ce6207 / 0x82ceac9d
def strings_near(vaddr, before=0x40, after=0x200):
    o = v2o(vaddr - before)
    blob = data[o:o+before+after]
    return re.findall(rb"[\x20-\x7e]{4,}", blob)
print("\n=== printable strings around 'SblDrvSendSx' ===")
for s in strings_near(0xffffffff82ce6207, 0x80, 0x140):
    print("   ", s.decode(errors="replace"))
print("\n=== printable strings around 'req msg cv'/'req mtx' ===")
for s in strings_near(0xffffffff82ceac60, 0x80, 0x140):
    print("   ", s.decode(errors="replace"))

# ---- what calls / references the sdt holders?
print("\n=== code refs (lea/load/movabs) to the sdt-holder rodata area 0x82ea1c80 ===")
MODRM_RIP = {0x05,0x0d,0x15,0x1d,0x2d,0x35,0x3d}
hits = []
for i in range(0, len(data) - 7):
    b0,b1,b2 = data[i], data[i+1], data[i+2]
    if b0 in (0x48,0x4c) and b1 in (0x8d,0x8b) and b2 in MODRM_RIP:
        disp = struct.unpack_from("<i", data, i+3)[0]
        v = o2v(i)
        if v is None: continue
        tgt = v + 7 + disp
        if 0xffffffff82ea1c00 <= tgt <= 0xffffffff82ea1d00:
            hits.append((v, tgt))
print("   count:", len(hits))
for v,t in hits[:20]:
    print(f"   @ {v:#018x} -> {t:#018x}  koff {t-BASE:#010x}")
