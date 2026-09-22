#!/usr/bin/env python3
"""Stage-9 : locate dmpml4i / dmpdpi / pml4pml4i via the pmap 'dmap' error-string anchor."""
import struct, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

P = r"C:\Users\Kinan\Downloads\czdji0\1352k.elf"
data = open(P, "rb").read()
BASE = 0xffffffff82200000
segs = []
for i in range(6):
    t, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", data, 0x40 + i*56)
    segs.append((t, off, va, fsz, msz))
def v2o(v):
    for t, off, va, fsz, msz in segs:
        if t == 1 and va <= v < va + fsz: return off + (v - va)
    return None
def o2v(o):
    for t, off, va, fsz, msz in segs:
        if t == 1 and off <= o < off + fsz: return va + (o - off)
    return None
md = Cs(CS_ARCH_X86, CS_MODE_64)

DMAP_STR = 0xffffffff8298428d
print("all RIP-relative refs to the 'pte@(dmap:...' error string:")
refs = []
o = 0
while o < len(data) - 7:
    b0, b1, b2 = data[o], data[o+1], data[o+2]
    if b0 in (0x48, 0x4c) and b1 in (0x8d, 0x8b) and b2 in {0x05,0x0d,0x15,0x1d,0x2d,0x35,0x3d}:
        disp = struct.unpack_from("<i", data, o+3)[0]
        v = o2v(o)
        if v and v + 7 + disp == DMAP_STR:
            refs.append(v)
    o += 1
print("  ", [hex(r) for r in refs])

def fstart(v):
    oo = v2o(v)
    for back in range(0x1000):
        if data[oo-back:oo-back+3] == b"\x55\x48\x89\xe5":
            return o2v(oo-back)
    return None

if refs:
    v0 = refs[0]
    fs = fstart(v0) or (v0 - 0x300)
    print(f"\nfunction start: {fs:#018x}  (koff {fs-BASE:#010x})")
    print("scanning the whole function for GLOBAL (>=.data) and .text fn-ptr refs...\n")
    oo = v2o(fs)
    end = min(oo + 0x3000, len(data))
    found = []
    for ins in md.disasm(data[oo:end], fs):
        s = f"{ins.mnemonic} {ins.op_str}"
        m = re.search(r"\[rip \+ (0x[0-9a-f]+)\]", s)
        if m:
            tgt = ins.address + ins.size + int(m.group(1), 16)
            if tgt >= 0xffffffff83720000:
                found.append((ins.address, ins.mnemonic, tgt))
        if ins.mnemonic == "ret":
            break
    print(f"  {len(found)} global refs:")
    for a, mn, t in found[:60]:
        print(f"   @{a:#018x}  {mn:5} -> koff {t-BASE:#010x}   ({t:#018x})")
