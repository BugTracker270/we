#!/usr/bin/env python3
"""Stage-8 : auto-resolve lea targets -> SBL driver globals; then chase dmap/pmap globals."""
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

def cstr(v):
    o = v2o(v)
    if o is None: return None
    e = data.find(b"\x00", o, o+80)
    if e < 0: return None
    s = data[o:e]
    if all(32 <= c < 127 for c in s) and len(s) >= 3:
        return s.decode()
    return None

def func_start(v):
    o = v2o(v)
    for back in range(0, 0x1000):
        if data[o-back:o-back+3] == b"\x55\x48\x89\xe5":
            return o2v(o-back)
    return None

def scan(vstart, n, label):
    print(f"\n===== {label}  @ {vstart:#018x} (koff {vstart-BASE:#010x}) =====")
    o = v2o(vstart)
    globs = []
    for ins in md.disasm(data[o:o+n], vstart):
        s = f"{ins.mnemonic} {ins.op_str}"
        note = ""
        m = re.search(r"\[rip \+ (0x[0-9a-f]+)\]", s)
        if m:
            disp = int(m.group(1), 16)
            tgt = ins.address + ins.size + disp
            st = cstr(tgt)
            if st: note = f'   -> STR "{st}"'
            elif tgt >= 0xffffffff83720000:
                note = f"   -> GLOBAL koff {tgt-BASE:#010x}"
                globs.append((ins.address, tgt))
            else:
                note = f"   -> {tgt:#018x}"
        print(f"  {ins.address:#018x}  {s}{note}")
    return globs

scan(0xffffffff8281bc50, 0x120, "SblDrvSendSx-region init (SBL driver)")
