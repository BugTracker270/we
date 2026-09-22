#!/usr/bin/env python3
"""Stage-12 : derive the SM request wrapper signature from its body + call sites."""
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
    e = data.find(b"\x00", o, o+90)
    if e < 0: return None
    s = data[o:e]
    if len(s) >= 3 and all(32 <= c < 127 for c in s): return s.decode()
    return None

def callsites(target):
    out = []
    for i in range(0, len(data) - 5):
        if data[i] == 0xE8:
            rel = struct.unpack_from("<i", data, i+1)[0]
            v = o2v(i)
            if v is not None and v + 5 + rel == target:
                out.append(v)
    return out

def show(vstart, n, label, stop_ret=True):
    print(f"\n===== {label} @ {vstart:#018x} =====")
    o = v2o(vstart)
    for ins in md.disasm(data[o:o+n], vstart):
        s = f"{ins.mnemonic} {ins.op_str}"
        note = ""
        m = re.search(r"\[rip \+ (0x[0-9a-f]+)\]", s)
        if m:
            tgt = ins.address + ins.size + int(m.group(1), 16)
            st = cstr(tgt)
            if st: note = f'   -> "{st}"'
            elif tgt >= 0xffffffff83720000: note = f"   -> GLOBAL koff {tgt-BASE:#010x}"
            else: note = f"   -> {tgt:#018x}"
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            note += "  <-- CALL"
        print(f"  {ins.address:#018x}  {s}{note}")
        if stop_ret and ins.mnemonic == "ret":
            break

WRAP = 0xffffffff8283fff0
show(WRAP, 0x140, "SM request wrapper")
cs = callsites(WRAP)
print(f"\ncall sites of the wrapper: {[hex(c) for c in cs]}")
for c in cs[:4]:
    show(c - 0x50, 0x58, f"args at call site {c:#018x}")

print("\n\n########## sceSblServiceMailbox ##########")
MB = 0xffffffff82830230
show(MB, 0x120, "sceSblServiceMailbox entry")
cs2 = callsites(MB)
print(f"\ncall sites of sceSblServiceMailbox: {[hex(c) for c in cs2]}")
for c in cs2[:3]:
    show(c - 0x50, 0x58, f"args at call site {c:#018x}")
