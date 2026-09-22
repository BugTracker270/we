#!/usr/bin/env python3
"""Stage-11 : disassemble the AuthMgr finalize/start path, where orbital dereferences
*sceSblAuthMgrModuleId, and locate sceSblServiceMailbox."""
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

def show(vstart, n, label):
    print(f"\n===== {label} @ {vstart:#018x} =====")
    o = v2o(vstart)
    for ins in md.disasm(data[o:o+n], vstart):
        s = f"{ins.mnemonic} {ins.op_str}"
        note = ""
        m = re.search(r"\[rip(?: \+| -) (0x[0-9a-f]+)\]", s)
        if m:
            disp = int(m.group(1), 16)
            if " - " in s: disp = -disp
            tgt = ins.address + ins.size + disp
            st = cstr(tgt)
            if st: note = f'   -> "{st}"'
            elif tgt >= 0xffffffff83720000: note = f"   -> GLOBAL koff {tgt-BASE:#010x}"
            else: note = f"   -> {tgt:#018x}"
        if ins.mnemonic == "call": note += "  <-- CALL"
        print(f"  {ins.address:#018x}  {s}{note}")

# --- refs to sceSblServiceMailbox strings
print("refs to SceSblServiceMailbox strings:")
for sv, nm in ((0xffffffff82cea66e, "bare name"),
               (0xffffffff82ceceab, "ERROR site A"),
               (0xffffffff82ced738, "ERROR site B")):
    rs = []
    o = 0
    while o < len(data) - 7:
        b0, b1, b2 = data[o], data[o+1], data[o+2]
        if b0 in (0x48, 0x4c) and b1 in (0x8d, 0x8b, 0x89) and b2 in {0x05,0x0d,0x15,0x1d,0x2d,0x35,0x3d}:
            disp = struct.unpack_from("<i", data, o+3)[0]
            v = o2v(o)
            if v and v + 7 + disp == sv: rs.append(v)
        o += 1
    print(f"   {nm:12} {sv:#018x}: {[hex(r) for r in rs]}")

show(0xffffffff8283ff40, 0x120, "function containing _sceSblAuthMgrSmFinalize ref (0x8283ff9f)")
show(0xffffffff82842d70, 0x140, "sceSblAuthMgrAuthHeader region (0x82842d92)")
show(0xffffffff8283d9c0, 0x120, "sceSblServiceMailbox CALLER (0x8283d9ee)")
