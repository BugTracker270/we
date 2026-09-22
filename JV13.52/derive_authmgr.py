#!/usr/bin/env python3
"""Stage-6 : finish the mailbox cluster (SblDrvSendSx) and locate AuthMgr globals."""
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
md.detail = False

def show(vstart, nbytes, label):
    print(f"\n=== {label}  @ {vstart:#018x} ===")
    o = v2o(vstart)
    for ins in md.disasm(data[o:o+nbytes], vstart):
        print(f"  {ins.address:#018x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}")

show(0xffffffff8281bc70, 0x90, "function referencing 'SblDrvSendSx'")

print("\n=== 'AuthMgr' related strings in kernel image ===")
for m in re.finditer(rb"[ -~]{5,}", data):
    s = m.group()
    if b"AuthMgr" in s or b"authmgr" in s or b"AuthMgr" in s:
        v = o2v(m.start())
        if v: print(f"  {v:#018x}  koff {v-BASE:#010x}  {s[:80].decode(errors='replace')}")
