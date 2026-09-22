#!/usr/bin/env python3
"""Stage-5 : correct byte-by-byte reference scan + real disassembly of the SBL
mailbox init function, to recover the actual globals."""
import struct

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
TEXT_START, TEXT_END = BASE, BASE + 0xcfe758
DATA_START = 0xffffffff83720000
MODRM_RIP = {0x05,0x0d,0x15,0x1d,0x2d,0x35,0x3d}

ANCH = {"sdt":0xffffffff82a036b1,"SblDrvSendSx":0xffffffff82ce6207,
        "req mtx":0xffffffff82ceaca8,"req msg cv":0xffffffff82ceac9d,
        "req cv":0xffffffff82ceacb0}

# ---- correct byte-by-byte scan
refs = {k: [] for k in ANCH}
movabs = {k: [] for k in ANCH}
o = 0
while o < len(data) - 10:
    b0, b1, b2 = data[o], data[o+1], data[o+2]
    v = o2v(o)
    if v is not None:
        if b0 in (0x48,0x49,0x4c,0x4d) and 0xb8 <= b1 <= 0xbf:
            imm = struct.unpack_from("<Q", data, o+2)[0]
            for k, va in ANCH.items():
                if imm == va: movabs[k].append(v)
        if b0 in (0x48,0x4c) and b1 in (0x8d,0x8b,0x89) and b2 in MODRM_RIP:
            disp = struct.unpack_from("<i", data, o+3)[0]
            tgt = v + 7 + disp
            for k, va in ANCH.items():
                if tgt == va:
                    refs[k].append((v, {0x8d:"lea",0x8b:"load",0x89:"store"}[b1]))
    o += 1

print("=== correct ref scan ===")
for k in ANCH:
    print(f"  {k!r:14}: lea/load/store={len(refs[k])}  movabs={len(movabs[k])}")
    for (v, kind) in refs[k][:12]:
        print(f"       {kind:5} @ {v:#018x}  koff {v-BASE:#010x}")

# ---- disassemble the req-mtx init function
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    have_cs = True
except Exception:
    have_cs = False
print("\ncapstone available:", have_cs)

TARGET = 0xffffffff82831963
# function start = nearest preceding call target
calls = set()
i = v2o(TEXT_START)
while i < v2o(TEXT_END - 1) - 5:
    if data[i] == 0xE8:
        rel = struct.unpack_from("<i", data, i+1)[0]
        t = o2v(i) + 5 + rel
        if t is not None and TEXT_START <= t < TEXT_END: calls.add(t)
    i += 1
fstart = max([c for c in calls if c <= TARGET], default=TARGET-0x200)
print(f"function containing {TARGET:#018x} starts at {fstart:#018x} (koff {fstart-BASE:#010x})")

if have_cs:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    o = v2o(fstart)
    code = data[o:o+0x300]
    print("\n=== disassembly ===")
    for ins in md.disasm(code, fstart):
        txt = f"{ins.mnemonic} {ins.op_str}"
        star = ""
        if ins.mnemonic.startswith("call"):
            star = "   <-- CALL"
        print(f"  {ins.address:#018x}  {ins.bytes.hex():<18} {txt}{star}")
