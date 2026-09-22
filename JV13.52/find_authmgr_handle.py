#!/usr/bin/env python3
"""Stage-10 : locate the auth-manager service/module id global ('authmgr_handle')."""
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

# file-backed .data range
DATA_V, DATA_F = 0xffffffff83720000, 0x6065e8
DATA_END = DATA_V + DATA_F

# ---------- A) collect every RIP-relative global ref in .text ----------
REFS = []   # (insn_addr, target)
o = 0
while o < len(data) - 7:
    b0, b1, b2 = data[o], data[o+1], data[o+2]
    if b0 in (0x48, 0x4c) and b1 in (0x8d, 0x8b, 0x89) and b2 in {0x05,0x0d,0x15,0x1d,0x2d,0x35,0x3d}:
        disp = struct.unpack_from("<i", data, o+3)[0]
        v = o2v(o)
        if v is not None:
            REFS.append((v, v + 7 + disp))
    o += 1
print(f"[A] {len(REFS)} RIP-relative refs total")

# ---------- B) file-backed globals whose value == 4 ----------
cand = {}
for off in range(v2o(DATA_V), v2o(DATA_END - 1) - 8, 4):
    if struct.unpack_from("<I", data, off)[0] == 4:
        cand[o2v(off)] = 4
print(f"[B] {len(cand)} dword slots in .data holding the value 4")

# which of them are actually referenced by code?
byref = {}
for (ia, tgt) in REFS:
    if tgt in cand:
        byref.setdefault(tgt, []).append(ia)
print(f"[B] {len(byref)} of them are referenced by code:\n")
for t, sites in sorted(byref.items()):
    print(f"   global {t:#018x}  koff {t-BASE:#010x}   refs={[hex(s) for s in sites[:6]]}")

# ---------- C) enclosing functions of AuthMgr code ----------
AUTH = {"sceSblAuthMgrAuthHeader":0xffffffff82ceda46,
        "_sceSblAuthMgrSmFinalize":0xffffffff82ced2f6,
        "sceSblAuthMgrFinalize":0xffffffff82cedbaf,
        "_sceSblAuthMgrLoadSelfBlock":0xffffffff82cecba3,
        "authmgr":0xffffffff82cecb23,
        "_sceSblAuthMgrSmLoadSelfBlock":0xffffffff82ced3a0}
asites = {}
for name, sv in AUTH.items():
    rs = [ia for (ia, t) in REFS if t == sv]
    asites[name] = rs
    print(f"\n[C] {name!r}: {len(rs)} ref site(s) {[hex(x) for x in rs[:8]]}")

def fstart(v):
    oo = v2o(v)
    if oo is None: return None
    for back in range(0, 0x1000):
        if data[oo-back:oo-back+3] == b"\x55\x48\x89\xe5":
            return o2v(oo-back)
    return None

fs = set()
for name, rs in asites.items():
    for r in rs:
        f = fstart(r)
        if f: fs.add(f)
print(f"\n[C] enclosing function starts ({len(fs)}):")
for f in sorted(fs):
    print(f"   {f:#018x}  koff {f-BASE:#010x}")

# ---------- D) cross-reference: value-4 globals referenced from AuthMgr functions ----------
print("\n[D] value-4 globals whose reference site falls inside an AuthMgr function:")
hit = False
for t, sites in byref.items():
    for s in sites:
        f = fstart(s)
        if f in fs:
            print(f"   *** {t:#018x} (koff {t-BASE:#010x}) referenced at {s:#018x} inside fn {f:#018x}")
            hit = True
if not hit:
    print("   (none)")
