#!/usr/bin/env python3
"""Stage-13 : resolve the public AuthMgr entry points (function starts)."""
import struct
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

# whole-file RIP-relative ref index
REFS = []
o = 0
while o < len(data) - 7:
    b0, b1, b2 = data[o], data[o+1], data[o+2]
    if b0 in (0x48, 0x4c) and b1 in (0x8d, 0x8b, 0x89) and b2 in {0x05,0x0d,0x15,0x1d,0x2d,0x35,0x3d}:
        disp = struct.unpack_from("<i", data, o+3)[0]
        v = o2v(o)
        if v is not None: REFS.append((v, v + 7 + disp))
    o += 1

# call-target set (function-entry evidence)
CALLS = set()
i = 0
lim = v2o(0xffffffff82efe758 - 1)
while i < lim - 5:
    if data[i] == 0xE8:
        rel = struct.unpack_from("<i", data, i+1)[0]
        t = o2v(i) + 5 + rel
        if t is not None and BASE <= t < 0xffffffff82efe758: CALLS.add(t)
    i += 1

def fstart(site, maxback=0x8000):
    oo = v2o(site)
    for back in range(0, maxback):
        if data[oo-back:oo-back+3] == b"\x55\x48\x89\xe5":
            return o2v(oo-back)
    return None

NAMES = {
 "sceSblAuthMgrAuthHeader":0xffffffff82ceda46,
 "sceSblAuthMgrLoadSegment":0xffffffff82cedcd9,
 "sceSblAuthMgrLoadBlock":0xffffffff82cedc57,
 "sceSblAuthMgrFinalize":0xffffffff82cedbaf,
 "sceSblAuthMgrIsLoadable":0xffffffff82ced976,
 "_sceSblAuthMgrSmFinalize":0xffffffff82ced2f6,
 "_sceSblAuthMgrSmStart":0xffffffff82ced06a,
 "_sceSblAuthMgrLoadSelfBlock":0xffffffff82cecba3,
 "_sceSblAuthMgrCheckSelfHeader":0xffffffff82cecd3c,
 "_sceSblAuthMgrSmLoadSelfBlock":0xffffffff82ced3a0,
 "detach_authmgr":0xffffffff82a029a1,
 "authmgrwait":0xffffffff82a02829,
}
print(f"{'symbol':32} {'fn start':18} {'koff':12} calltarget")
for nm, sv in NAMES.items():
    sites = [ia for (ia, t) in REFS if t == sv]
    starts = sorted({fstart(s) for s in sites if fstart(s)})
    if not starts:
        print(f"{nm:32} {'-':18} {'-':12} no ref / no fstart  refs={[hex(s) for s in sites[:3]]}")
        continue
    for st in starts:
        print(f"{nm:32} {st:#018x} {st-BASE:#012x} {'YES' if st in CALLS else 'no'}")
