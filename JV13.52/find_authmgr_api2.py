#!/usr/bin/env python3
"""Stage-13b : resolve AuthMgr entry points using call-target boundaries + prologue list."""
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
TEXT_END = 0xffffffff82efe758

# prologue positions (whole .text)
PRO = [o2v(i) for i in range(0, len(data) - 4) if data[i:i+4] == b"\x55\x48\x89\xe5"]
PRO = sorted(p for p in PRO if p)
print(f"functions with 'push rbp; mov rbp,rsp' : {len(PRO)}")

# call targets
CALLS = set()
i = 0
lim = v2o(TEXT_END - 1)
while i < lim - 5:
    if data[i] == 0xE8:
        rel = struct.unpack_from("<i", data, i+1)[0]
        t = o2v(i) + 5 + rel
        if t is not None and BASE <= t < TEXT_END: CALLS.add(t)
    i += 1
CALLS = sorted(CALLS)
print(f"call targets                          : {len(CALLS)}")

# RIP ref index
REFS = []
o = 0
while o < len(data) - 7:
    b0, b1, b2 = data[o], data[o+1], data[o+2]
    if b0 in (0x48, 0x4c) and b1 in (0x8d, 0x8b, 0x89) and b2 in {0x05,0x0d,0x15,0x1d,0x2d,0x35,0x3d}:
        disp = struct.unpack_from("<i", data, o+3)[0]
        v = o2v(o)
        if v is not None: REFS.append((v, v + 7 + disp))
    o += 1

def prior(lst, x):
    lo, hi, best = 0, len(lst) - 1, None
    while lo <= hi:
        m = (lo + hi) // 2
        if lst[m] <= x: best = lst[m]; lo = m + 1
        else: hi = m - 1
    return best

NAMES = [
 ("sceSblAuthMgrAuthHeader", 0xffffffff82ceda46),
 ("sceSblAuthMgrLoadSegment", 0xffffffff82cedcd9),
 ("sceSblAuthMgrLoadBlock", 0xffffffff82cedc57),
 ("sceSblAuthMgrFinalize", 0xffffffff82cedbaf),
 ("sceSblAuthMgrIsLoadable", 0xffffffff82ced976),
 ("_sceSblAuthMgrSmFinalize", 0xffffffff82ced2f6),
 ("_sceSblAuthMgrSmStart", 0xffffffff82ced06a),
 ("_sceSblAuthMgrLoadSelfBlock", 0xffffffff82cecba3),
 ("_sceSblAuthMgrCheckSelfHeader", 0xffffffff82cecd3c),
 ("_sceSblAuthMgrSmLoadSelfBlock", 0xffffffff82ced3a0),
]
print(f"\n{'symbol':34} {'fn start':18} {'koff':13} prologue calltgt")
for nm, sv in NAMES:
    sites = [ia for (ia, t) in REFS if t == sv]
    if not sites:
        print(f"{nm:34} no refs"); continue
    st = prior(CALLS, sites[0])
    print(f"{nm:34} {st:#018x} {st-BASE:#013x} "
          f"{'YES' if st in PRO else 'no ':8} {'YES' if st in CALLS else 'no'}")
