#!/usr/bin/env python3
"""String -> xref -> function, on the 13.52 kernel image.

The kernel logs with lea rdx,[rip+FILE] / lea rsi,[rip+...]. Every SBL driver
function has distinctive strings ("SblDrv...MapPages..."). Finding which
function references them pins its koff exactly.
"""
import struct, re, sys, collections

ELF   = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KBASE = 0xffffffff82200000
d = open(ELF, 'rb').read()
e_phoff, = struct.unpack_from('<Q', d, 0x20)
e_phentsize, e_phnum = struct.unpack_from('<HH', d, 0x36)
SEGS = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t, fl, po, va, pa, fsz, msz, al = struct.unpack_from('<IIQQQQQQ', d, o)
    if t == 1:
        SEGS.append((va - KBASE, po, fsz, msz, fl))
SEGS.sort()
TEXT_BASE, TEXT_FOFF, TEXT_FSZ = SEGS[0][0], SEGS[0][1], SEGS[0][2]
TEXT_END = TEXT_BASE + TEXT_FSZ
tb = d[TEXT_FOFF:TEXT_FOFF + TEXT_FSZ]
print(f"[i] .text/rodata seg koff 0x{TEXT_BASE:x} .. 0x{TEXT_END:x}  ({TEXT_FSZ:,} B)")

def foff2koff(o):
    for ko, po, fsz, msz, fl in SEGS:
        if po <= o < po + fsz:
            return ko + (o - po)
    return None
def koff2foff(k):
    for ko, po, fsz, msz, fl in SEGS:
        if ko <= k < ko + fsz:
            return po + (k - ko)
    return None
def rd(k, n):
    o = koff2foff(k)
    return None if o is None else d[o:o + n]

# ---------------------------------------------------------------- strings
print("\n=== strings in the SBL / AuthMgr log cluster (koff 0xad0000 .. 0xaf1000) ===")
strs = []
for m in re.finditer(rb'[ -~]{5,}', d):
    ko = foff2koff(m.start())
    if ko is None:
        continue
    s = m.group().decode('ascii')
    strs.append((ko, s))
for ko, s in strs:
    if 0xad0000 <= ko < 0xaf1000:
        print(f"  0x{ko:08x}  {s}")
print(f"[i] total strings in image: {len(strs):,}")

# ------------------------------------------------- deterministic RIP scan
# modrm with mod=00, rm=101  -> RIP-relative disp32
RIPMODRM = bytes([0x05,0x0d,0x15,0x1d,0x25,0x2d,0x35,0x3d,
                  0x85,0x8d,0x95,0x9d,0xa5,0xad,0xb5,0xbd,
                  0xc5,0xcd,0xd5,0xdd,0xe5,0xed,0xf5,0xfd])
OPS  = set(range(0x00, 0x100))
PREF = {0x48,0x4c,0x49,0x4d,0x4e,0x4f,0x44,0x45,0x40,0x41,
        0x66,0xf3,0xf2,0x0f,0xc5,0xc4}
print("\n=== scanning every RIP-relative operand in .text ===")
refs = collections.defaultdict(list)      # target koff -> [insn koffs]
pat = re.compile(b'[' + re.escape(RIPMODRM) + b']')
n = 0
for m in pat.finditer(tb):
    p = m.start()
    if p < 2 or p + 5 > len(tb):
        continue
    if tb[p-2] not in PREF:
        continue
    rel, = struct.unpack_from('<i', tb, p + 1)
    ioff = p - 2                                   # assume REX+opcode+modrm
    tgt = TEXT_BASE + ioff + 7 + rel
    refs[tgt].append(TEXT_BASE + ioff)
    n += 1
print(f"[i] {n:,} RIP-relative operands decoded -> {len(refs):,} distinct targets")

PROLOGUES = [b'\x55\x48\x89\xe5', b'\xf3\x0f\x1e\xfa\x55\x48\x89\xe5', b'\x55\x48\x89\xe5']
def enclosing_fn(site):
    """walk back to the nearest 'push rbp; mov rbp,rsp' (function entry)."""
    k = site
    for back in range(0, 0x1200):
        p = k - back
        if p < TEXT_BASE: break
        o = p - TEXT_BASE
        if tb[o:o+3] == b'\x55\x48\x89\xe5':
            # a real entry: previous byte should be ret/nop/int3 end-of-func
            prev = tb[o-1:o] if o else b''
            if prev in (b'\xc3', b'\x90', b'\xcc', b'\x5d') or back == 0:
                return p
    return None

KEY = ['MapPages','UnmapPages','SblDrv','LoadSelfBlock','IsLoadable','AuthMgr',
       'authmgr','self','Self','sbl','Sbl','80010008','SELF']
print("\n=== xrefs to SBL/AuthMgr strings ===")
seen = set()
for ko, s in strs:
    if not (0xad0000 <= ko < 0xaf1000):
        continue
    if not any(k in s for k in KEY):
        continue
    if ko not in refs:
        continue
    sites = refs[ko]
    fns = sorted({enclosing_fn(x) for x in sites if enclosing_fn(x)})
    print(f"\n  0x{ko:08x}  \"{s}\"")
    print(f"      refs at: {', '.join('0x%08x' % x for x in sites[:8])}")
    print(f"      enclosing fns: {', '.join('0x%08x' % f for f in fns)}")

# ------------------------------------- who references MapPages/UnmapPages?
print("\n=== dedicated: every MapPages / UnmapPages string xref ===")
for ko, s in strs:
    if ('MapPages' in s or 'UnmapPages' in s):
        sites = refs.get(ko, [])
        print(f"  0x{ko:08x}  \"{s}\"   refs={len(sites)}")
        for x in sites:
            print(f"        site 0x{x:08x}   enclosing fn 0x{enclosing_fn(x) or 0:08x}")
