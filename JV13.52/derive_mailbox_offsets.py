#!/usr/bin/env python3
"""Stage-3 : PS4 does NOT store absolute pointers to the lock-name strings, so the PS5
recipe's "pointer to X" holders do not exist. Instead find the RIP-relative reference
sites and recover the real globals next to them."""
import struct

P = r"C:\Users\Kinan\Downloads\czdji0\1352k.elf"
data = open(P, "rb").read()
BASE = 0xffffffff82200000
e_phoff, e_phnum = 0x40, 6
segs = []
for i in range(e_phnum):
    t, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", data, e_phoff + i*56)
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
DATA_START = 0xffffffff83720000     # .data segment vaddr

MODRM_RIP = {0x05, 0x0d, 0x15, 0x1d, 0x2d, 0x35, 0x3d}

def rip_refs_in(lo, hi):
    """all RIP-relative memory refs within [lo,hi) -> list of (insn_vaddr, kind, target_vaddr)"""
    out = []
    a = lo
    while a < hi - 7:
        o = v2o(a)
        if o is None or o + 7 > len(data):
            a += 1; continue
        b0, b1, b2 = data[o], data[o+1], data[o+2]
        kind = None
        if b0 in (0x48, 0x4c) and b1 in (0x8d, 0x8b) and b2 in MODRM_RIP:
            kind = {0x8d: "lea", 0x8b: "load"}[b1]
        elif b0 in (0x48, 0x4c) and b1 == 0x89 and b2 in MODRM_RIP:
            kind = "store"
        if kind:
            disp = struct.unpack_from("<i", data, o+3)[0]
            tgt = a + 7 + disp
            out.append((a, kind, tgt))
            a += 7; continue
        a += 3
    return out

ANCH = {"sdt":0xffffffff82a036b1,"SblDrvSendSx":0xffffffff82ce6207,
        "req mtx":0xffffffff82ceaca8,"req msg cv":0xffffffff82ceac9d,
        "req cv":0xffffffff82ceacb0}

print("=== RIP-relative reference sites for each anchor string ===")
sites = {}
for name, va in ANCH.items():
    refs = [r for r in rip_refs_in(TEXT_START, TEXT_END) if r[2] == va]
    sites[name] = refs
    print(f"\n{name!r} @ {va:#018x}: {len(refs)} ref site(s)")
    for (a, kind, tgt) in refs:
        print(f"   {kind:5} @ {a:#018x}   (koff {a-BASE:#010x})")

print("\n=== globals referenced within +/-0x100 of each 'req *' ref site ===")
for name in ("req mtx", "req msg cv", "req cv"):
    for (a, kind, tgt) in sites[name]:
        print(f"\n-- around {name!r} {kind} @ {a:#018x} --")
        for (aa, kk, tt) in rip_refs_in(a - 0x100, a + 0x100):
            if tt >= DATA_START or tt < 0xffffffff82eff000:
                tag = "DATA" if tt >= DATA_START else "other"
                print(f"   {kk:5} @ {aa:#018x} -> {tt:#018x}  [{tag}] koff {tt-BASE:#010x}")

print("\n=== authmgr_handle candidate test: candidate must hold value 4 ===")
for cand in (0xffffffff82ea1cb0, 0xffffffff83c79fc0):
    o = v2o(cand)
    if o is None:
        print(f"  {cand:#018x}: outside file-backed segment (bss)")
        continue
    vals = [struct.unpack_from("<I", data, o + k)[0] for k in (0, 4, 8, 0x10, 0x18, 0x20)]
    print(f"  {cand:#018x} (koff {cand-BASE:#010x}): dwords {[hex(v) for v in vals]}")
