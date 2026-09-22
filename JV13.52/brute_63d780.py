#!/usr/bin/env python3
"""Search for the base pointer sub_63D780 actually expects.

AuthHeader memcpy's the raw header into ctx->0x38 and verify_header then hands
ctx->0x38 to sub_63D780 as `r8`. If the arithmetic cannot be satisfied with
r8 = the start of that buffer, then r8 must be an interior pointer - or the
structure is not in the file at all. Brute force every candidate base over the
whole file and report those where BOTH checks pass.
"""
import glob, os, sys

MASK64 = (1 << 64) - 1


def try_base(d, hdr_total, b):
    def u16(o):
        return int.from_bytes(d[o:o + 2], 'little') if o + 2 <= len(d) else None

    n = u16(b + 0x18)
    hs = u16(b + 0x0c)
    if n is None or hs is None:
        return None
    r9 = n * 0x20
    off = b + r9 + 0x58
    if off + 2 > len(d):
        return None
    cnt = int.from_bytes(d[off:off + 2], 'little')
    ecx = (hs - r9 - 0x20) & 0xffffffff
    edi = (((cnt * 0x38) + 0x4f) & 0xffffffff) & 0xfffffff0
    rdx = (0xfffffffc0 + ((ecx - edi) & 0xffffffff)) & MASK64
    edx = (rdx >> 4) & 0xffffffff
    if edx < 3:
        return None
    boff = b + r9 + 0x20 + edi + 0x40
    if boff >= len(d):
        return None
    if (d[boff] & 3) != 3:
        return None
    return dict(base=b, n=n, hs=hs, cnt=cnt, edi=edi,
                out=b + r9 + 0x20 + edi + 0x50, chk=boff)


FILES = sorted(glob.glob(r'C:\Users\Kinan\Downloads\JV13.52\dec\**\*.self',
                         recursive=True))
for f in FILES:
    d = open(f, 'rb').read()
    tot = int.from_bytes(d[0xc:0xe], 'little') + int.from_bytes(d[0xe:0x10], 'little')
    hits = []
    for b in range(0, min(len(d), 0x8000) - 0x200):
        r = try_base(d, tot, b)
        if r:
            hits.append(r)
    print(f"{os.path.basename(f):26s} {len(hits)} base(s) satisfy BOTH checks")
    for h in hits[:6]:
        print(f"     base={h['base']:#06x} n={h['n']} hs={h['hs']:#x} "
              f"cnt={h['cnt']} edi={h['edi']:#x} chkbyte@{h['chk']:#06x} "
              f"(={d[h['chk']]:#04x}) *out={h['out']:#06x}")
    print()
