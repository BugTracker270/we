#!/usr/bin/env python3
"""Same arithmetic, but treat the size field as header_size + metadata_size.

sceSblAuthMgrAuthHeader sets ctx->total_header_size = header_size +
metadata_size (it passes r14d = hdr + meta into verify_header), and
verify_header hands that same value to the module as packet+0x10. So if
ctx->0x38 points at a kernel-side structure whose size field merges the two,
this is the field sub_63D780 would read.
"""
import glob, os

FILES = sorted(glob.glob(r'C:\Users\Kinan\Downloads\JV13.52\dec\**\*.self',
                         recursive=True))

for f in FILES:
    d = open(f, 'rb').read()

    def u16(o):
        return int.from_bytes(d[o:o + 2], 'little')

    def u32(o):
        return int.from_bytes(d[o:o + 4], 'little')

    n = u16(0x18)
    hs = u16(0x0c)
    tot = hs + u16(0x0e)
    r9 = n * 0x20
    cnt = u16(r9 + 0x58)
    ecx = (tot - r9 - 0x20) & 0xffffffff
    edi = (((cnt * 0x38) + 0x4f) & 0xffffffff) & 0xfffffff0
    rdx = (0xfffffffc0 + ((ecx - edi) & 0xffffffff)) & 0xffffffffffffffff
    edx = (rdx >> 4) & 0xffffffff
    rcx = r9 + 0x20
    boff = edi + rcx + 0x40
    b = d[boff] if boff < len(d) else -1
    ok1, ok2 = edx >= 3, (b >= 0 and (b & 3) == 3)
    print(f"{os.path.basename(f):28s} n={n} hdr={hs:#x} tot={tot:#x} "
          f"cnt={cnt:<5d} edi={edi:#06x} edx={edx:#06x} "
          f"byte[{boff:#06x}]={b:#04x}  "
          f"c1={'P' if ok1 else 'F'} c2={'P' if ok2 else 'F'} "
          f"-> {'*** SUCCEEDS ***' if (ok1 and ok2) else 'fails -2'}")
