#!/usr/bin/env python3
"""Run the sub_63D780 arithmetic over every SELF we have.

If the kernel really feeds it the raw on-disk header, then for a genuine,
normally-loadable SELF the derived `cnt` must be a small number and both checks
must pass. Any SELF that behaves gives us the layout the code expects.
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

    magic = u32(0)
    n = u16(0x18)
    hs = u16(0x0c)
    meta = u16(0x0e)
    r9 = n * 0x20
    cnt_off = r9 + 0x58
    cnt = u16(cnt_off) if cnt_off + 2 <= len(d) else -1
    ecx = (hs - r9 - 0x20) & 0xffffffff
    edi = ((cnt * 0x38) + 0x4f) & 0xffffffff & 0xfffffff0
    rdx = (0xfffffffc0 + ((ecx - edi) & 0xffffffff)) & 0xffffffffffffffff
    edx = (rdx >> 4) & 0xffffffff
    rcx = r9 + 0x20
    boff = edi + rcx + 0x40
    b = d[boff] if boff < len(d) else -1

    print(os.path.basename(f))
    print(f"   magic={magic:#010x} n={n} hs={hs:#x} meta={meta:#x} "
          f"file={len(d):#x}")
    print(f"   cnt=u16[{cnt_off:#x}]={cnt} ecx={ecx:#x} edi={edi:#x} edx={edx:#x}")
    ok1 = edx >= 3
    ok2 = (b >= 0) and ((b & 3) == 3)
    print(f"   check1 (edx>=3)={'PASS' if ok1 else 'FAIL'}"
          f"   check2 (byte[{boff:#x}]={b:#x} &3)="
          f"{'PASS' if ok2 else 'FAIL'}   -> "
          f"{'SUCCEEDS' if (ok1 and ok2) else 'FAILS -2'}")
    print()
