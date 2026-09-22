#!/usr/bin/env python3
"""Dump the shared SM request builder + the finalize wrapper."""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ELF = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KB = 0xffffffff82200000
d = open(ELF, 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

KNOWN = {0x630230: 'sceSblServiceMailbox', 0x63E470: 'SmStart',
         0x63FF00: 'SmFinalize', 0x63FFF0: 'SmRequest',
         0x640AA0: 'SmLoadSelfBlock', 0x642C90: 'AuthMgrAuthHeader',
         0x61AE20: 'MapPages', 0x61B500: 'UnmapPages',
         0xA3840: '_sx_xlock', 0xA3A00: '_sx_xunlock',
         0x2BD4E0: 'bzero', 0x2BD5A0: 'memcpy'}


def dis(lo, hi):
    out, off = [], lo
    while off < hi:
        g = False
        for i in md.disasm(d[off:hi], KB + off):
            out.append(i)
            off += i.size
            g = True
        if not g:
            off += 1
    return out


for lo, hi, title in [(0x63FFF0, 0x6401C0, 'sceSblAuthMgrSmRequest'),
                      (0x63FF00, 0x63FFF0, '_sceSblAuthMgrSmFinalize'),
                      (0x63F900, 0x63FF00, 'region before Finalize')]:
    print(f"===== {title}  0x{lo:x}..0x{hi:x} =====")
    for i in dis(lo, hi):
        note = ''
        if i.mnemonic == 'call' and i.op_str.startswith('0x'):
            t = int(i.op_str, 16) - KB
            note = '   ; ' + KNOWN.get(t, f'sub_{t:06x}')
        print(f"  {i.address - KB:06x}  {i.mnemonic:8s} {i.op_str}{note}")
    print()
