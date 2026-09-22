#!/usr/bin/env python3
"""Dump one koff range of the decrypted 13.52 kernel. Usage:
    python dump_fn.py 0x640630 0x640aa0
"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ELF = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KB = 0xffffffff82200000
d = open(ELF, 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

KNOWN = {0x630230: 'sceSblServiceMailbox', 0x630340: 'sm?',
         0x63E470: 'SmStart', 0x63FF00: 'SmFinalize', 0x63FFF0: 'SmRequest',
         0x640AA0: 'SmLoadSelfBlock', 0x642C90: 'AuthMgrAuthHeader',
         0x61AE20: 'MapPages', 0x61B500: 'UnmapPages',
         0x9520: 'kmalloc', 0x96E0: 'kfree',
         0x2BD4E0: 'bzero', 0x2BD5A0: 'memcpy',
         0x2BD790: 'copyin', 0x2BD6A0: 'copyout',
         0x394AD0: 'memcmp', 0x2E0510: 'log_err', 0x6C8550: 'panic',
         0xA3840: '_sx_xlock', 0xA3A00: '_sx_xunlock',
         0x62FB60: 'sm62fb60', 0x62FD20: 'sm62fd20', 0x62FFC0: 'sm62ffc0',
         0x62FFD0: 'sm62ffd0', 0x6442B0: 'sm6442b0'}

GLOB = {0x269C098: 'SM_FLAG', 0x269C0A0: 'MODULE_ID', 0x269C0A8: 'G0A8',
        0x269C0B0: 'BUF_A', 0x269C0B8: 'BUF_B', 0x269C0C0: 'BUF_C',
        0x269C0C8: 'SM_XLOCK', 0x269C130: 'CTX_STATUS', 0x269C140: 'SELF_CTX',
        0x269C2C0: 'CTX_BUFBASE'}

lo = int(sys.argv[1], 16)
hi = int(sys.argv[2], 16)
off = lo
print(f"===== 0x{lo:x}..0x{hi:x} =====")
while off < hi:
    got = False
    for i in md.disasm(d[off:hi], KB + off):
        got = True
        off += i.size
        note = ''
        if i.mnemonic == 'call' and i.op_str.startswith('0x'):
            t = int(i.op_str, 16) - KB
            note = '   ; ' + KNOWN.get(t, f'sub_{t:06x}')
        for op in i.operands:
            if op.type == 3 and op.mem.base == 41:
                t = i.address + i.size + op.mem.disp
                if t in GLOB:
                    note += f'   ; G {GLOB[t]}'
        print(f"  {i.address - KB:06x}  {i.mnemonic:8s} {i.op_str}{note}")
    if not got:
        off += 1
