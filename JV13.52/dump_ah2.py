#!/usr/bin/env python3
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
         0x2BD4E0: 'bzero', 0x2BD5A0: 'memcpy',
         0x2E0510: 'log_err', 0x6C8550: 'panic'}

GLOB = {0x269C098: 'SM_FLAG', 0x269C0A0: 'MODULE_ID', 0x269C0B0: 'BUF_A',
        0x269C0C0: 'BUF_C', 0x269C0C8: 'SM_XLOCK', 0x269C140: 'SELF_CTX',
        0x269C2C0: 'CTX_BUFBASE'}


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


def show(lo, hi, title):
    print(f"===== {title} 0x{lo:x}..0x{hi:x} =====")
    for i in dis(lo, hi):
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
    print()


show(0x642F80, 0x643400, 'sceSblAuthMgrAuthHeader part 2')
