#!/usr/bin/env python3
"""Disassemble a range with every RIP-relative target RESOLVED and printed as a
koff, so hand arithmetic never enters the picture.

Both crashing builds (run 5: hand walk, run 6: sub_645110 scan) converge on
koff 0x0269C300, and run 4 - which worked - never touched it. So this prints
the exact global each instruction touches, including the loop traversal.
"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_REG_RIP

ELF = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KB = 0xffffffff82200000
d = open(ELF, 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

GLOB = {0x269C098: 'SM_STARTED', 0x269C0A0: 'MODULE_ID', 0x269C0A8: 'G0A8',
        0x269C0B0: 'BUF_A', 0x269C0B8: 'BUF_B', 0x269C0C0: 'BUF_C',
        0x269C0C8: 'SM_XLOCK', 0x269C130: 'CTX_STATUS', 0x269C140: 'SELF_CTX',
        0x269C2C0: 'CTX_BUFBASE', 0x269C2E0: 'KEY_LOCK?', 0x269C300: 'KEY_HEAD?',
        0x2845168: 'SBL_BUF', 0x2845170: 'SBL_META'}

lo, hi = int(sys.argv[1], 16), int(sys.argv[2], 16)
off = lo
while off < hi:
    got = False
    for i in md.disasm(d[off:hi], KB + off):
        got = True
        off += i.size
        note = ''
        if i.mnemonic == 'call' and i.op_str.startswith('0x'):
            note = f"   ; -> koff {int(i.op_str, 16) - KB:#x}"
        for op in i.operands:
            if op.type == 3 and op.mem.base == X86_REG_RIP:
                t = i.address + i.size + op.mem.disp - KB
                note += f"   ; [koff {t:#x}]"
                if t in GLOB:
                    note += f" = {GLOB[t]}"
        print(f"  {i.address - KB:06x}  {i.mnemonic:8s} {i.op_str}{note}")
    if not got:
        off += 1
