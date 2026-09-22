#!/usr/bin/env python3
"""Locate every store of a small SM command immediate into a stack packet."""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_REG_RBP

ELF = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KB = 0xffffffff82200000
d = open(ELF, 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

LO, HI = 0x63C000, 0x645000
WANT = (1, 2, 5, 6, 0x16)

off = LO
hits = []
while off < HI:
    g = False
    for i in md.disasm(d[off:HI], KB + off):
        g = True
        off += i.size
        if i.mnemonic != 'mov' or len(i.operands) != 2:
            continue
        dst, src = i.operands
        if dst.type == 3 and dst.mem.base == X86_REG_RBP \
                and src.type == 2 and src.imm in WANT and dst.size in (2, 4, 8):
            hits.append((i.address - KB, dst.size, dst.mem.disp, src.imm, i.op_str))
    if not g:
        off += 1

for a, sz, disp, imm, txt in hits:
    print(f"  0x{a:06x}  u{sz*8:<3} [rbp{disp:+#x}] = {imm:#x}    {txt}")
