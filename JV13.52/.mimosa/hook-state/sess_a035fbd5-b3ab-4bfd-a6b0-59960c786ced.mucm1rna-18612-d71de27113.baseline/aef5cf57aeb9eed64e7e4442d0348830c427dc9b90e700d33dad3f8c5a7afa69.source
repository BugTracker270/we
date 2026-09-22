#!/usr/bin/env python3
"""Disassemble a range with the raw instruction bytes, so encodings can be
checked rather than trusted."""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ELF = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KB = 0xffffffff82200000
d = open(ELF, 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

lo, hi = int(sys.argv[1], 16), int(sys.argv[2], 16)
off = lo
while off < hi:
    got = False
    for i in md.disasm(d[off:hi], KB + off):
        got = True
        off += i.size
        hx = i.bytes.hex()
        print(f"  {i.address - KB:06x}  {hx:<22} {i.mnemonic:8s} {i.op_str}")
    if not got:
        off += 1
