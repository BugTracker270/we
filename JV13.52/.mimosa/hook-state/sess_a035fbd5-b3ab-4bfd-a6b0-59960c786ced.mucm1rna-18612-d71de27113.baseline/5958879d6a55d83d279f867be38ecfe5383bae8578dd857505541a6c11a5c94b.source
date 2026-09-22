#!/usr/bin/env python3
"""Find every RIP-relative access to a koff, classified read vs write.

Used to find who POPULATES the EEKC key store (root at koff 0x0269C300).
The store is empty on a booted console, which is why verify_header can never
obtain a key and the module always answers EINVAL - so whoever inserts into it
is the thing worth understanding.
"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_REG_RIP

ELF = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KB = 0xffffffff82200000
d = open(ELF, 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

TARGET = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x269C300
LO = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x0
HI = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x800000

off = LO
hits = []
while off < HI:
    g = False
    for i in md.disasm(d[off:HI], KB + off):
        g = True
        off += i.size
        for k, op in enumerate(i.operands):
            if op.type == 3 and op.mem.base == X86_REG_RIP:
                t = i.address + i.size + op.mem.disp - KB
                if t == TARGET:
                    # operand index 0 and a non-mem source => a WRITE
                    wr = (k == 0 and i.mnemonic in
                          ('mov', 'or', 'and', 'add', 'sub', 'xor') and
                          len(i.operands) > 1 and
                          not (i.operands[1].type == 3))
                    hits.append((i.address - KB, 'WRITE' if wr else 'read ',
                                 i.mnemonic, i.op_str))
    if not g:
        off += 1

print(f"accesses to koff {TARGET:#x} in [{LO:#x},{HI:#x}): {len(hits)}")
for a, kind, m, ops in hits:
    print(f"  {a:06x}  {kind}  {m:8s} {ops}")
