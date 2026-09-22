#!/usr/bin/env python3
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
KB = 0xffffffff82200000
d = open(r'C:\Users\Kinan\Downloads\czdji0\1352k.elf', 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("--- 0x2BD790 (candidate copyin) ---")
for ins in md.disasm(d[0x2BD790:0x2BD8A0], KB + 0x2BD790):
    print('0x%08x  %-24s %s %s' % (ins.address - KB, ins.bytes.hex(), ins.mnemonic, ins.op_str))
print("\n--- 0x2BD6A0 tail (copyout, for comparison) ---")
for ins in md.disasm(d[0x2BD750:0x2BD790], KB + 0x2BD750):
    print('0x%08x  %-24s %s %s' % (ins.address - KB, ins.bytes.hex(), ins.mnemonic, ins.op_str))
