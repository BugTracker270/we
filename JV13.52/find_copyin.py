#!/usr/bin/env python3
"""Find copyin: the mirror of copyout (0x2BD6A0). Look for a function that
validates a USER source address then rep-movs user -> kernel (no xchg needed)."""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
KB = 0xffffffff82200000
d = open(r"C:\Users\Kinan\Downloads\czdji0\1352k.elf", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

# find every 'push rbp; mov rbp,rsp' entry in the window
lo, hi = 0x2BD400, 0x2BDA00
print("entries in window:")
for i in range(lo, hi - 4):
    if d[i:i+4] == b'\x55\x48\x89\xe5':
        print("   0x%08x  %s" % (i, d[i:i+16].hex(' ')))

for start in range(0x2BD5E0, 0x2BD9A0):
    if d[start:start+4] != b'\x55\x48\x89\xe5':
        continue
    print("\n" + "=" * 74)
    print("function 0x%08x" % start)
    n = 0
    for ins in md.disasm(d[start:start+0x120], KB + start):
        k = ins.address - KB
        ex = ""
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            ex = "   -> koff 0x%08x" % (int(ins.op_str, 16) - KB)
        print("  0x%08x  %-22s %s %s%s" % (k, ins.bytes.hex(), ins.mnemonic, ins.op_str, ex))
        n += 1
        if n > 30 or ins.mnemonic == 'ret':
            break

