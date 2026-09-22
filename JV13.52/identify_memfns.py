#!/usr/bin/env python3
"""Distinguish bzero / copyin / copyout in the 0x2BD4E0 cluster."""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
KB = 0xffffffff82200000
d = open(r"C:\Users\Kinan\Downloads\czdji0\1352k.elf", "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
for start, label in [
    (0x2BD4E0, "0x2bd4e0 (bzero? 3265 callers)"),
    (0x2BD5A0, "0x2bd5a0 (copyin or bcopy? 2170 callers)"),
    (0x2BD6A0, "0x2bd6a0 (copyout, CONFIRMED by libPS4 K1352_COPYOUT)"),
]:
    print("=" * 74)
    print(label)
    n = 0
    for ins in md.disasm(d[start:start + 0xC0], KB + start):
        k = ins.address - KB
        ex = ""
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            ex = "   -> koff 0x%08x" % (int(ins.op_str, 16) - KB)
        print("  0x%08x  %-22s %s %s%s" % (k, ins.bytes.hex(), ins.mnemonic, ins.op_str, ex))
        n += 1
        if n > 36:
            break
