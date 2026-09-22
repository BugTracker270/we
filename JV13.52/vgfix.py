#!/usr/bin/env python3
"""Prove sd_step addresses g_a directly instead of trusting the kexec argument.

From selfdec2.map:
    .bss.g_a   0x6b00  0xd8
    .bss.g_r   0x6a60  0x88
sd_step is the first .text function, so its code starts at the top of the flat
-O binary image.

Two assertions:
  1. it must NOT consult rsi/esi (the 2nd kexec parameter) at all
  2. it should reach the payload .bss via rip-relative addressing around 0x6b00
"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BIN = r'C:\Users\Kinan\Downloads\JV13.52\selfdec2\selfdec2.bin'
IMAGE_BASE = 0x05          # sd_step vaddr per the linker map
G_A, G_R = 0x6b00, 0x6a60

d = open(BIN, 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

insns = list(md.disasm(d[:0x260], IMAGE_BASE))
print(f"disassembled {len(insns)} instructions of sd_step\n")

print("--- prologue (first 30) ---")
for ins in insns[:30]:
    extra = ""
    for op in ins.operands:
        if op.type == 3 and op.mem.base == 41:          # rip-relative
            tgt = ins.address + ins.size + op.mem.disp
            extra = f"   ; -> 0x{tgt:x}"
            if tgt in (G_A, G_R):
                extra += "  <== payload .bss"
    print(f"  0x{ins.address - IMAGE_BASE:04x}  {ins.bytes.hex():<20} "
          f"{ins.mnemonic:<8} {ins.op_str}{extra}")

print("\n--- every rip-relative access to payload .bss in sd_step ---")
hits = 0
for ins in insns:
    for op in ins.operands:
        if op.type == 3 and op.mem.base == 41:
            tgt = ins.address + ins.size + op.mem.disp
            if tgt == G_A:
                hits += 1
                print(f"  0x{ins.address - IMAGE_BASE:04x}  {ins.mnemonic} "
                      f"{ins.op_str}   ; g_a")
            elif tgt == G_R:
                print(f"  0x{ins.address - IMAGE_BASE:04x}  {ins.mnemonic} "
                      f"{ins.op_str}   ; g_r")

rsi = [i for i in insns
       if ', rsi' in i.op_str or ', esi' in i.op_str
       or i.op_str.startswith('rsi') or i.op_str.startswith('esi')]

print(f"\ng_a references: {hits}")
print(f"rsi/esi references: {len(rsi)}")
for i in rsi:
    print(f"    {i.mnemonic} {i.op_str}")

ok = (len(rsi) == 0) and hits >= 1
print("\nVERDICT:", "PASS - kexec arg unused, g_a addressed directly"
      if ok else "FAIL")
sys.exit(0 if ok else 1)
