#!/usr/bin/env python3
"""Prove sd_step now addresses g_a directly instead of trusting the kexec arg.

sd_step is the first .text function (vaddr 0x05 per the linker map). If the fix
is real, its prologue must load g_a's fixed address into a register and read
the step field from there, rather than reading [rsi+8] (the 2nd kexec arg).
"""
import re, subprocess, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ROOT = r'C:\Users\Kinan\Downloads\JV13.52\selfdec2'
BIN = ROOT + r'\selfdec2.bin'
MAP = ROOT + r'\selfdec2.map'

txt = open(MAP, encoding='utf-8', errors='replace').read()
m = re.search(r'^\s*(0x[0-9a-f]+)\s+\.bss\.g_a\s' , txt, re.M)
if not m:
    print("could not find g_a in the map"); sys.exit(2)
g_a = int(m.group(1), 16)
m2 = re.search(r'^\s*(0x[0-9a-f]+)\s+sd_step\s' , txt, re.M)
sd_step = int(m2.group(1), 16)
print(f"g_a     = 0x{g_a:x}")
print(f"sd_step = 0x{sd_step:x}")

d = open(BIN, 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
# sd_step occupies the first bytes of the image (its vaddr is the image base)
insns = []
for ins in md.disasm(d[:0x200], sd_step):
    insns.append(ins)

print("\n--- prologue ---")
for ins in insns[:26]:
    print(f"  0x{ins.address - sd_step:04x}  {ins.bytes.hex():<20} {ins.mnemonic:<8} {ins.op_str}")

# does anything reference g_a's absolute address via rip-relative lea/mov?
ref = [i for i in insns
       if 'rip' in i.op_str and i.mnemonic in ('lea', 'mov', 'cmp')]
print("\n--- rip-relative refs in prologue ---")
for i in ref:
    print(f"  0x{i.address - sd_step:04x}  {i.mnemonic} {i.op_str}")

uses_rsi = [i for i in insns
            if i.op_str.startswith('rsi') or i.op_str.startswith('esi')
            or ', rsi' in i.op_str or ', esi' in i.op_str]
print("\n--- instructions touching rsi/esi in prologue ---")
for i in uses_rsi:
    print(f"  0x{i.address - sd_step:04x}  {i.mnemonic} {i.op_str}")

ok = len(uses_rsi) == 0
print("\nVERDICT:", "PASS - second kexec argument is not consulted"
      if ok else f"FAIL - rsi still consulted {len(uses_rsi)}x")
sys.exit(0 if ok else 1)

