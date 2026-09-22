#!/usr/bin/env python3
"""Disassemble sd_step out of the flat selfdec2.bin and prove the
'no SELF file -> never copyin' guard is actually compiled in.

sd_step is the first .text function: the linker map puts it at vaddr 0x05 with
size 0x7bf, so its file offset in the flat -O binary image is 0x05.

Expected shape at the top of the function, before the jump table:
    cmp  <step>, 5          ; a->step >= 5 ?
    jb   <switch>           ;   no  -> allowed
    cmp  <p_self>, 0        ; a->p_self == 0 ?
    jne  <switch>           ;   no  -> allowed
    mov  o->rc, step        ;   yes -> bail out with rc = step
    ret
with  a->step  at [args+0x08] and a->p_self at [args+0x48].
"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BIN = r'C:\Users\Kinan\Downloads\JV13.52\selfdec2\selfdec2.bin'
SD_STEP_OFF, SD_STEP_LEN = 0x05, 0x7BF

d = open(BIN, 'rb').read()
print(f"{BIN}  {len(d):,} bytes")
print(f"sd_step @ file offset 0x{SD_STEP_OFF:x}, len 0x{SD_STEP_LEN:x}\n")

md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(d[SD_STEP_OFF:SD_STEP_OFF + SD_STEP_LEN], SD_STEP_OFF))
print(f"decoded {len(insns)} instructions\n")

print("--- first 34 instructions of sd_step ---")
for ins in insns[:34]:
    print(f"  0x{ins.address:04x}  {ins.bytes.hex():<20} {ins.mnemonic:<8}{ins.op_str}")

# --- look for the guard pattern -------------------------------------------
print("\n--- searching for the guard ---")
# The compiler emits `step >= 5` as `cmp rax, 4 / jbe allowed`, so match the
# load of a->p_self at [args+0x48] against zero and then the bail-out store.
ok = False
for i, ins in enumerate(insns):
    if not (ins.mnemonic == 'cmp' and '0x48' in ins.op_str and ', 0' in ins.op_str):
        continue
    back = insns[max(0, i - 5): i]
    fwd = insns[i + 1: i + 5]
    step_cmp = any(b.mnemonic == 'cmp' and b.op_str.strip()[-1] in '45'
                   for b in back)
    bail = any(f.mnemonic == 'mov' and 'rip' in f.op_str for f in fwd)
    ret = any(f.mnemonic == 'jmp' or f.mnemonic == 'ret' for f in fwd)
    print(f"  p_self load at 0x{ins.address:04x}: {ins.mnemonic} {ins.op_str}"
          f"   step-compare-before={step_cmp}  bailout-after={bail}  ret-after={ret}")
    for w in back + [ins] + fwd:
        print(f"        0x{w.address:04x}  {w.mnemonic:<8}{w.op_str}")
    if step_cmp and bail and ret:
        ok = True

print("\nVERDICT:", "PASS - NULL-source guard is compiled in" if ok
      else "FAIL - guard not found; DO NOT RUN THIS BINARY")
sys.exit(0 if ok else 1)
