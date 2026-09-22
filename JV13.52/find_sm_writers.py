"""Find every reference (esp. STORE) into the AuthMgr SM block, using full linear
disassembly instead of the earlier REX-only byte pattern (which missed
`cmp byte [rip+..], imm` and friends)."""
import re
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ELF = r"C:\Users\Kinan\Downloads\czdji0\1352k.elf"
data = open(ELF, "rb").read()
BASE = 0xffffffff82200000
TEXT_END_KO = 0x00cfe758

# SM block we care about
LO = BASE + 0x0269C000
HI = BASE + 0x0269C160

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

hits = []
n = 0
for ins in md.disasm(data[0:TEXT_END_KO], BASE):
    n += 1
    if "[rip" not in ins.op_str:
        continue
    m = re.search(r"\[rip ([-+] )?(0x[0-9a-f]+)\]", ins.op_str)
    if not m:
        continue
    disp = int(m.group(2), 16)
    if m.group(1) and "-" in m.group(1):
        disp = -disp
    tgt = ins.address + ins.size + disp
    if LO <= tgt < HI:
        hits.append((ins.address, ins.mnemonic, ins.op_str, tgt))

print(f"disassembled {n} instructions")
print(f"refs into SM block [{LO:#x},{HI:#x}): {len(hits)}\n")

def enclosing(v):
    """nearest preceding 'push rbp; mov rbp,rsp'"""
    o = v - BASE
    for back in range(0, 0x2000):
        if o - back < 0:
            break
        if data[o-back:o-back+3] == b"\x55\x48\x89\xe5":
            return BASE + o - back
    return None

print(f"{'site':>14} {'koff':>10}  {'target koff':>12}  fn            insn")
for (a, mn, ops, t) in hits:
    f = enclosing(a)
    print(f"{a:#14x} {a-BASE:#10x}  {t-BASE:#12x}  "
          f"{('%#x' % f) if f else '?':>13}  {mn} {ops}")

print("\n--- distinct enclosing functions ---")
for f in sorted({enclosing(a) for (a, *_ ) in hits if enclosing(a)}):
    print(f"  {f:#x}  (koff {f-BASE:#x})")
