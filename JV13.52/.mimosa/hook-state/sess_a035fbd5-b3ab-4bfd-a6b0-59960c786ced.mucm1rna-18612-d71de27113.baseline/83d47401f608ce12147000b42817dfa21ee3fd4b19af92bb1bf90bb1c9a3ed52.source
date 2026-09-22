"""Full disassembly of sceSblAuthMgrIsLoadable (F5) to find the SM command id."""
import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ELF = r"C:\Users\Kinan\Downloads\czdji0\1352k.elf"
data = open(ELF, "rb").read()
BASE = 0xffffffff82200000
md = Cs(CS_ARCH_X86, CS_MODE_64)

def cstr(v):
    if not (BASE <= v < BASE + 0x10000000):
        return None
    o = v - BASE
    if o < 0 or o >= len(data):
        return None
    e = data.find(b"\x00", o, o + 80)
    if e < 0:
        return None
    s = data[o:e]
    if len(s) >= 4 and all(32 <= c < 127 for c in s):
        return s.decode()
    return None

START, END = 0x00642880, 0x00642a20
print(f"=== sceSblAuthMgrIsLoadable  {BASE+START:#x} .. {BASE+END:#x} ===")
for ins in md.disasm(data[START:END], BASE + START):
    s = f"{ins.mnemonic} {ins.op_str}"
    note = ""
    m = re.search(r"\[rip \+ (0x[0-9a-f]+)\]", s)
    if m:
        tgt = ins.address + ins.size + int(m.group(1), 16)
        st = cstr(tgt)
        if st:
            note = f'   -> "{st}"'
        else:
            note = f"   -> {tgt:#x}  (koff {tgt-BASE:#x})"
    if ins.mnemonic == "call":
        note += "  <-- CALL"
    # highlight the regs of interest
    if re.search(r"\br1[234]\b|\br1[234]d\b", s):
        note += "   ***"
    print(f"  {ins.address:#x}  {s}{note}")
