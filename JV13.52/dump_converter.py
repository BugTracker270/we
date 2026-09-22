"""Disassemble the SM command selector at 0x825b3630 (IsLoadable feeds it arg3
and passes its return value as smreq's command argument)."""
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
    e = data.find(b"\x00", o, o + 90)
    if e < 0:
        return None
    s = data[o:e]
    if len(s) >= 4 and all(32 <= c < 127 for c in s):
        return s.decode()
    return None

KO = 0x003b3630   # 0xffffffff825b3630 - 0xffffffff82200000
print(f"=== command selector @ {BASE+KO:#x} (koff {KO:#x}) ===")
for ins in md.disasm(data[KO:KO + 0xB0], BASE + KO):
    s = f"{ins.mnemonic} {ins.op_str}"
    note = ""
    m = re.search(r"\[rip \+ (0x[0-9a-f]+)\]", s)
    if m:
        tgt = ins.address + ins.size + int(m.group(1), 16)
        st = cstr(tgt)
        note = f'   -> "{st}"' if st else f"   -> koff {tgt-BASE:#x}"
    if ins.mnemonic == "call":
        note += "  <-- CALL"
    print(f"  {ins.address:#x}  {s}{note}")
    if ins.mnemonic == "ret":
        break
