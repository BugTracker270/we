"""Disassemble the prologues of the ambiguous entries to settle argument registers."""
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
    e = data.find(b"\x00", o, o + 70)
    if e < 0:
        return None
    s = data[o:e]
    if len(s) >= 3 and all(32 <= c < 127 for c in s):
        return s.decode()
    return None

TARGETS = [
    ("F0 mailbox", 0x00630230),
    ("F2 authhdr", 0x00642c90),
    ("F3 load   ", 0x006434d0),
    ("F5 isload ", 0x00642880),
]

for label, ko in TARGETS:
    va = BASE + ko
    print(f"\n===== {label}  @ {va:#x} =====")
    for ins in md.disasm(data[ko:ko + 0x58], va):
        s = f"{ins.mnemonic} {ins.op_str}"
        note = ""
        m = re.search(r"\[rip \+ (0x[0-9a-f]+)\]", s)
        if m:
            tgt = ins.address + ins.size + int(m.group(1), 16)
            st = cstr(tgt)
            if st:
                note = f'   -> "{st}"'
            elif BASE + 0x1520000 <= tgt < BASE + 0x2800000:
                note = f"   -> GLOBAL koff {tgt-BASE:#x}"
        if ins.mnemonic == "call":
            note += "  <-- CALL"
        print(f"  {ins.address:#x}  {s}{note}")
