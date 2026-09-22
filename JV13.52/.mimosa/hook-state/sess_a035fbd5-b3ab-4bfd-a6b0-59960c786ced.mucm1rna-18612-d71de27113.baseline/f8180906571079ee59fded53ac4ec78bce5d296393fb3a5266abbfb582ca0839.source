"""The prologue flag at koff 0x269C108 read as 0 - the SM layer is not started.
Find who WRITES it and who references the 'authMgrPrologue' string."""
import re, struct
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

FLAG_KO = 0x0269C108
FLAG_VA = BASE + FLAG_KO
PROLOGUE_STR = None
for m in re.finditer(rb"authMgrPrologue", data):
    PROLOGUE_STR = BASE + m.start()
    print(f"'authMgrPrologue' string at {PROLOGUE_STR:#x} (koff {m.start():#x})")

# all rip-relative refs
REFS = []
o = 0
while o < len(data) - 7:
    b0, b1, b2 = data[o], data[o+1], data[o+2]
    if b0 in (0x48, 0x4c) and b1 in (0x8d, 0x8b, 0x89) and b2 in {0x05,0x0d,0x15,0x1d,0x2d,0x35,0x3d}:
        disp = struct.unpack_from("<i", data, o+3)[0]
        REFS.append((BASE + o, BASE + o + 7 + disp, {0x8d:'lea',0x8b:'load',0x89:'store'}[b1]))
    o += 1

print(f"\n=== refs to the prologue flag {FLAG_VA:#x} ===")
hits = [(a, k) for (a, t, k) in REFS if t == FLAG_VA]
for a, k in hits:
    print(f"  {k:5} @ {a:#x} (koff {a-BASE:#x})")
if not hits:
    print("  (none)")
print("  writers (store):", [hex(a) for a, k in hits if k == 'store'])

print(f"\n=== refs to 'authMgrPrologue' {PROLOGUE_STR:#x} ===" if PROLOGUE_STR else "no string")
if PROLOGUE_STR:
    ph = [(a, k) for (a, t, k) in REFS if t == PROLOGUE_STR]
    for a, k in ph:
        print(f"  {k:5} @ {a:#x} (koff {a-BASE:#x})")

# show code around each store to the flag
def show(vstart, n, label):
    print(f"\n--- {label} @ {vstart:#x} ---")
    for ins in md.disasm(data[vstart-BASE:vstart-BASE+n], vstart):
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

for a, k in hits:
    if k == 'store':
        show(a - 0x40, 0x50, "around store")
