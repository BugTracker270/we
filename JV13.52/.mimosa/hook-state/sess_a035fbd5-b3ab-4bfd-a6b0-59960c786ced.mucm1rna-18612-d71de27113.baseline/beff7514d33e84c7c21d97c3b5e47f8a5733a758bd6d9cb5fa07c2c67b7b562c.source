"""Dedupe the SM-block refs, isolate the WRITERS, then disassemble
_sceSblAuthMgrSmStart (koff 0x63e470) which appears to write the flags."""
import struct, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ELF = r"C:\Users\Kinan\Downloads\czdji0\1352k.elf"
data = open(ELF, "rb").read()
BASE = 0xffffffff82200000
TEXT_END = 0x00cfe758
md = Cs(CS_ARCH_X86, CS_MODE_64)

MODRM_RIP = {0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d}
REX = set(range(0x40, 0x50))

OP1 = {op: 0 for op in (0x88, 0x89, 0x8A, 0x8B, 0x38, 0x39, 0x3A, 0x3B, 0x84,
                        0x85, 0x86, 0x87, 0x20, 0x21, 0x22, 0x23, 0x28, 0x29,
                        0x2A, 0x2B, 0x30, 0x31, 0x32, 0x33, 0x08, 0x09, 0x0A,
                        0x0B, 0x10, 0x11, 0x18, 0x19, 0xFE, 0xFF)}
OP1[0x80] = 1; OP1[0x83] = 1; OP1[0xC6] = 1
OP1[0x81] = 4; OP1[0xC7] = 4
for op in range(0xB0, 0xB8): OP1[op] = 1
OP2 = {op: 0 for op in (0xB6, 0xB7, 0xBE, 0xBF)}
for op in range(0x40, 0x50): OP2[op] = 0
for op in range(0x90, 0xA0): OP2[op] = 0

# call targets, for enclosing-function lookup
CALLS = []
i = 0
lim = min(TEXT_END, len(data)) - 5
while i < lim:
    if data[i] == 0xE8:
        rel = struct.unpack_from("<i", data, i + 1)[0]
        t = BASE + i + 5 + rel
        if BASE <= t < BASE + TEXT_END:
            CALLS.append(t)
    i += 1
CALLS.sort()

def enclosing(v):
    lo, hi, best = 0, len(CALLS) - 1, None
    while lo <= hi:
        m = (lo + hi) // 2
        if CALLS[m] <= v: best = CALLS[m]; lo = m + 1
        else: hi = m - 1
    return best

LO, HI = 0x0269C000, 0x0269C160
seen = set()
hits = []
for o in range(0, min(TEXT_END, len(data)) - 8):
    b = data[o]
    info = None
    if b in REX:
        op = data[o + 1]
        if op in OP1 and data[o + 2] in MODRM_RIP:
            info = (o, o + 3, 7 + OP1[op], op, data[o + 2], True)
        elif op == 0x0F and data[o + 2] in OP2 and data[o + 3] in MODRM_RIP:
            info = (o, o + 4, 8, op, data[o + 3], True)
    elif b == 0x0F and data[o + 1] in OP2 and data[o + 2] in MODRM_RIP:
        info = (o, o + 3, 7, data[o + 1], data[o + 2], False)
    elif b in OP1 and data[o + 1] in MODRM_RIP:
        info = (o, o + 2, 6 + OP1[b], b, data[o + 1], False)
    if not info:
        continue
    o0, dpos, ln, op, modrm, was_rex = info
    if (o0, op) in seen:
        continue
    seen.add((o0, op))
    disp = struct.unpack_from("<i", data, dpos)[0]
    ko = o0 + ln + disp
    if LO <= ko < HI:
        reg = (modrm >> 3) & 7
        is_store = op in (0x88, 0x89, 0xC6, 0xC7, 0x80, 0x81, 0x83, 0xFE, 0x00) or (op in (0x80,0x81,0x83) and reg != 7)
        hits.append((BASE + o0, ko, op, reg, was_rex, is_store))

print("=== WRITERS into the SM block ===")
for (a, ko, op, reg, rex, st) in hits:
    if not st:
        continue
    print(f"  {a:#x} (koff {a-BASE:#x})  op {op:#04x}/reg{reg} -> koff {ko:#x}"
          f"   fn {enclosing(a):#x}")

print("\n=== all refs to the key slots ===")
for key in (0x0269C098, 0x0269C0A0, 0x0269C0A8, 0x0269C108, 0x0269C110, 0x0269C130):
    rs = [(a, op, st) for (a, ko, op, reg, rex, st) in hits if ko == key]
    print(f"  koff {key:#x}: {len(rs)} refs")
    for (a, op, st) in rs[:6]:
        print(f"      {a:#x}  op {op:#04x} {'STORE' if st else 'load'}"
              f"  fn {enclosing(a):#x}")

print("\n=== _sceSblAuthMgrSmStart @ koff 0x63e470 ===")
KO = 0x0063e470
def cstr(v):
    if not (BASE <= v < BASE + 0x10000000): return None
    o = v - BASE
    if o < 0 or o >= len(data): return None
    e = data.find(b"\x00", o, o + 80)
    if e < 0: return None
    s = data[o:e]
    return s.decode() if len(s) >= 4 and all(32 <= c < 127 for c in s) else None

for ins in md.disasm(data[KO:KO + 0x150], BASE + KO):
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
