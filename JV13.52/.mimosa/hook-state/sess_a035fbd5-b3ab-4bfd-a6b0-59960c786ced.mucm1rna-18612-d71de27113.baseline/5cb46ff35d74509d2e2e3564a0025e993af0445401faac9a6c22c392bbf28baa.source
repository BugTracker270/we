"""Deterministic RIP-relative reference scanner covering the opcode forms the
first pass missed (cmp/test/movz/setcc, non-REX byte ops, etc.)."""
import struct

ELF = r"C:\Users\Kinan\Downloads\czdji0\1352k.elf"
data = open(ELF, "rb").read()
BASE = 0xffffffff82200000
TEXT_END = 0x00cfe758

MODRM_RIP = {0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d}
REX = set(range(0x40, 0x50))

# opcode -> extra immediate bytes after disp32
OP1 = {}
for op in (0x88, 0x89, 0x8A, 0x8B, 0x38, 0x39, 0x3A, 0x3B, 0x84, 0x85,
           0x86, 0x87, 0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2A, 0x2B,
           0x30, 0x31, 0x32, 0x33, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x11,
           0x18, 0x19, 0xFE, 0xFF):
    OP1[op] = 0
OP1[0x80] = 1
OP1[0x83] = 1
OP1[0xC6] = 1
OP1[0x81] = 4
OP1[0xC7] = 4
for op in range(0xB0, 0xB8):        # mov r8, imm8
    OP1[op] = 1

OP2 = {}
for op in (0xB6, 0xB7, 0xBE, 0xBF):          # movzx / movsx
    OP2[op] = 0
for op in range(0x40, 0x50):                 # cmovcc
    OP2[op] = 0
for op in range(0x90, 0xA0):                 # setcc
    OP2[op] = 0

LO, HI = 0x0269C000, 0x0269C160      # koff range of the SM block

hits = []
n = 0
for o in range(0, min(TEXT_END, len(data)) - 8):
    b = data[o]
    info = None
    if b in REX:
        if o + 8 > len(data):
            continue
        op = data[o + 1]
        if op in OP1:
            modrm = data[o + 2]
            if modrm in MODRM_RIP:
                info = (o, o + 3, 7 + OP1[op], f"rex {op:#04x}")
        elif op == 0x0F and data[o + 2] in OP2:
            if data[o + 3] in MODRM_RIP:
                info = (o, o + 4, 8, f"rex0f {data[o+2]:#04x}")
    elif b == 0x0F and o + 7 <= len(data):
        op = data[o + 1]
        if op in OP2 and data[o + 2] in MODRM_RIP:
            info = (o, o + 3, 7, f"0f {op:#04x}")
    elif b in OP1:
        if o + 7 > len(data):
            continue
        if data[o + 1] in MODRM_RIP:
            info = (o, o + 2, 6 + OP1[b], f"{b:#04x}")
    if not info:
        continue
    o0, dpos, ln, kind = info
    disp = struct.unpack_from("<i", data, dpos)[0]
    tgt_ko = (o0 + ln + disp)
    n += 1
    if LO <= tgt_ko < HI:
        mn = {0x88: "mov", 0x89: "mov", 0x8A: "mov", 0x8B: "mov",
              0x38: "cmp", 0x39: "cmp", 0x3A: "cmp", 0x3B: "cmp",
              0x84: "test", 0x85: "test", 0xC6: "mov", 0xC7: "mov",
              0x80: "grp1", 0x81: "grp1", 0x83: "grp1"}.get(b, kind)
        hits.append((BASE + o0, mn, kind, tgt_ko))

print(f"RIP-relative refs scanned: {n}")
print(f"refs into koff [{LO:#x},{HI:#x}): {len(hits)}\n")
for (a, mn, kind, t) in hits:
    print(f"  {a:#x} (koff {a-BASE:#x})  {mn:5} {kind:10} -> koff {t:#x}")

# which are stores (writes)?
print("\nstores (first byte of opcode 0x88/0x89/0xC6/0xC7/0x80/0x81/0x83 -> could be store or group):")
for (a, mn, kind, t) in hits:
    o = a - BASE
    b = data[o + 1] if data[o] in REX else data[o]
    if b in (0x88, 0x89, 0xC6, 0xC7):
        print(f"  *** STORE at {a:#x} -> koff {t:#x}  ({kind})")
    elif b in (0x80, 0x81, 0x83):
        reg = (data[o + 2] if data[o] in REX else data[o + 1]) >> 3
        if reg == 0:      # /0 = add -> not a store
            pass
        else:
            print(f"  *** group1/{reg} at {a:#x} -> koff {t:#x} ({kind})")
