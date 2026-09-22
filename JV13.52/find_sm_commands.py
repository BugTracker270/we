"""Find every caller of the smreq shim and recover the SM command argument each
one passes, so the decrypter can issue the right commands."""
import re
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ELF = r"C:\Users\Kinan\Downloads\czdji0\1352k.elf"
data = open(ELF, "rb").read()
BASE = 0xffffffff82200000
md = Cs(CS_ARCH_X86, CS_MODE_64)

SHIM = 0xffffffff8283d0a0      # reorders args, then calls smreq
SMREQ = 0xffffffff8283fff0

def callers(target):
    out = []
    for i in range(0, len(data) - 5):
        if data[i] == 0xE8:
            rel = struct.unpack_from("<i", data, i + 1)[0]
            v = BASE + i
            if v + 5 + rel == target:
                out.append(v)
    return out

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
    if len(s) >= 3 and all(32 <= c < 127 for c in s):
        return s.decode()
    return None

def show_before(callva, nbytes=0x60):
    print(f"\n--- args before call at {callva:#x} ---")
    start = callva - nbytes
    o = start - BASE
    for ins in md.disasm(data[o:o + nbytes + 5], start):
        s = f"{ins.mnemonic} {ins.op_str}"
        note = ""
        m = re.search(r"\[rip \+ (0x[0-9a-f]+)\]", s)
        if m:
            tgt = ins.address + ins.size + int(m.group(1), 16)
            st = cstr(tgt)
            note = f'   -> "{st}"' if st else f"   -> {tgt:#x}"
        if ins.address == callva:
            note += "   <<< CALL"
        print(f"    {ins.address:#x}  {s}{note}")
        if ins.address >= callva:
            break

print(f"callers of SHIM  {SHIM:#x}: {[hex(c) for c in callers(SHIM)]}")
print(f"callers of SMREQ {SMREQ:#x}: {[hex(c) for c in callers(SMREQ)]}")

for c in callers(SHIM)[:6]:
    show_before(c)
