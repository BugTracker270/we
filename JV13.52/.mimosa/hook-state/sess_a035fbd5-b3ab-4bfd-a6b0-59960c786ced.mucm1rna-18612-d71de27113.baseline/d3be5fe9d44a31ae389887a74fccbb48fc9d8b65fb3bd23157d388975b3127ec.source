#!/usr/bin/env python3
"""The MapPages/UnmapPages *call sites* are known (0x627a08, 0x635c18, 0x63ac3c,
0x6459be, 0x653ed8, 0x6546fc, 0x655046, 0x69c758 ...). Disassemble those
functions and read out the call target that precedes the error log."""
import struct, re, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ELF   = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KBASE = 0xffffffff82200000
d = open(ELF, 'rb').read()
e_phoff, = struct.unpack_from('<Q', d, 0x20)
e_phentsize, e_phnum = struct.unpack_from('<HH', d, 0x36)
SEGS = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t, fl, po, va, pa, fsz, msz, al = struct.unpack_from('<IIQQQQQQ', d, o)
    if t == 1:
        SEGS.append((va - KBASE, po, fsz, msz, fl))
SEGS.sort()
TB0 = SEGS[0][0]
tb = d[SEGS[0][1]:SEGS[0][1] + SEGS[0][2]]
def rd(k, n):
    o = k - TB0
    return tb[o:o + n] if 0 <= o < len(tb) else None
def foff2koff(o):
    for ko, po, fsz, msz, fl in SEGS:
        if po <= o < po + fsz:
            return ko + (o - po)
    return None

# strings in the SBL log cluster
print("=== strings koff 0xae6100..0xae6400 and 0xae9400..0xae9500 ===")
for m in re.finditer(rb'[ -~]{5,}', d):
    ko = foff2koff(m.start())
    if ko is None: continue
    if 0xae6100 <= ko < 0xae6400 or 0xae9400 <= ko < 0xae9500:
        print(f"  0x{ko:08x}  {m.group().decode('ascii')}")

md = Cs(CS_ARCH_X86, CS_MODE_64)

def targets(kstart, kend, label):
    buf = rd(kstart, kend - kstart)
    if not buf:
        print(f"\n### {label}: no bytes"); return
    print(f"\n### {label}  0x{kstart:08x}..0x{kend:08x}  -- notable instructions")
    prev = []
    for ins in md.disasm(buf, KBASE + kstart):
        k = ins.address - KBASE
        if ins.mnemonic == 'call' and ins.op_str.startswith('0x'):
            t = int(ins.op_str, 16) - KBASE
            ctx = '  |  '.join(prev[-4:])
            print(f"  call 0x{k:08x} -> koff 0x{t:08x}      [{ctx}]")
            prev = []
        else:
            s = f"{ins.mnemonic} {ins.op_str}"
            if '[rip' in s or ins.mnemonic in ('lea', 'mov', 'movabs'):
                prev.append(f"{ins.mnemonic} {ins.op_str}")
            else:
                prev.append(f"{ins.mnemonic} {ins.op_str}")
        if ins.mnemonic == 'ret':
            prev = []

targets(0x00627910, 0x00627C00, 'caller of MapPages @0x627a08')
targets(0x00628000, 0x00628120, 'caller of MapPages @0x628099')
targets(0x00635AD0, 0x00635C60, 'caller of MapPages @0x635c18')
