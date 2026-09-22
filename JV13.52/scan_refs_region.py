#!/usr/bin/env python3
"""Disassembly-independent RIP-relative reference scanner over a koff RANGE.

Beats xref_koff.py because it never linear-disassembles the image (capstone
desyncs on this 13.52 build after ~12 instructions), so it cannot silently miss
a reference.  Method:

  * a RIP-relative memory operand is ModRM with mod=00, rm=101
    -> byte pattern (b & 0xC7) == 0x05 immediately followed by disp32
  * target_koff = (modrm_file_off + insn_tail) + disp32
        insn_tail = 5 normally, 6 when an imm8 follows, 9 when an imm32 follows
  * every candidate whose target lands in [LO,HI) is reported with the 14 bytes
    preceding the ModRM, so the opcode can be read off directly.

Usage: scan_refs_region.py LO HI   (hex koffs)
"""
import struct, sys, collections

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


def koff2foff(k):
    for ko, po, fsz, msz, fl in SEGS:
        if ko <= k < ko + fsz:
            return po + (k - ko)
    return None


def foff2koff(o):
    for ko, po, fsz, msz, fl in SEGS:
        if po <= o < po + fsz:
            return ko + (o - po)
    return None


def rd(k, n):
    o = koff2foff(k)
    return None if o is None else d[o:o + n]


LO = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x269C2E0
HI = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x269C380

# text segment (first executable PT_LOAD) is what we scan
TEXT_BASE, TEXT_FOFF, TEXT_FSZ, _, _ = SEGS[0]
tb = d[TEXT_FOFF:TEXT_FOFF + TEXT_FSZ]
print(f"[i] scanning koff 0x{TEXT_BASE:x}..0x{TEXT_BASE + TEXT_FSZ:x} "
      f"({TEXT_FSZ:,} B) for refs into [0x{LO:x},0x{HI:x})")

hits = collections.defaultdict(list)
n_modrm = 0
for p in range(len(tb) - 9):
    if (tb[p] & 0xC7) != 0x05:
        continue
    n_modrm += 1
    disp, = struct.unpack_from('<i', tb, p + 1)
    for tail in (5, 6, 9):
        # target_koff = modrm_koff + tail + disp32
        t = TEXT_BASE + p + tail + disp
        if LO <= t < HI:
            pre = tb[max(0, p - 14):p + 1].hex(' ')
            hits[t].append((TEXT_BASE + p, tail, pre))

print(f"[i] {n_modrm:,} RIP-ModRM candidates; {len(hits)} targets matched")

for t in sorted(hits):
    print(f"\n=== koff 0x{t:06x} ===")
    for site, tail, pre in sorted(set(hits[t])):
        print(f"   insn-koff ~0x{site:06x}  tail={tail}  bytes: {pre}")
