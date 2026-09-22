#!/usr/bin/env python3
"""Find direct callers of a koff, handling BOTH `call rel32` (E8) and the
tail-jump form `jmp rel32` (E9).  Missing E9 is what previously made
_sceSblAuthMgrSmVerifyHeader look like dead code.

Maps file offset -> koff through the ELF PT_LOADs, so it is correct even when
p_offset != vaddr (find_callers.py assumed they were equal).

Usage: callers.py KOFF [KOFF...]
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
        SEGS.append((po, fsz, va - KBASE))


def foff2koff(o):
    for po, fsz, ko in SEGS:
        if po <= o < po + fsz:
            return ko + (o - po)
    return None


TARGETS = {int(a, 16) for a in sys.argv[1:]}
hits = collections.defaultdict(list)
n = len(d)
for off in range(0, n - 5):
    op = d[off]
    if op != 0xE8 and op != 0xE9:
        continue
    src = foff2koff(off)
    if src is None:
        continue
    disp, = struct.unpack_from('<i', d, off + 1)
    tgt = src + 5 + disp
    if tgt in TARGETS:
        hits[tgt].append((src, 'call' if op == 0xE8 else 'JMP '))

for t in sorted(TARGETS):
    print(f'target 0x{t:06x}: {len(hits[t])} direct site(s)')
    for s, k in sorted(set(hits[t])):
        print(f'    {k} at 0x{s:06x}')
