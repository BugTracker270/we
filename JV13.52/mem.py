#!/usr/bin/env python3
"""Dump bytes by FILE OFFSET (not koff) and annotate the koff, for looking at
pointer tables that find_refs.py located.

Usage: mem.py foff OFFSET LEN   |   mem.py koff OFFSET LEN
"""
import struct, sys

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
        SEGS.append((po, fsz, va - KBASE, msz, fl))
SEGS.sort()
for po, fsz, ko, msz, fl in SEGS:
    print(f'[seg] foff 0x{po:x}..0x{po+fsz:x}  koff 0x{ko:x}..0x{ko+fsz:x}  '
          f'filesz 0x{fsz:x} memsz 0x{msz:x} fl {fl}')


def foff2koff(o):
    for po, fsz, ko, msz, fl in SEGS:
        if po <= o < po + fsz:
            return ko + (o - po)
    return None


def koff2foff(k):
    for po, fsz, ko, msz, fl in SEGS:
        if ko <= k < ko + fsz:
            return po + (k - ko)
    return None


mode = sys.argv[1]
off = int(sys.argv[2], 16)
ln = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x40
if mode == 'koff':
    off = koff2foff(off)

a = off
while a < off + ln:
    b = d[a:a + 16]
    hx = ' '.join(f'{x:02x}' for x in b)
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in b)
    ko = foff2koff(a)
    ktxt = f'koff {ko:#010x}' if ko is not None else 'koff --'
    print(f'  foff {a:#09x}  {ktxt}  {hx:<47}  {asc}')
    a += 16
