#!/usr/bin/env python3
"""Hex+ASCII dump of a koff range, plus every plausible function-entry prologue
found in it (with the preceding bytes shown), so an entry point can be located
even when the padding byte before it is not the usual 0x90/0xc3/0xcc.

Usage: inspect_range.py LO_KOFF HI_KOFF [dump|entries]
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
        SEGS.append((va - KBASE, po, fsz, msz, fl))
SEGS.sort()


def koff2foff(k):
    for ko, po, fsz, msz, fl in SEGS:
        if ko <= k < ko + fsz:
            return po + (k - ko)
    return None


def rd(k, n):
    o = koff2foff(k)
    return b'' if o is None else d[o:o + n]


LO = int(sys.argv[1], 16)
HI = int(sys.argv[2], 16)
mode = sys.argv[3] if len(sys.argv) > 3 else 'entries'

if mode == 'dump':
    a = LO
    while a < HI:
        b = rd(a, 16)
        hx = ' '.join(f'{x:02x}' for x in b)
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in b)
        print(f'  {a:06x}  {hx:<47}  {asc}')
        a += 16
else:
    print(f'--- prologues in [0x{LO:x},0x{HI:x}) ---')
    p = LO
    while p < HI - 4:
        if rd(p, 4) == b'\x55\x48\x89\xe5':
            prev8 = rd(p - 8, 8)
            flag = 'OK ' if prev8[-1:] in (b'\x90', b'\xc3', b'\xcc', b'\x5d', b'\x00') else '?? '
            print(f'  {flag} entry 0x{p:06x}   prev8 {prev8.hex(" ")}')
        p += 1
    for pat in (b'\xf3\x0f\x1e\xfa', b'\x55\x53\x48\x89'):
        p = LO
        while p < HI - 4:
            if rd(p, len(pat)) == pat:
                print(f'  ---  other prologue 0x{p:06x}  {pat.hex(" ")}'
                      f'   prev4 {rd(p - 4, 4).hex(" ")}')
            p += 1
