#!/usr/bin/env python3
"""Search the image for a koff stored as data (4- and 8-byte little endian) and
for call/jmp rel32 sites. Tells us whether a function is reachable via a table.
"""
import struct, sys

ELF = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
d = open(ELF, 'rb').read()
KB = 0xffffffff82200000

for a in sys.argv[1:]:
    v = int(a, 16)
    p4 = struct.pack('<I', v)
    p8 = struct.pack('<Q', KB + v)
    i4, i8, out = [], [], []
    off = 0
    while True:
        k = d.find(p4, off)
        if k < 0:
            break
        i4.append(k)
        off = k + 1
    off = 0
    while True:
        k = d.find(p8, off)
        if k < 0:
            break
        i8.append(k)
        off = k + 1
    # E8 rel32 call sites
    off = 0
    while True:
        k = d.find(b'\xe8', off)
        if k < 0 or k > len(d) - 5:
            break
        off = k + 1
        disp = struct.unpack_from('<i', d, k + 1)[0]
        if KB + k + 5 + disp - KB == v:
            out.append(k)
    print(f"0x{v:06x}:")
    print(f"   u32 immediates/data: {[hex(x) for x in i4]}")
    print(f"   u64 (VA)      data : {[hex(x) for x in i8]}")
    print(f"   E8 call sites      : {[hex(x) for x in out]}")
