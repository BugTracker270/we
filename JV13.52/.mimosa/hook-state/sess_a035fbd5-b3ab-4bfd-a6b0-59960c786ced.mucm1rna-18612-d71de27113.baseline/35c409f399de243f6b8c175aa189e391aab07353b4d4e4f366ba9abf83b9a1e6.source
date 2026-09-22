#!/usr/bin/env python3
"""Parse SELF headers we care about."""
import struct, os

FILES = [
    r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\80010008.self',
    r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\80010002.self',
    r'C:\Users\Kinan\Downloads\JV13.52\dec\80010002_kernel_14.00.self',
    r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\80010001.self',
]
for p in FILES:
    if not os.path.exists(p):
        print(f"MISSING {p}"); continue
    d = open(p, 'rb').read()
    magic, = struct.unpack_from('<I', d, 0)
    ver, mode, endian, attr = d[4], d[5], d[6], d[7]
    key_type, = struct.unpack_from('<I', d, 8)
    hsize, msize = struct.unpack_from('<HH', d, 0x0C)
    fsize, = struct.unpack_from('<Q', d, 0x10)
    nseg, flags = struct.unpack_from('<HH', d, 0x18)
    print(f"\n=== {os.path.basename(p)}  ({len(d):,} B) ===")
    print(f"  magic 0x{magic:08x}  ver {ver} mode {mode} endian {endian} attr {attr}")
    print(f"  key_type 0x{key_type:08x}  header_size 0x{hsize:x}  meta_size 0x{msize:x}"
          f"  hdr+meta 0x{hsize+msize:x}")
    print(f"  file_size 0x{fsize:x} ({fsize:,})  segments {nseg}  flags 0x{flags:x}")
    for i in range(min(nseg, 8)):
        off = 0x20 + i * 0x20
        f, o, cs, us = struct.unpack_from('<QQQQ', d, off)
        bits = []
        for nm, b in [('ORD',0),('ENC',1),('SIG',2),('CMP',3),('BLK',11),('DIG',16),('EXT',17)]:
            if f & (1 << b): bits.append(nm)
        print(f"    seg[{i}] flags=0x{f:010x} off=0x{o:x} csize=0x{cs:x} usize=0x{us:x}"
              f"  idx={(f>>20)&0xfff}  [{'|'.join(bits)}]")
