#!/usr/bin/env python3
"""Hex+ASCII dump of arbitrary files (not the kernel image).

Usage: hexdump.py OFFSET LENGTH FILE [FILE...]
OFFSET/LENGTH accept hex (0x..) or decimal.
"""
import sys

off = int(sys.argv[1], 0)
ln = int(sys.argv[2], 0)
paths = sys.argv[3:]

for p in paths:
    try:
        with open(p, 'rb') as f:
            import os
            size = os.path.getsize(p)
            f.seek(off)
            b = f.read(ln)
    except Exception as e:
        print(f'{p}: {type(e).__name__}: {e}')
        continue
    print(f'=== {p}   (size {size} B)  from 0x{off:x}, 0x{len(b):x} B ===')
    for i in range(0, len(b), 16):
        row = b[i:i + 16]
        hx = ' '.join(f'{x:02x}' for x in row)
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in row)
        print(f'  {off + i:#08x}  {hx:<47}  {asc}')
    print()
