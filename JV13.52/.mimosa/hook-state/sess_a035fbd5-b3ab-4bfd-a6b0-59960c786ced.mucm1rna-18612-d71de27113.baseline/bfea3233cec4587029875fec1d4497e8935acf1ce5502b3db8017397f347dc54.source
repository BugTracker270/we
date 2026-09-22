#!/usr/bin/env python3
"""Print NUL-terminated strings at given koffs.  Usage: readstr.py 0xAEA62F ..."""
import sys

ELF = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
d = open(ELF, 'rb').read()
for a in sys.argv[1:]:
    o = int(a, 16)
    e = d.find(b'\x00', o)
    print(f"0x{o:06x}: {d[o:e].decode('latin1')!r}")
