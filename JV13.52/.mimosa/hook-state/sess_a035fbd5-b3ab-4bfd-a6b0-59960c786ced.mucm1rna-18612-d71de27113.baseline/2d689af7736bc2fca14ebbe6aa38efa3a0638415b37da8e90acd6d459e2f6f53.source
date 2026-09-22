#!/usr/bin/env python3
"""Probe the odd low-entropy region in 80010001.self (the Secure Kernel).

Every other module's segments sit at entropy 7.95+. 80010001's region after
hdr+meta sits at 5.01, and its segment 0 is only 0x54 bytes - so something there is
not ciphertext. Map it block by block and dump whatever is structured.

Context: Al-Azif's 80010001.py extracts the System Module keyset from a decrypted
Secure Kernel. If any of our files has readable structure, it should be this one.
"""
import math, struct

F = r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\80010001.self'
d = open(F, 'rb').read()

magic, ver, mode, endian, attr = struct.unpack_from('<IBBBB', d, 0)
key_type, = struct.unpack_from('<I', d, 8)
hdr, meta = struct.unpack_from('<HH', d, 0x0C)
fsz, = struct.unpack_from('<Q', d, 0x10)
nent, fl = struct.unpack_from('<HH', d, 0x18)
base = hdr + meta
print(f'{F}\n  size {len(d)}  key_type={key_type:#x} hdr={hdr:#x} meta={meta:#x} '
      f'hdr+meta={base:#x} entries={nent}')
for i in range(min(nent, 4)):
    b = 0x20 + i * 0x20
    fl2, off, sz, t = struct.unpack_from('<QQQQ', d, b)
    print(f'  entry[{i}] flags={fl2:#x} offset={off:#x} size={sz:#x}')


def entropy(b):
    if not b:
        return 0.0
    n = len(b)
    c = [0] * 256
    for x in b:
        c[x] += 1
    h = 0.0
    for v in c:
        if v:
            p = v / n
            h -= p * math.log2(p)
    return h


print(f'\nper-0x100 entropy from {base:#x} to 0x3000 (8.0=cipher, <5=structured):')
for i in range(base, 0x3000, 0x100):
    b = d[i:i + 0x100]
    if len(b) < 0x100:
        break
    h = entropy(b)
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in b[:24])
    flag = '  <<< LOW' if h < 6.0 else ''
    print(f'  {i:#06x}  {h:5.2f}  |{asc}|{flag}')

print(f'\nhexdump of {base:#x}..{base+0x180:#x}:')
for i in range(base, base + 0x180, 16):
    b = d[i:i + 16]
    hx = ' '.join(f'{x:02x}' for x in b)
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in b)
    print(f'  {i:#06x}  {hx:<47}  {asc}')
