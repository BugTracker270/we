#!/usr/bin/env python3
"""Compare the 13.52 kernel SELF against the 14.00 one, field by field.

Why this matters: the whole offline chain ends in "use the SELF keys to decrypt
the kernel SELF". A SELF header names which key bank it needs via key_type, and the
key revision is carried alongside. If 14.00's kernel SELF names the same bank as a
kernel we can already key, the offline route works; if Sony bumped the bank, it
does not. So compare rather than assume.
"""
import glob, hashlib, os, struct

CAND = []
for pat in (r'C:\Users\Kinan\Downloads\JV13.52\dec\**\*.self',
            r'C:\Users\Kinan\Downloads\JV13.52\dec\*.self',
            r'C:\Users\Kinan\Downloads\JV13.52\**\80010002*.self'):
    CAND += glob.glob(pat, recursive=True)
CAND = sorted(set(CAND))

print(f'{"file":<34} {"magic":>10} {"ver":>4} {"mode":>5} {"attr":>5} '
      f'{"key_type":>9} {"hdrsz":>6} {"meta":>6} {"nent":>5} {"filesz":>9} '
      f'{"sha1[:12]":>13}')
for f in CAND:
    d = open(f, 'rb').read()
    magic, ver, mode, endian, attr = struct.unpack_from('<IBBBB', d, 0)
    key_type, = struct.unpack_from('<I', d, 0x08)
    hdr, meta = struct.unpack_from('<HH', d, 0x0C)
    fsz, = struct.unpack_from('<Q', d, 0x10)
    nent, flags = struct.unpack_from('<HH', d, 0x18)
    sha = hashlib.sha1(d).hexdigest()[:12]
    print(f'{os.path.basename(f):<34} {magic:#010x} {ver:>4} {mode:>5} {attr:#5x} '
          f'{key_type:#9x} {hdr:#6x} {meta:#6x} {nent:>5} {fsz:>9} {sha:>13}')

# name the two we care about, if present
a = [f for f in CAND if os.path.basename(f) == '80010002.self']
b = [f for f in CAND if '14.00' in os.path.basename(f)]
if a and b:
    da, db = open(a[0], 'rb').read(), open(b[0], 'rb').read()
    print(f'\n80010002.self          size {len(da)}')
    print(f'80010002 14.00 kernel  size {len(db)}')
    n = min(len(da), len(db), 0x200)
    diff = [i for i in range(n) if da[i] != db[i]]
    print(f'bytes differing in first {n:#x}: {len(diff)}')
    if diff:
        print(f'  first differing offset: {diff[0]:#x}  '
              f'{da[diff[0]]:02x} -> {db[diff[0]]:02x}')
    print('\nfirst 0x40 bytes of each:')
    for i in range(0, 0x40, 16):
        print(f'  13.52 {i:#04x}: {da[i:i+16].hex(" ")}')
        print(f'  14.00 {i:#04x}: {db[i:i+16].hex(" ")}')
else:
    print('\n(one of the two kernel SELFs was not found)')
