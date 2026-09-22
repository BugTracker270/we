#!/usr/bin/env python3
"""Is the AuthMgr SELF we already have ENCRYPTED or DECRYPTED?

Definitive test: a decrypted SELF has a plaintext ELF header at its segment
offset. An encrypted one has ciphertext there. Check offset-0x13E0 for
80010008 (its seg0 offset, per the payload's own report) and generally for all
the 1352 modules.

If any of these is already decrypted, 80010008.py can run on it right now and the
entire key chain is unnecessary.
"""
import math, os, struct, glob

DIRS = [r'C:\Users\Kinan\Downloads\JV13.52\dec\1352',
        r'C:\Users\Kinan\Downloads\JV13.52\dec']


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


files = []
for d in DIRS:
    files += glob.glob(os.path.join(d, '*.self'))
files = sorted(set(files))

for f in files:
    d = open(f, 'rb').read()
    magic, ver, mode, endian, attr = struct.unpack_from('<IBBBB', d, 0)
    key_type, = struct.unpack_from('<I', d, 8)
    hdr, meta = struct.unpack_from('<HH', d, 0x0C)
    fsz, = struct.unpack_from('<Q', d, 0x10)
    nent, fl = struct.unpack_from('<HH', d, 0x18)
    print(f'\n=== {os.path.basename(f)}  ({len(d)} B)')
    print(f'    key_type={key_type:#x} hdr={hdr:#x} meta={meta:#x} '
          f'entries={nent} file_size={fsz}')
    for i in range(min(nent, 4)):
        b = 0x20 + i * 0x20
        flg, off, sz, t = struct.unpack_from('<QQQQ', d, b)
        seg = d[off:off + min(sz, 0x1000)]
        is_elf = seg[:4] == b'\x7fELF'
        print(f'    entry[{i}] flags={flg:#x} offset={off:#x} size={sz:#x} '
              f'-> magic={seg[:4].hex()} {"*** PLAINTEXT ELF ***" if is_elf else ""}'
              f'  entropy={entropy(seg):.2f}')
        print(f'        head: {seg[:32].hex()}')
    # whole-file entropy of the tail (past header+meta) tells encrypted vs not
    tail = d[hdr + meta:]
    print(f'    tail after hdr+meta: {len(tail)} B  entropy={entropy(tail[:0x4000]):.2f}'
          f'  (8.0 = encrypted, ~6 or less = code/data)')
