#!/usr/bin/env python3
"""Locate the encrypted region of each SLB2 blob, then try the published keys.

Two passes:
  1. block map - entropy + printable fraction per block, so the plaintext header
     and the ciphertext payload can be told apart structurally rather than guessed.
  2. key trials - AES-128-CBC with a zeroed IV (as the wiki specifies) at several
     candidate offsets, scored on printable-ASCII content. A correct key over an
     AMD EMC IPL body should yield mostly-printable/code-like output; a wrong key
     yields ~uniform random bytes (~0.36 printable by chance).
"""
import math, os

K_AEOLIA = bytes.fromhex('5F74FE7790127FECF82CC6E6D91FA2D1')   # EMC IPL Cipher Key
K_BELIZE = bytes.fromhex('1A4B4DC4179114F0A6B0266ACFC81193')   # EMC IPL Cipher Key
K_EAP    = bytes.fromhex('581A75D7E9C01F3C1BD7473DBD443B98')   # EAP KBL Cipher Key
KEYS = {'aeolia': K_AEOLIA, 'belize': K_BELIZE, 'eapkbl': K_EAP}

FILES = [
    r'C:\Users\Kinan\Downloads\JV13.52\dec\unpacked1\dev\sflash0s0x32b',
    r'C:\Users\Kinan\Downloads\JV13.52\dec\unpacked1\dev\sflash0s0x33',
    r'C:\Users\Kinan\Downloads\JV13.52\dec\unpacked1\dev\sflash0s1.cryptx2b',
]

try:
    from Crypto.Cipher import AES
    HAVE_AES = True
except Exception:
    HAVE_AES = False
    print('[!] pycryptodome not available - key trials will be skipped\n')


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


def printable_frac(b):
    if not b:
        return 0.0
    return sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / len(b)


BLK = 0x2000
for path in FILES:
    d = open(path, 'rb').read()
    print(f'=== {os.path.basename(path)}   {len(d)} B ===')
    print(f'{"off":>8} {"entropy":>8} {"print":>6}  sample')
    for i in range(0, len(d), BLK):
        b = d[i:i + BLK]
        if len(b) < 0x40:
            break
        smp = ''.join(chr(x) if 32 <= x < 127 else '.' for x in b[:32])
        print(f'{i:#8x} {entropy(b):8.3f} {printable_frac(b):6.2f}  {smp}')
    print()

if HAVE_AES:
    OFFSETS = [0x00, 0x40, 0x60, 0x100, 0x200, 0x240, 0x260, 0x267,
               0x280, 0x2C0, 0x300, 0x400, 0x500, 0x800, 0x1000]
    for path in FILES:
        d = open(path, 'rb').read()
        print(f'--- key trials: {os.path.basename(path)} ---')
        for off in OFFSETS:
            if off + 0x200 > len(d):
                continue
            row = [f'{off:#06x}']
            for name, k in KEYS.items():
                try:
                    pt = AES.new(k, AES.MODE_CBC, b'\x00' * 16).decrypt(d[off:off + 0x200])
                except Exception as e:
                    row.append(f'{name}=ERR')
                    continue
                row.append(f'{name}: print={printable_frac(pt):.2f} '
                           f'|{"".join(chr(x) if 32 <= x < 127 else "." for x in pt[:24])}|')
            print('   ' + '   '.join(row))
        print()
