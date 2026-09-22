#!/usr/bin/env python3
"""Locate and decrypt the EMC IPL / Secure Loader bodies.

Three independent probes:
  A. HMAC oracle. The wiki says the EMC IPL Hasher Key is HMAC-SHA1 over the IPL's
     0x6C-byte header. So for every candidate header offset, compute
     HMAC-SHA1(hasher_key, 0x6C bytes) and look for that digest anywhere in the
     file. A hit both locates the header and proves the hasher key is right.
  B. Fine entropy map of the first 0x2000, where the small entries live.
  C. AES-128-CBC zero-IV trials at candidate body offsets with the published
     cipher keys, scored on printable-ASCII content.
"""
import hashlib, hmac, math, os
from Crypto.Cipher import AES

ROOT = r'C:\Users\Kinan\Downloads\JV13.52\dec\unpacked1\dev'
FILES = ['sflash0s0x32b', 'sflash0s0x33', 'sflash0s1.cryptx2b']

K = {
    'aeolia': bytes.fromhex('5F74FE7790127FECF82CC6E6D91FA2D1'),
    'belize': bytes.fromhex('1A4B4DC4179114F0A6B0266ACFC81193'),
    'eapkbl': bytes.fromhex('581A75D7E9C01F3C1BD7473DBD443B98'),
}
HASHERS = {
    'aeolia_hasher': bytes.fromhex('73FE06F3906B05ECB506DFB8691F9F54'),
    'eap_hasher':    bytes.fromhex('824D9BB4DBA3209294C93976221249E4'),
}


def printable_frac(b):
    if not b:
        return 0.0
    return sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / len(b)


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


def asc(b, n=32):
    return ''.join(chr(x) if 32 <= x < 127 else '.' for x in b[:n])


for fn in FILES:
    path = os.path.join(ROOT, fn)
    d = open(path, 'rb').read()
    print(f'\n########## {fn}  ({len(d)} B) ##########')

    # ---------- A. HMAC oracle ----------
    windows = set()
    for i in range(len(d) - 20 + 1):
        windows.add(d[i:i + 20])
    print(' A. HMAC oracle over 0x6C-byte header candidates in first 0x2000:')
    any_hit = False
    for hname, hkey in HASHERS.items():
        for off in range(0, 0x2000):
            dig = hmac.new(hkey, d[off:off + 0x6C], hashlib.sha1).digest()
            if dig in windows:
                where = d.find(dig)
                print(f'      HIT {hname} header@{off:#06x} digest stored@{where:#x}')
                any_hit = True
    if not any_hit:
        print('      no match (header is probably encrypted, or offset/magic differs)')

    # ---------- B. fine entropy map ----------
    print(' B. first 0x2400, 0x100 blocks:')
    line = []
    for i in range(0, 0x2400, 0x100):
        b = d[i:i + 0x100]
        line.append(f'{i:#06x}:{entropy(b):.1f}')
    for i in range(0, len(line), 6):
        print('      ' + '  '.join(line[i:i + 6]))

    # ---------- C. AES trials ----------
    print(' C. AES-128-CBC zero-IV trials:')
    for off in (0x120, 0x200, 0x320, 0x400, 0x480, 0x600, 0x2000, 0x3000):
        if off + 0x100 > len(d):
            continue
        parts = []
        for kname, k in K.items():
            pt = AES.new(k, AES.MODE_CBC, b'\x00' * 16).decrypt(d[off:off + 0x100])
            parts.append(f'{kname} p={printable_frac(pt):.2f} |{asc(pt, 20)}|')
        print(f'      {off:#06x}  ' + '   '.join(parts))

    # double-layer trial for aeolia at the two most likely offsets
    print(' C2. aeolia then belize (two layers, as the wiki describes):')
    for off in (0x200, 0x320, 0x2000):
        if off + 0x100 > len(d):
            continue
        pt = AES.new(K['aeolia'], AES.MODE_CBC, b'\x00' * 16).decrypt(d[off:off + 0x100])
        pt2 = AES.new(K['belize'], AES.MODE_CBC, b'\x00' * 16).decrypt(pt)
        pt3 = AES.new(K['aeolia'], AES.MODE_CBC, b'\x00' * 16).decrypt(pt)
        print(f'      {off:#06x}  a->b p={printable_frac(pt2):.2f} |{asc(pt2, 20)}|'
              f'   a->a p={printable_frac(pt3):.2f} |{asc(pt3, 20)}|')
