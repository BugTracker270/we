#!/usr/bin/env python3
"""Identify the southbridge / platform from the extracted PUP tree.

The published EMC IPL / EAP KBL cipher keys exist only for Aeolia and Belize. If
this machine is Baikal or Torus, no published key applies and hand-decrypting the
blobs is futile - so establish the platform BEFORE more crypto work.

Codename map (PS4 revisions):
    Aeolia  - CUH-1000 / 1100   (original)
    Belize  - CUH-1200          (first slim revision)
    Baikal  - CUH-2000 / 2100   (Slim)
    Torus   - CUH-7000 / 7100   (Pro)
    Salina  - PS4 Pro later southbridge
"""
import os

ROOT = r'C:\Users\Kinan\Downloads\JV13.52\dec'
CHUNK = 1 << 23
OVERLAP = 32

TERMS = [b'Aeolia', b'Belize', b'Baikal', b'Torus', b'Salina',
         b'aeria', b'AERIA', b'belize', b'torus', b'baikal']

files = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    for fn in filenames:
        files.append(os.path.join(dirpath, fn))
files.sort()

for path in files:
    size = os.path.getsize(path)
    rel = path.replace(ROOT, '').lstrip('\\')
    found = {}
    with open(path, 'rb') as f:
        off = 0
        prev = b''
        while True:
            buf = f.read(CHUNK)
            if not buf:
                break
            hay = prev + buf
            base = off - len(prev)
            for t in TERMS:
                i = hay.find(t)
                if i >= 0 and t.decode() not in found:
                    found[t.decode()] = base + i
            prev = hay[-OVERLAP:]
            off += len(buf)
    if found:
        print(f'{rel}  ({size} B)')
        for k, o in sorted(found.items()):
            print(f'      {k:<10} at 0x{o:x}')
print('\ndone')
