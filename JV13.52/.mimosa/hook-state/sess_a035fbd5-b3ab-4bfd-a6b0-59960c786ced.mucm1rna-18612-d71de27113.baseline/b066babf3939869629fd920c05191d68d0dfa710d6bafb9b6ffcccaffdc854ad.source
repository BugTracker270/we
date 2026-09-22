#!/usr/bin/env python3
"""Scan the already-extracted PUP tree for boot-chain magics.

Goal: find out whether the pieces the offline key chain needs are ALREADY sitting
on disk. If a Secure Loader (magic 5E D7 9A 0B, per psdevwiki) or an EMC IPL blob
is present, then the published EMC IPL Cipher Key (AES-128-CBC, zero IV) applies
to it and the chain can be walked entirely on the PC - no console, no power
analysis, no SM.

Streamed in chunks so the 326 MB PUP and 368 MB system image do not blow up.
"""
import os

ROOT = r'C:\Users\Kinan\Downloads\JV13.52\dec'
CHUNK = 1 << 23          # 8 MB
OVERLAP = 64

MAGICS = {
    'secure_loader  5E D7 9A 0B': bytes.fromhex('5ED79A0B'),
    'self  (SELF)   4F 15 3D 1D': bytes.fromhex('4F153D1D'),
    'elf             7F 45 4C 46': b'\x7fELF',
    'PUP          PUP\\0/....':    b'PUP\x00',
    'ascii    C0000001':           b'C0000001',
    'ascii    80010008':           b'80010008',
    'ascii    C0010001':           b'C0010001',
    'ascii    eap_kbl':            b'eap_kbl',
}

files = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    for fn in filenames:
        files.append(os.path.join(dirpath, fn))
files.sort()

print(f'scanning {len(files)} files under {ROOT}\n')

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
            for name, m in MAGICS.items():
                start = 0
                while True:
                    i = hay.find(m, start)
                    if i < 0:
                        break
                    if name not in found:
                        found[name] = base + i
                    start = i + 1
            prev = hay[-OVERLAP:]
            off += len(buf)
    if found:
        print(f'{rel}  ({size} B)')
        for name, o in found.items():
            print(f'      {name:<28} at 0x{o:x}')
    else:
        print(f'{rel}  ({size} B)   - no magics')
