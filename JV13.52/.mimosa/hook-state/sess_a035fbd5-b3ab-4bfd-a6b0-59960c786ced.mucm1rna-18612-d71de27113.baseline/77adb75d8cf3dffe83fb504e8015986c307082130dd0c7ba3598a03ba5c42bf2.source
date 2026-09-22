#!/usr/bin/env python3
"""Decode the SLB2 container and locate member data.

SLB2 is the archive wrapping the sflash images. Observed: member names at 0x30 and
0x60 (0x30 apart) -> 0x30-byte member records, name first. The numeric descriptor
fields need reading off the bytes, not guessing.

Also runs the TeamFAPS oracle densely over the first 0x400 bytes of each container,
where member descriptors point, so a member's data is tested even if its offset
turns out to be inside the header region.
"""
import struct
from Crypto.Cipher import AES

Z16 = b'\x00' * 16
BELIZE = bytes.fromhex('1A4B4DC4179114F0A6B0266ACFC81193')
ROOT = r'C:\Users\Kinan\Downloads\JV13.52\dec\unpacked1\dev'
FILES = ['sflash0s0x32b', 'sflash0s0x33', 'sflash0s1.cryptx2b']

for fn in FILES:
    p = f'{ROOT}\\{fn}'
    d = open(p, 'rb').read()
    print(f'\n########## {fn}  ({len(d)} B) ##########')

    # --- raw header, annotated ---
    print('  offset  bytes                                              ascii')
    for i in range(0, 0x100, 0x10):
        row = d[i:i + 16]
        hx = ' '.join(f'{x:02x}' for x in row)
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in row)
        print(f'  {i:#06x}  {hx:<47}  {asc}')

    magic = d[0:4]
    ver, a, b2, cnt = struct.unpack_from('<IIII', d, 4)
    f10, = struct.unpack_from('<I', d, 0x10)
    f14, = struct.unpack_from('<I', d, 0x14)
    f20, = struct.unpack_from('<I', d, 0x20)
    f24, = struct.unpack_from('<I', d, 0x24)
    print(f'  magic={magic!r} ver={ver} a={a:#x} b={b2:#x} count={cnt}')
    print(f'  @0x10={f10:#x} @0x14={f14:#x} @0x20={f20:#x} @0x24={f24:#x}')

    # --- member records, 0x30 apart, name first ---
    print('  member records (0x30 stride from 0x30):')
    for k in range(cnt):
        base = 0x30 + k * 0x30
        if base + 0x30 > len(d):
            break
        name = d[base:base + 8]
        qs = struct.unpack_from('<QQQ', d, base + 8)
        tail = struct.unpack_from('<II', d, base + 0x20)
        print(f'    [{k}] name={name!r} q<{base+8:#x}>={qs[0]:#x},{qs[1]:#x},{qs[2]:#x}'
              f'  u32<{base+0x20:#x}>={tail[0]:#x},{tail[1]:#x}')

    # --- dense oracle over the first 0x400 ---
    print('  dense oracle (Belize key) 0x00..0x400, step 1:')
    hits = 0
    for o in range(0, 0x400):
        h = d[o:o + 0x80]
        if len(h) < 0x80:
            break
        dec = AES.new(BELIZE, AES.MODE_CBC, Z16).decrypt(h[0x30:0x80])
        if dec[0x64:0x6C] != b'\x00' * 8:
            continue
        hits += 1
        body_len, = struct.unpack_from('<L', dec, 0xC)
        print(f'    *** HIT off={o:#x} type_byte={h[7]:#04x} body_len={body_len:#x}')
        print(f'        hdr[0:0x30]={h[:0x30].hex()}')
        print(f'        dec[0:0x30]={dec[:0x30].hex()}')
        print(f'        body_aes_key={dec[0x30:0x40].hex()}')
    if not hits:
        print('    none')
