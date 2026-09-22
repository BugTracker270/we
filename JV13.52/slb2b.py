#!/usr/bin/env python3
"""SLB2, parsed correctly, with the oracle results actually visible.

Correct header layout (from the bytes):
    0x00 char magic[4]  "SLB2"
    0x04 u32 version    1
    0x08 u32            0
    0x0C u32 count      2          <-- was misread as 0x10 before
    0x10 u32 0x267      (member[0] end offset, 0x200 + 0x67)
    0x20 u32 1
    0x24 u32 0x4c920    (member[1] size; 0x267 + 0x4c920 = 0x4CB87, the
                         ciphertext/zero-padding boundary seen in the entropy map)
    0x30 member[0]: char name[8] "C0000001", 24 pad, then u32 0x266 / u32 0x40
    0x60 member[1]: char name[8] "C0008001", rest zero

So member data occupies 0x200..0x267 for C0000001 (about 103 bytes) and
0x267..0x4CB87 for C0008001 - which is why the oracle must be run over the
first 0x400 densely rather than only at "nice" offsets.
"""
import struct, sys
from Crypto.Cipher import AES

Z16 = b'\x00' * 16
BELIZE = bytes.fromhex('1A4B4DC4179114F0A6B0266ACFC81193')
ROOT = r'C:\Users\Kinan\Downloads\JV13.52\dec\unpacked1\dev'

for fn in ('sflash0s0x32b', 'sflash0s0x33', 'sflash0s1.cryptx2b'):
    d = open(f'{ROOT}\\{fn}', 'rb').read()
    magic = d[0:4]
    ver, f08, cnt, f10, f20, f24 = struct.unpack_from('<IIIIII', d, 4)
    print(f'\n=== {fn} ({len(d)} B)')
    print(f'    magic={magic!r} ver={ver} count={cnt} @0x10={f10:#x} '
          f'@0x20={f20:#x} @0x24={f24:#x}')
    for i in range(min(cnt, 4)):
        b = 0x30 + i * 0x30
        name = d[b:b + 8]
        a, c = struct.unpack_from('<II', d, b + 0x20)
        print(f'    member[{i}] name={name!r} @+0x20 u32={a:#x},{c:#x}')

    hits, best, best_off, best_frac = 0, 0.0, -1, 0.0
    for o in range(0, 0x2800):
        h = d[o:o + 0x80]
        if len(h) < 0x80:
            break
        dec = AES.new(BELIZE, AES.MODE_CBC, Z16).decrypt(h[0x30:0x80])
        fr = sum(1 for x in dec if 32 <= x < 127) / len(dec)
        if fr > best_frac:
            best_frac, best_off = fr, o
        if dec[0x64:0x6C] == b'\x00' * 8:
            hits += 1
            bl, = struct.unpack_from('<L', dec, 0xC)
            print(f'    *** ORACLE HIT off={o:#x} type={h[7]:#04x} body_len={bl:#x}')
            print(f'        hdr[0:0x30]={h[:0x30].hex()}')
            print(f'        dec[0:0x30]={dec[:0x30].hex()}')
            print(f'        body_aes_key={dec[0x30:0x40].hex()}')
            if bl and o + 0x80 + bl <= len(d):
                enc = d[o + 0x80:o + 0x80 + bl]
                import hashlib, hmac
                if hmac.new(dec[0x40:0x50], enc, hashlib.sha1).digest() == dec[0x50:0x64]:
                    pt = AES.new(dec[0x30:0x40], AES.MODE_CBC, Z16).decrypt(enc)
                    out = f'{ROOT}\\{fn}.off{o:x}.DEC.bin'
                    open(out, 'wb').write(dec + pt)
                    print(f'        BODY HMAC VERIFIED -> {out}')
    print(f'    oracle hits in 0x0..0x2800: {hits}')
    print(f'    best printable fraction {best_frac:.3f} at offset {best_off:#x} '
          f'(chance level is ~0.36, a real header decrypt is >0.9)')
