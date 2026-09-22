#!/usr/bin/env python3
"""Locate the real EMC IPL / EAP KBL image and decrypt it, using the algorithm
from TeamFAPS ps4-emc-ipl-eap-kbl-tool (verified against its published source).

Oracle: after unwrapping hdr[0x30:0x80] with the published cipher key,
bytes hdr_dec[0x64:0x6C] MUST be eight zero bytes. False positive odds are 2^-64,
so a hit is definitive. We do NOT rely on the ASCII names in the SLB2 wrapper.

On a hit the header also yields: body_len (dec[0xC:0x10]), body_aes_key
(dec[0x30:0x40]), body_hmac_key (dec[0x40:0x50]), body_hmac (dec[0x50:0x64]),
header_hmac (dec[0x6C:0x80]) - and the body is AES-128-CBC with body_aes_key over
body_len bytes, HMAC'd (SHA1) over the CIPHERTEXT.
"""
import hashlib, hmac, os, struct
from Crypto.Cipher import AES

Z16 = b'\x00' * 16
KEYS = {
    'Aeolia': bytes.fromhex('5F74FE7790127FECF82CC6E6D91FA2D1'),
    'Belize': bytes.fromhex('1A4B4DC4179114F0A6B0266ACFC81193'),
}
HASHERS = {
    0x48: bytes.fromhex('73FE06F3906B05ECB506DFB8691F9F54'),   # EMC IPL hasher (Aeolia)
    0x68: bytes.fromhex('824D9BB4DBA3209294C93976221249E4'),   # EAP KBL hasher (Aeolia)
}
TYPE = {0x48: 'EMC IPL', 0x68: 'EAP KBL'}

ROOT = r'C:\Users\Kinan\Downloads\JV13.52\dec'
CANDIDATES = [
    os.path.join(ROOT, r'unpacked1\dev\sflash0s0x32b'),
    os.path.join(ROOT, r'unpacked1\dev\sflash0s0x33'),
    os.path.join(ROOT, r'unpacked1\dev\sflash0s0x38'),
    os.path.join(ROOT, r'unpacked1\dev\sflash0s1.cryptx2b'),
    os.path.join(ROOT, r'unpacked1\unknown\49.img'),
    os.path.join(ROOT, r'unpacked1\unknown\50.img'),
    os.path.join(ROOT, r'unpacked1\tables\32_for_8.img'),
    os.path.join(ROOT, r'unpacked1\tables\28_for_5.img'),
    os.path.join(ROOT, r'unpacked1\tables\30_for_6.img'),
    os.path.join(ROOT, r'unpacked1\tables\34_for_7.img'),
    os.path.join(ROOT, r'unpacked1\tables\4_for_514.img'),
    os.path.join(ROOT, r'unpacked1\tables\7_for_3329.img'),
    os.path.join(ROOT, r'unpacked1\dev\sc_fw_update0'),
    os.path.join(ROOT, r'PS4UPDATE1.PUP.dec'),
]


def scan(path, step=0x10):
    if not os.path.exists(path):
        print(f'[skip] {os.path.basename(path)} missing')
        return
    d = open(path, 'rb').read()
    print(f'--- {os.path.basename(path)}  ({len(d)} B, scanning step {step:#x})')
    hits = 0
    for off in range(0, len(d) - 0x80, step):
        hdr = d[off:off + 0x80]
        for kname, k in KEYS.items():
            try:
                dec = hdr[:0x30] + AES.new(k, AES.MODE_CBC, Z16).decrypt(hdr[0x30:0x80])
            except Exception:
                continue
            if dec[0x64:0x6C] != b'\x00' * 8:
                continue
            t = hdr[7]
            hits += 1
            body_len, = struct.unpack_from('<L', dec, 0xC)
            print(f'    HIT off={off:#x} key={kname} type={t:#04x} ({TYPE.get(t, "?")}) '
                  f'body_len={body_len:#x} ({body_len} B)')
            print(f'        body_aes_key = {dec[0x30:0x40].hex()}')
            print(f'        body_hmac_key= {dec[0x40:0x50].hex()}')
            print(f'        body_hmac    = {dec[0x50:0x64].hex()}')
            print(f'        header_hmac  = {dec[0x6C:0x80].hex()}')
            print(f'        hdr_dec[0x00:0x30] = {dec[:0x30].hex()}')
            hk = HASHERS.get(t)
            if hk:
                calc = hmac.new(hk, dec[:0x6C], hashlib.sha1).digest()
                print(f'        header hmac verify vs Aeolia hasher: '
                      f'{"OK" if calc == dec[0x6C:0x80] else "MISMATCH"}')
            if body_len and off + 0x80 + body_len <= len(d):
                enc = d[off + 0x80: off + 0x80 + body_len]
                bh = hmac.new(dec[0x40:0x50], enc, hashlib.sha1).digest()
                ok = (bh == dec[0x50:0x64])
                print(f'        body hmac verify (over ciphertext): '
                      f'{"OK - KEY AND OFFSET CONFIRMED" if ok else "MISMATCH"}')
                if ok:
                    pt = AES.new(dec[0x30:0x40], AES.MODE_CBC, Z16).decrypt(enc)
                    out = path + f'.off{off:06x}.dec.bin'
                    open(out, 'wb').write(dec + pt)
                    print(f'        *** decrypted body written: {out}')
                    print(f'        body[0:32] = {pt[:32].hex()}')
                    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in pt[:48])
                    print(f'        body ascii = |{asc}|')
    if not hits:
        print('    no hit')


for p in CANDIDATES:
    scan(p)

# the big system image last, coarser
p = os.path.join(ROOT, r'unpacked1\system_fs_image.img')
if os.path.exists(p):
    print(f'--- system_fs_image.img : skipped (no secure-loader role)')
