#!/usr/bin/env python3
"""Run TeamFAPS's ps4-emc-ipl-eap-kbl-tool procedure faithfully, over every file
whose offset-7 discriminator byte says it is an EMC IPL (0x48) or EAP KBL (0x68).

The tool reads the image at OFFSET 0 - the input file IS the image - so there is no
offset scanning to do. Finding the image is a matter of the discriminator byte.
"""
import hashlib, hmac, os, struct
from Crypto.Cipher import AES

Z16 = b'\x00' * 16
KEYS = {
    'Aeolia': bytes.fromhex('5F74FE7790127FECF82CC6E6D91FA2D1'),
    'Belize': bytes.fromhex('1A4B4DC4179114F0A6B0266ACFC81193'),
}
HASHERS = {
    0x48: bytes.fromhex('73FE06F3906B05ECB506DFB8691F9F54'),
    0x68: bytes.fromhex('824D9BB4DBA3209294C93976221249E4'),
}
TYPE = {0x48: 'EMC IPL', 0x68: 'EAP KBL'}
ROOT = r'C:\Users\Kinan\Downloads\JV13.52\dec'


def probe(path):
    d = open(path, 'rb').read(0x80)
    if len(d) < 0x80:
        return None
    t = d[7]
    if t not in (0x48, 0x68):
        return None
    print(f'\n=== {path.replace(ROOT, "").lstrip(chr(92))}  '
          f'discriminator[7]={t:#04x} -> {TYPE[t]} ===')
    print(f'    raw hdr[0x00:0x30] = {d[:0x30].hex()}')
    for kname, k in KEYS.items():
        dec = d[:0x30] + AES.new(k, AES.MODE_CBC, Z16).decrypt(d[0x30:0x80])
        zero_ok = (dec[0x64:0x6C] == b'\x00' * 8)
        print(f'    {kname:<7} zeros@0x64-0x6B: '
              f'{"YES  <-- key is right" if zero_ok else "no"}')
        if not zero_ok:
            continue
        body_len, = struct.unpack_from('<L', dec, 0xC)
        print(f'      body_len      = {body_len:#x} ({body_len} B)')
        print(f'      body_aes_key  = {dec[0x30:0x40].hex()}')
        print(f'      body_hmac_key = {dec[0x40:0x50].hex()}')
        print(f'      body_hmac     = {dec[0x50:0x64].hex()}')
        print(f'      header_hmac   = {dec[0x6C:0x80].hex()}')
        print(f'      hdr_dec[0:0x30]= {dec[:0x30].hex()}')
        hk = HASHERS.get(t)
        if hk:
            calc = hmac.new(hk, dec[:0x6C], hashlib.sha1).digest()
            print(f'      header hmac   = {"VERIFIED" if calc == dec[0x6C:0x80] else "mismatch"}')
        # body lives right after the 0x80 header, in the same file
        full = open(path, 'rb').read()
        if body_len and 0x80 + body_len <= len(full):
            enc = full[0x80:0x80 + body_len]
            bh = hmac.new(dec[0x40:0x50], enc, hashlib.sha1).digest()
            if bh == dec[0x50:0x64]:
                pt = AES.new(dec[0x30:0x40], AES.MODE_CBC, Z16).decrypt(enc)
                out = path + '.DEC.bin'
                open(out, 'wb').write(dec + pt)
                print(f'      body hmac     = VERIFIED - FULL DECRYPT')
                print(f'      *** written: {out}')
                asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in pt[:64])
                print(f'      body ascii    = |{asc}|')
            else:
                print('      body hmac     = mismatch (body not at 0x80?)')
    return t


found = 0
for dirpath, dirnames, filenames in os.walk(ROOT):
    for fn in sorted(filenames):
        p = os.path.join(dirpath, fn)
        try:
            if probe(p):
                found += 1
        except Exception as e:
            pass
if not found:
    print('\nNo file has discriminator byte 0x48/0x68 at offset 7.')
