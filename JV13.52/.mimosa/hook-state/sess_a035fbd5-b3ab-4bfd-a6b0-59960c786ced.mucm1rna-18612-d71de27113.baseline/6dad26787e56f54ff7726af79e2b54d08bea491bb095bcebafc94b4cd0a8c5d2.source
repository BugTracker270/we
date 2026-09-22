#!/usr/bin/env python3
"""Fast search for the nested EMC IPL / EAP KBL image inside the containers.

Pre-filter: the image's first 0x30 bytes are PLAINTEXT (only hdr[0x30:0x80] is
encrypted), so at the image's offset `off`, byte d[off+7] must be 0x48 (EMC IPL) or
0x68 (EAP KBL). That reduces candidates from "every offset" to ~2/256 of them, which
makes the 326 MB PUP tractable.

Then the definitive oracle: unwrap hdr[off+0x30:off+0x80] with the published cipher
key and require ok[0x64:0x6C] == 8 zero bytes (odds 2^-64 by chance). On a hit, verify
the header HMAC and the body HMAC before claiming anything.
"""
import hashlib, hmac, os, struct, sys
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
DISC = (0x48, 0x68)
ROOT = r'C:\Users\Kinan\Downloads\JV13.52\dec'

FILES = [
    r'unpacked1\dev\sflash0s0x32b', r'unpacked1\dev\sflash0s0x33',
    r'unpacked1\dev\sflash0s0x38', r'unpacked1\dev\sflash0s1.cryptx2b',
    r'unpacked1\dev\sc_fw_update0',
    r'unpacked1\unknown\49.img', r'unpacked1\unknown\50.img',
    r'unpacked1\tables\32_for_8.img', r'unpacked1\tables\28_for_5.img',
    r'unpacked1\tables\30_for_6.img', r'unpacked1\tables\34_for_7.img',
    r'unpacked1\tables\4_for_514.img', r'unpacked1\tables\7_for_3329.img',
    r'unpacked1\eap_fs_image.img',
    r'unpacked1\torus2_firmware.bin', r'unpacked1\wlan_firmware.bin',
    r'PS4UPDATE1.PUP.dec',
]

total_hits = 0
for rel in FILES:
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        print(f'[skip] {rel}')
        continue
    d = open(path, 'rb').read()
    n = len(d)
    cands = [p - 7 for p in range(7, n - 0x80) if d[p] in DISC and p - 7 >= 0]
    print(f'--- {rel}  ({n} B)  {len(cands)} discriminator candidates', flush=True)
    hits = 0
    for off in cands:
        hdr = d[off:off + 0x80]
        for kname, k in KEYS.items():
            ok = hdr[:0x30] + AES.new(k, AES.MODE_CBC, Z16).decrypt(hdr[0x30:0x80])
            if ok[0x64:0x6C] != b'\x00' * 8:
                continue
            hits += 1
            total_hits += 1
            t = hdr[7]
            body_len, = struct.unpack_from('<L', ok, 0xC)
            print(f'    HIT off={off:#x} key={kname} type={t:#04x} {TYPE.get(t, "?")} '
                  f'body_len={body_len:#x}')
            print(f'        hdr_dec[0:0x30]={ok[:0x30].hex()}')
            print(f'        body_aes_key   ={ok[0x30:0x40].hex()}')
            print(f'        body_hmac_key  ={ok[0x40:0x50].hex()}')
            print(f'        body_hmac      ={ok[0x50:0x64].hex()}')
            print(f'        header_hmac    ={ok[0x6C:0x80].hex()}')
            hk = HASHERS.get(t)
            if hk:
                calc = hmac.new(hk, ok[:0x6C], hashlib.sha1).digest()
                print(f'        header hmac    = '
                      f'{"VERIFIED" if calc == ok[0x6C:0x80] else "mismatch"}')
            if body_len and off + 0x80 + body_len <= n:
                enc = d[off + 0x80: off + 0x80 + body_len]
                bh = hmac.new(ok[0x40:0x50], enc, hashlib.sha1).digest()
                if bh == ok[0x50:0x64]:
                    pt = AES.new(ok[0x30:0x40], AES.MODE_CBC, Z16).decrypt(enc)
                    out = os.path.join(ROOT, f'IPL_{rel.replace(chr(92),"_")}.off{off:06x}.dec.bin')
                    open(out, 'wb').write(ok + pt)
                    print(f'        body hmac      = VERIFIED - FULL DECRYPT')
                    print(f'        *** {out}')
                    print(f'        body[0:32]={pt[:32].hex()}')
                else:
                    print('        body hmac      = mismatch')
    if not hits:
        print('    no hit')

print(f'\ntotal hits: {total_hits}')
