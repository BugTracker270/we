#!/usr/bin/env python3
"""Enumerate all 35 PUP entries, identify each, and hunt the EMC IPL / EAP KBL.

Two things at once:
  * a table of every entry (id, offset, size, entropy, magic) so we can see what the
    PUP actually contains
  * the TeamFAPS oracle at EVERY 16-byte-aligned offset inside every entry, using
    the BELIZE cipher key (the platform is CUH-1216B = Belize). The oracle is
    "hdr_dec[0x64:0x6C] == 8 zero bytes", odds 2^-64 by chance, so it does not care
    what the discriminator byte says - which also covers the case where this FW
    variant uses a type byte other than 0x48/0x68.

On a hit: verify the header HMAC, then decrypt the body with the per-file
body_aes_key taken from the decrypted header, and verify the body HMAC over the
ciphertext before claiming anything.
"""
import hashlib, hmac, math, struct, sys, time
from Crypto.Cipher import AES

Z16 = b'\x00' * 16
Z32 = b'\x00' * 32
PUP = r'C:\Users\Kinan\Downloads\JV13.52\dec\PS4UPDATE1.PUP.dec'
KEYS = {
    'Belize': bytes.fromhex('1A4B4DC4179114F0A6B0266ACFC81193'),
}
HDR_HMACS = {                      # candidate header-hmac keys
    'belize_zeros': Z32,
    'aeolia':       bytes.fromhex('73FE06F3906B05ECB506DFB8691F9F54'),
    'eapkbl_aeolia': bytes.fromhex('824D9BB4DBA3209294C93976221249E4'),
}

d = open(PUP, 'rb').read()
print(f'{PUP}\n  size {len(d)} B')

magic, ver, mode, endian, attr = struct.unpack_from('<IBBBB', d, 0)
key_type, = struct.unpack_from('<I', d, 8)
hdr, meta = struct.unpack_from('<HH', d, 0x0C)
fsz, = struct.unpack_from('<Q', d, 0x10)
nent, flags = struct.unpack_from('<HH', d, 0x18)
print(f'  magic {magic:#010x}  attr {attr:#04x}  key_type {key_type:#x}  '
      f'hdr {hdr:#x}  meta {meta:#x}  entries {nent}  data_base {hdr+meta:#x}\n')

entries = []
off = 0x20
for i in range(nent):
    eid, eflags, eoff, sa, sb = struct.unpack_from('<IIQQQ', d, off)
    entries.append((i, eid, eflags, eoff, sa, sb))
    off += 0x20


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


def ident(b):
    if b[:4] == b'\x7fELF':
        return 'ELF'
    if b[:4] == struct.pack('<I', 0x1d3d154f):
        return 'SELF'
    if b[:4] == b'SLB2':
        return 'SLB2'
    if b[0x1e4:0x1e8] == b'\\x00' * 4:
        return ''
    return ''


print(f'{"i":>3} {"id":>10} {"flags":>5} {"offset":>10} {"size_a":>10} {"size_b":>10} '
      f'{"b7":>4} {"ent":>5} {"magic":>5}')
tiles_ok = True
prev_end = hdr + meta
for (i, eid, eflags, eoff, sa, sb) in entries:
    b = d[eoff:eoff + sa] if eoff + sa <= len(d) else d[eoff:]
    b7 = b[7] if len(b) > 7 else -1
    mg = ident(b)
    print(f'{i:>3} {eid:#010x} {eflags:>5} {eoff:#10x} {sa:#10x} {sb:#10x} '
          f'{b7:>4} {entropy(b[:0x1000]):5.2f} {mg:>5}')
    if eoff != prev_end:
        tiles_ok = False
    prev_end = eoff + sa
print(f'\ncontiguous tiling from 0x{hdr+meta:x}: {"YES" if tiles_ok else "NO"}'
      f'   ends at 0x{prev_end:x} (file 0x{len(d):x})')

# ---------------- hunt ----------------
print('\n=== oracle scan: Belize key, every 16-byte-aligned offset in each entry ===')
hits = 0
t0 = time.time()
for (i, eid, eflags, eoff, sa, sb) in entries:
    end = min(eoff + sa, len(d))
    # The image, if present, is small; the 8 MB+ entries are whole filesystems and
    # brute-forcing them at 0x10 stride is what blew the previous time budget.
    if sa > 0x200000:
        print(f'  entry {i:>2} SKIPPED ({sa} B > 2 MB cap)', flush=True)
        continue
    print(f'  entry {i:>2} scanning ({sa} B)', flush=True)
    for o in range(eoff, end - 0x80, 0x10):
        h = d[o:o + 0x80]
        dec = AES.new(KEYS['Belize'], AES.MODE_CBC, Z16).decrypt(h[0x30:0x80])
        if dec[0x64:0x6C] != b'\x00' * 8:
            continue
        hits += 1
        t = h[7]
        body_len, = struct.unpack_from('<L', dec, 0xC)
        print(f'  *** HIT entry={i} id={eid:#010x} off={o:#x} type={t:#04x} '
              f'body_len={body_len:#x}')
        print(f'      hdr[0:0x30] ={h[:0x30].hex()}')
        print(f'      dec[0:0x30] ={dec[:0x30].hex()}')
        print(f'      body_aes_key ={dec[0x30:0x40].hex()}')
        print(f'      body_hmac_key={dec[0x40:0x50].hex()}')
        for hn, hk in HDR_HMACS.items():
            if hmac.new(hk, dec[:0x6C], hashlib.sha1).digest() == dec[0x6C:0x80]:
                print(f'      header hmac VERIFIED with "{hn}"')
        if body_len and o + 0x80 + body_len <= len(d):
            enc = d[o + 0x80:o + 0x80 + body_len]
            if hmac.new(dec[0x40:0x50], enc, hashlib.sha1).digest() == dec[0x50:0x64]:
                pt = AES.new(dec[0x30:0x40], AES.MODE_CBC, Z16).decrypt(enc)
                out = PUP + f'.e{i}.off{o:x}.DEC.bin'
                open(out, 'wb').write(dec + pt)
                print(f'      BODY HMAC VERIFIED - FULL DECRYPT -> {out}')
print(f'\nhits: {hits}   scan time {time.time()-t0:.0f}s')
