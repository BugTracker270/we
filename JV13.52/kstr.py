#!/usr/bin/env python3
"""Search the decrypted 13.52 kernel for the strings that would indicate a
sealed-key / keyset accessor.

Why: psdevwiki states "PS4 Keysets 4 and lower were dumped with the
getSealedKeySecret kernel function on System Software 5.05". If an equivalent
exists in this kernel, then the keyset material can be obtained from OUR console
with kernel code execution (which GoldHEN already gives us) - no hardware attack,
no power analysis, no 14.00 console. If it does not exist, the answer is no.

Reports the koff of every hit plus surrounding context, so a false positive is
obvious.
"""
import re, struct

ELF = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KBASE = 0xffffffff82200000
d = open(ELF, 'rb').read()

e_phoff, = struct.unpack_from('<Q', d, 0x20)
e_phentsize, e_phnum = struct.unpack_from('<HH', d, 0x36)
SEGS = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t, fl, po, va, pa, fsz, msz, al = struct.unpack_from('<IIQQQQQQ', d, o)
    if t == 1:
        SEGS.append((po, fsz, va - KBASE))
SEGS.sort()


def foff2koff(o):
    for po, fsz, ko in SEGS:
        if po <= o < po + fsz:
            return ko + (o - po)
    return None


TERMS = [
    b'getSealedKeySecret',
    b'SealedKeySecret',
    b'sceSblGetSealedKeySecret',
    b'sealedkey',
    b'SealedKey',
    b'Sealed Key',
    b'KeySet',
    b'keyset',
    b'Keyset',
    b'keyring',
    b'KeyRing',
    b'eap_kbl',
    b'ipl',
    b'SAMU',
    b'EMC',
    b'sflash',
    b'SecureModules',
    b'80010008',
    b'AuthMgr',
]

for t in TERMS:
    hits = [m.start() for m in re.finditer(re.escape(t), d)]
    print(f'--- {t.decode():<24} {len(hits)} hit(s)')
    for h in hits[:6]:
        ko = foff2koff(h)
        lo = max(0, h - 24)
        ctx = d[lo:h + len(t) + 24]
        asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
        ktxt = f'koff {ko:#x}' if ko is not None else 'koff --'
        print(f'      foff {h:#x}  {ktxt}  |{asc}|')
    if len(hits) > 6:
        print(f'      ... {len(hits) - 6} more')
