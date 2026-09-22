#!/usr/bin/env python3
"""Read the Program Identification Header, per psdevwiki SELF-SPRX layout.

   0xB8  Auth ID            (0x8)
   0xC0  Program Type       (0x8)
   0xC8  Program Version    (0x8)
   0xD0  System SW Version  (0x8)  <- requested MINIMUM firmware
   0xD8  Digest             (0x20) <- SHA-256 of the DECRYPTED ELF

Then check the blackbox-decrypter condition:
   "it must have a required FW version lower than the FW version of the PS4
    being used"  -- psdevwiki
Our console is 13.52.
"""
import struct

A = r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\80010002.self'          # 13.52 kernel
B = r'C:\Users\Kinan\Downloads\JV13.52\dec\80010002_kernel_14.00.self'  # 14.00 kernel


def fw(v):
    """0x13520000 -> 13.52 style, and human readable."""
    major = (v >> 24) & 0xFF
    minor = (v >> 16) & 0xFF
    return f'{major}.{minor:02d}  (raw {v:#018x})'


for nm, f in (('13.52', A), ('14.00', B)):
    d = open(f, 'rb').read(0x100)
    auth, ptype, pver, ssv = struct.unpack_from('<QQQQ', d, 0xB8)
    digest = d[0xD8:0xF8]
    print(f'--- {nm} kernel SELF ---')
    print(f'  Auth ID           {auth:#018x}')
    print(f'  Program Type      {ptype:#018x}')
    print(f'  Program Version   {pver:>20}   {pver:#018x}')
    print(f'  System SW Version {fw(ssv)}')
    print(f'  Digest (SHA-256 of DECRYPTED elf):')
    print(f'    {digest.hex()}')
    print()

da = open(A, 'rb').read(0x100)
db = open(B, 'rb').read(0x100)
sa, sb = struct.unpack_from('<Q', da, 0xD0)[0], struct.unpack_from('<Q', db, 0xD0)[0]
print('=== blackbox decrypter condition (psdevwiki) ===')
print(f'  SELF requires FW : {fw(sb)}')
print(f'  console is on    : 13.52')
print(f'  condition "required FW < console FW" -> {sb < 0x13520000}')
print()
print('=== which bytes in 0xB8..0x100 differ between the two? ===')
diffs = [i for i in range(0xB8, 0x100) if da[i] != db[i]]
print(f'  {len(diffs)} bytes: {[hex(x) for x in diffs]}')
print(f'  -> 0xd0-0xd7 is System SW Version: {"DIFFERS" if any(0xd0 <= x < 0xd8 for x in diffs) else "same"}')
print(f'  -> 0xd8-0xf7 is the ELF digest:    {"DIFFERS" if any(0xd8 <= x < 0xf8 for x in diffs) else "same"}')
