#!/usr/bin/env python3
"""Test whether the prior roadmap's "RVA"s are relative to the SELF segment link
vaddr (0x680000) rather than kbase (0).

Background: the SELF program header says p_vaddr = 0x680000, p_filesz = 0x14a65e8.
0x680000 + 0x14a65e8 = 0x1b265e8, which is exactly the image end we dumped. So the
loaded segment may sit at image offset 0x680000, and the roadmap's RVAs may be
segment-relative, not image-relative. If so, everything shifts by +0x680000.

Three candidate values failed at the +0 interpretation:
   jmp_rsi      0x47B31   expected ff e6
   sysent[661]  0x1112470 (base 0x110a880)
   kl_lock      0xE6C20
"""
import struct

IMG = r'C:\Users\Kinan\Downloads\JV13.52\1352-KERNEL-HANDOFF\kmemfull.bin'
d = open(IMG, 'rb').read()
SEG = 0x680000
print(f'image {len(d):#x}   testing shift +{SEG:#x}\n')

print('=' * 74)
print('A. jmp_rsi candidate 0x47B31')
print('=' * 74)
for shift, tag in ((0, 'as-is (kbase-relative)'), (SEG, '+0x680000 (segment-relative)')):
    off = 0x47B31 + shift
    if off + 8 > len(d):
        print(f'  {tag:<32} {off:#x}  OUT OF RANGE')
        continue
    b = d[off:off + 8]
    print(f'  {tag:<32} {off:#08x}  {b.hex(" ")}  '
          f'{"<<< MATCH ff e6" if b[:2] == b"\xff\xe6" else "no"}')

print()
print('=' * 74)
print('B. sysent base candidates')
print('=' * 74)


def look(base, tag):
    if base + 8 > len(d):
        print(f'  {tag:<34} {base:#x}  OUT OF RANGE')
        return
    print(f'  {tag:<34} {base:#010x}')
    for i in range(4):
        e = base + i * 0x30
        if e + 0x18 > len(d):
            break
        n = struct.unpack_from('<i', d, e)[0]
        c = struct.unpack_from('<Q', d, e + 8)[0]
        print(f'      [{i}] narg={n:<12} sy_call={c:#018x}')


for shift, tag in ((0, 'kbase-relative'), (SEG, 'segment-relative (+0x680000)')):
    look(0x110A880 + shift, f'base 0x110a880 {tag}')
    look(0x110A760 + shift, f'base 0x110a760 {tag}')

print()
print('=' * 74)
print('C. kl_lock candidate 0xE6C20 — is the shifted location data-like?')
print('=' * 74)
for shift, tag in ((0, 'as-is'), (SEG, '+0x680000')):
    off = 0xE6C20 + shift
    if off + 32 > len(d):
        print(f'  {tag:<12} OUT OF RANGE')
        continue
    b = d[off:off + 32]
    z = b.count(0)
    print(f'  {tag:<12} {off:#08x}  {b.hex(" ")}   zeros={z}/32')

print()
print('=' * 74)
print('D. what actually sits at image offset 0x680000?')
print('=' * 74)
b = d[SEG:SEG + 48]
print(f'  {SEG:#x}  {b.hex(" ")}')
print(f'  as ascii: {b!r}')
print(f'  as u64s : {[hex(struct.unpack_from("<Q", d, SEG + i * 8)[0]) for i in range(6)]}')
