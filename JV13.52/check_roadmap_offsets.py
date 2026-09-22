#!/usr/bin/env python3
"""Check the candidate offsets that bd-j-usr/research/ROADMAP_13_52.md lists as
BLOCKED ON A KERNEL DUMP. We now have that dump.

Candidates from the roadmap / patches/1350.bin (CTAP decoded):
  jmp_rsi      RVA 0x00047B31  expect bytes ff e6
  sysent[661]  RVA 0x01112470  (implied sysent base 0x0110A880, stride 0x30)
  kl_lock      RVA 0x000E6C20  (assumed)
Also the 13.04-derived assumption: sysent base 0x110A760.
"""
import struct

IMG = r'C:\Users\Kinan\Downloads\JV13.52\kmemfull.bin'
d = open(IMG, 'rb').read()
TEXT_END = 0x00CFE758
print(f'image size {len(d):#x}   .text ends {TEXT_END:#x}\n')

print('=' * 74)
print('1. jmp_rsi gadget @ 0x47B31  (expect ff e6)')
print('=' * 74)
for off in (0x47B31,):
    b = d[off:off + 8]
    print(f'  @{off:#08x}  {b.hex(" ")}   {"MATCH (ff e6)" if b[:2] == b"\xff\xe6" else "no"}')

# also scan widely for the bare gadget to see how common it is
hits = []
i = d.find(b'\xff\xe6', 0, TEXT_END)
while i != -1 and len(hits) < 20:
    hits.append(i)
    i = d.find(b'\xff\xe6', i + 1, TEXT_END)
print(f'\n  total "ff e6" occurrences in .text: {len(hits)} (first 20: '
      f'{[hex(h) for h in hits]})')

print()
print('=' * 74)
print('2. sysent table — does a 0x30-stride table of code pointers exist?')
print('=' * 74)


def probe_base(base, n=6):
    print(f'\n  candidate sysent base {base:#x}')
    ok = 0
    for i in range(n):
        e = base + i * 0x30
        if e + 0x30 > len(d):
            break
        v0 = struct.unpack_from('<Q', d, e)[0]
        v1 = struct.unpack_from('<Q', d, e + 8)[0]
        v2 = struct.unpack_from('<Q', d, e + 0x10)[0]
        intxt = TEXT_END > v0 > 0
        if intxt:
            ok += 1
        print(f'    sysent[{i:>3}] @{e:#x}  +0x00={v0:#018x} {"<text" if intxt else ""}'
              f'  +0x08={v1:#018x}  +0x10={v2:#018x}')
    print(f'    -> {ok}/{n} entries have a .text pointer at +0x00')
    return ok


for base in (0x0110A880, 0x0110A760):
    probe_base(base)

print('\n  sysent[661] specifically:')
for base in (0x0110A880,):
    e = base + 661 * 0x30
    print(f'    base {base:#x} + 661*0x30 = {e:#x}')
    if e + 0x30 <= len(d):
        v0 = struct.unpack_from('<Q', d, e)[0]
        v1, v2 = struct.unpack_from('<QQ', d, e + 8)
        print(f'      +0x00={v0:#018x}  +0x08={v1:#018x}  +0x10={v2:#018x}')

print()
print('=' * 74)
print('3. kl_lock @ 0xE6C20 (assumed; should be a lock object, often zero-ish)')
print('=' * 74)
b = d[0xE6C20:0xE6C20 + 64]
print(f'  @0xE6C20  {b.hex(" ")}')
print(f'  surrounding 32 bytes at 0xE6C00: {d[0xE6C00:0xE6C40].hex(" ")}')

print()
print('=' * 74)
print('4. sanity: is 0xE6C20 inside .text or in a data region?')
print('=' * 74)
print(f'  0xE6C20 < TEXT_END({TEXT_END:#x}) -> {"in .text" if 0xE6C20 < TEXT_END else "in data"}')
print(f'  0x47B31 < TEXT_END -> {"in .text" if 0x47B31 < TEXT_END else "in data"}')
