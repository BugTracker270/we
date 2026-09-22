#!/usr/bin/env python3
"""Validate the dumped 13.52 kernel image against everything we know.

Checks are independent of each other, so a pass on most and a fail on one tells
us exactly where to look. Run this on the USB's kmemfull.bin.
"""
import hashlib
import os
import struct
import sys

IMG = r'C:\Users\Kinan\Downloads\JV13.52\kmemfull.bin'   # adjust if needed
if len(sys.argv) > 1:
    IMG = sys.argv[1]

KO_TEXT_END = 0x00cfe758
KO_DATA_START = 0x01520000
KO_DATA_FILE_END = 0x01b265e8

if not os.path.exists(IMG):
    print(f'not found: {IMG}')
    print('copy /mnt/usb0/kmemfull.bin off the USB stick first')
    raise SystemExit(1)

d = open(IMG, 'rb').read()
print('=' * 72)
print('file:', IMG)
print('size:', len(d), f'({len(d):#x})')
print('sha256:', hashlib.sha256(d).hexdigest())
print('=' * 72)

ok = 0
tot = 0


def check(name, cond, detail=''):
    global ok, tot
    tot += 1
    if cond:
        ok += 1
    print(f'  [{"PASS" if cond else "FAIL"}] {name}' + (f'  {detail}' if detail else ''))


print('\n--- 1. size ---')
check('size == 0x1b265e8 (image end from SELF phdr + offsets header)',
      len(d) == KO_DATA_FILE_END, f'got {len(d):#x}')

print('\n--- 2. kernel ELF header at 0x0 ---')
emagic = d[0:4]
eclass, edata, ever, eosabi = d[4], d[5], d[6], d[7]
check('ELF magic', emagic == b'\x7fELF', emagic.hex(' '))
check('ELFCLASS64', eclass == 2, str(eclass))
check('little-endian', edata == 1, str(edata))
check('EI_OSABI == 9 (FreeBSD)', eosabi == 9, str(eosabi))
e_type, e_machine, e_version = struct.unpack_from('<HHI', d, 0x10)
e_entry, e_phoff, e_shoff = struct.unpack_from('<QQQ', d, 0x18)
e_ehsize, e_phentsize, e_phnum = struct.unpack_from('<HHH', d, 0x36)
print(f'    e_type={e_type:#x} e_machine={e_machine:#x} e_entry={e_entry:#x}')
print(f'    e_phoff={e_phoff:#x} e_phnum={e_phnum} e_shoff={e_shoff:#x}')
check('e_machine == 0x3e (x86-64)', e_machine == 0x3E, hex(e_machine))
check('e_phnum <= 16 (0 is normal post-relocation)', e_phnum <= 16, str(e_phnum))

if 1 <= e_phnum <= 16 and e_phoff + e_phnum * e_phentsize <= len(d):
    print('\n    program headers:')
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from('<II', d, o)
        p_off, p_va, p_pa, p_fsz, p_msz, p_al = struct.unpack_from('<QQQQQQ', d, o + 8)
        fl = ''.join(c for b, c in ((4, 'R'), (2, 'W'), (1, 'X')) if p_flags & b)
        print(f'      [{i}] type={p_type:#x} {fl:<3} off={p_off:#x} '
              f'vaddr={p_va:#x} filesz={p_fsz:#x} memsz={p_msz:#x}')

print('\n--- 3. known anchors from the live console (v9 probes) ---')
# exact literal, cross-checked against the v9 live probe little-endian value
# 0x205359534942524f == "ORBISYS " -- one 'S', then 'Y'
check('"ORBISYS" tag at 0x1520000 (matches v9 live probe)',
      d[KO_DATA_START:KO_DATA_START + 7] == b'ORBISYS',
      repr(d[KO_DATA_START:KO_DATA_START + 7]))

print('\n--- 4. region behaviour ---')
# .text should be dense code; bss/end should show zero runs
for name, off, n in (('.text  start', 0x0, 16),
                     ('.text  mid', KO_TEXT_END // 2, 16),
                     ('.text  end', KO_TEXT_END - 16, 16),
                     ('.data  start', KO_DATA_START, 16),
                     ('image  end', KO_DATA_FILE_END - 16, 16)):
    print(f'    {name:<13} @{off:#010x}  {d[off:off+n].hex(" ")}')

zero = d.count(0)
print(f'    zero bytes: {zero} / {len(d)}  ({100.0*zero/len(d):.1f}%)')

print('\n--- 5. FreeBSD fingerprints (the kernel is a FreeBSD fork) ---')
for needle in (b'FreeBSD', b'@(#)FreeBSD', b'Copyright (c) 19'):
    hits = []
    start = 0
    while True:
        j = d.find(needle, start)
        if j < 0 or len(hits) >= 3:
            break
        hits.append(j)
        start = j + 1
    print(f'    {needle!r}: {len(hits)} hit(s)' +
          ('' if not hits else '  ' + ', '.join(hex(h) for h in hits)))
    for h in hits[:2]:
        seg = d[h:h + 64].split(b'\x00')[0]
        print(f'        @{h:#x}  {seg[:64]!r}')

print('\n--- 6. PS4-specific strings ---')
for needle in (b'SceSblAuthMgr', b'sceSblAuthMgrIsLoadable', b'authmgr',
               b'SblDrvHdlrSx', b'80010008', b'Orbis'):
    j = d.find(needle)
    print(f'    {needle.decode():<26} {"found @" + hex(j) if j >= 0 else "absent"}')

print('\n' + '=' * 72)
print(f'RESULT: {ok}/{tot} structural checks passed')
print('=' * 72)
if ok == tot:
    print('Image looks correct. This is the decrypted 13.52 kernel.')
else:
    print('Some checks failed - see which, above.')
print()
print('NOTE on scope: this dump is the FILE-BACKED image (0x0..0x1b265e8).')
print('The runtime bss region beyond 0x1b265e8 (where the AuthMgr structures')
print('at 0x269c0a0 etc. live) is NOT included. It is readable and can be')
print('grabbed in a second pass - but it is runtime state, not kernel code.')
