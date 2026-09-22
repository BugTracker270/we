#!/usr/bin/env python3
"""Deep analysis of the dumped 13.52 kernel image.

Three jobs:
  1. Verify the function offsets in kmemfull/include/offsets_1352.h against the
     real image. Those offsets were derived from live probing; this is the first
     time we can confirm them statically, from the code itself.
  2. Build a string index and locate the symbols we care about.
  3. Map the image (entropy / zero density) so we know where code, rodata and
     data actually are.
"""
import collections
import math
import os
import re
import struct

IMG = r'C:\Users\Kinan\Downloads\JV13.52\kmemfull.bin'
OUT_STRINGS = r'C:\Users\Kinan\Downloads\JV13.52\kernel_strings.txt'

d = open(IMG, 'rb').read()
print('=' * 74)
print(f'image {IMG}  {len(d)} bytes ({len(d):#x})')
print('=' * 74)

# ---------------------------------------------------------------- ELF header
e_type, e_machine = struct.unpack_from('<HH', d, 0x10)
e_entry = struct.unpack_from('<Q', d, 0x18)[0]
e_phoff, e_shoff = struct.unpack_from('<QQ', d, 0x20)
e_phnum, e_shnum = struct.unpack_from('<H', d, 0x38)[0], struct.unpack_from('<H', d, 0x3c)[0]
print(f'\nELF: type={e_type:#x} machine={e_machine:#x} entry={e_entry:#x}')
print(f'     e_phoff={e_phoff:#x} e_phnum={e_phnum} e_shoff={e_shoff:#x} e_shnum={e_shnum}')
print('     e_phnum=0 is expected: this is the post-relocation live image.')

# ---------------------------------------------------------------- offsets check
# from kmemfull/include/offsets_1352.h
KNOWN = [
    ('KO_1352_FN_LOAD_SELF_BLOCK',      0x0063d180),
    ('KO_1352_FN_SM_START',             0x0063e470),
    ('KO_1352_FN_SM_FINALIZE',          0x0063ff00),
    ('KO_1352_FN_SM_REQUEST',           0x0063fff0),
    ('KO_1352_FN_SERVICE_MAILBOX',      0x00630230),
    ('KO_1352_FN_AUTHMGR_ISLOADABLE',   0x00642880),
    ('KO_1352_FN_AUTHMGR_AUTHHDR',      0x00642c90),
    ('KO_1352_FN_AUTHMGR_FINALIZE',     0x00643370),
    ('KO_1352_FN_AUTHMGR_LOAD',         0x006434d0),
]
TEXT_END = 0x00cfe758

print('\n' + '=' * 74)
print('FUNCTION OFFSETS — does the real code match our live-probe offsets?')
print('=' * 74)

# crude x86-64 prologue heuristics
PUSHES = set(range(0x50, 0x58))          # push rax..rdi
def looks_like_func(b):
    if not b:
        return 'empty'
    if b[:4] == b'\xf3\x0f\x1e\xfa':
        return 'endbr64'
    if b[0] == 0x55:
        return 'push rbp'
    if b[0] in PUSHES:
        return 'push reg'
    if b[0:2] == b'\x48\x83' or b[0:2] == b'\x48\x81':
        return 'sub rsp'
    if b[0] == 0x53 or b[0] == 0x41:
        return 'push rbx/r15'
    if b[0] == 0xe9:
        return 'jmp (thunk)'
    if b[0] == 0xc3:
        return 'ret'
    if b[0] == 0xcc:
        return 'int3 (padding)'
    return 'other'

for name, off in KNOWN:
    if off + 24 > len(d):
        print(f'  {name:<32} @{off:#08x}  OUT OF RANGE')
        continue
    b = d[off:off + 24]
    kind = looks_like_func(b)
    flag = 'OK ' if kind not in ('empty', 'int3 (padding)', 'other') else '?? '
    print(f'  [{flag}] {name:<32} @{off:#08x}  {kind:<14} {b.hex(" ")}')

print(f'\n  entry point offset = {e_entry - 0xffffffffc5530000:#x}  '
      f'(kbase was ffffffffc5530000 this boot)')
print(f'  bytes at entry     = {d[e_entry - 0xffffffffc5530000:][:24].hex(" ")}')

# ---------------------------------------------------------------- FreeBSD id
print('\n' + '=' * 74)
print('FREEBSD IDENTITY (decides which source tree to diff against)')
print('=' * 74)
for pat in (rb'FreeBSD \d+\.\d+[^\x00]{0,60}', rb'\d+\.\d+-RELEASE[^\x00]{0,40}',
            rb'FreeBSD[^\x00]{0,50}'):
    seen = set()
    for m in re.finditer(pat, d):
        s = m.group(0)
        if s in seen:
            continue
        seen.add(s)
        if len(seen) > 6:
            break
        print(f'  @{m.start():#09x}  {s[:70]!r}')

print('\n--- copyright banners ---')
for m in list(re.finditer(rb'Copyright \(c\) 19[^\x00]{0,90}', d))[:4]:
    print(f'  @{m.start():#09x}  {m.group(0)[:90]!r}')

# ---------------------------------------------------------------- strings
print('\n' + '=' * 74)
print('STRING INDEX + WHERE OUR SYMBOLS LIVE')
print('=' * 74)
strings = [(m.start(), m.group(0)) for m in re.finditer(rb'[ -~]{6,}', d)]
print(f'  total printable runs >= 6 chars: {len(strings)}')

TARGETS = [b'sceSblAuthMgrIsLoadable', b'sceSblAuthMgr', b'SblDrvHdlrSx', b'authmgr',
           b'80010008', b'SblDrv', b'Orbis', b'ORBISYS']
for t in TARGETS:
    hits = [o for o, s in strings if t in s]
    print(f'\n  {t.decode():<26} {len(hits)} string(s)')
    for o in hits[:6]:
        seg = d[o:o + 70].split(b'\x00')[0]
        print(f'      @{o:#09x}  {seg[:70]!r}')

with open(OUT_STRINGS, 'w', encoding='utf-8', errors='replace') as f:
    for o, s in strings:
        f.write(f'{o:#010x}\t{s.decode("utf-8", "replace")}\n')
print(f'\n  wrote {len(strings)} strings -> {OUT_STRINGS}')

# ---------------------------------------------------------------- region map
print('\n' + '=' * 74)
print('REGION MAP (64 KiB blocks: entropy + zero density)')
print('=' * 74)
BLK = 0x10000
rows = []
for off in range(0, len(d), BLK):
    blk = d[off:off + BLK]
    if not blk:
        break
    c = collections.Counter(blk)
    n = len(blk)
    ent = -sum((v / n) * math.log2(v / n) for v in c.values())
    rows.append((off, ent, c.get(0, 0) / n))

print(f'  {"offset":>10}  {"entropy":>7}  {"zero%":>6}  class')
for off, ent, z in rows:
    if off % (BLK * 32):
        continue
    if ent > 7.4:
        cls = 'encrypted/compressed or dense rodata'
    elif ent > 5.5:
        cls = 'code or mixed rodata'
    elif z > 0.9:
        cls = 'zeros (bss-like)'
    else:
        cls = 'sparse data'
    print(f'  {off:#010x}  {ent:7.3f}  {z*100:5.1f}%  {cls}')

zs = [z for _, _, z in rows]
es = [e for _, e, _ in rows]
print(f'\n  blocks={len(rows)}  entropy min/max={min(es):.3f}/{max(es):.3f}  '
      f'zero% min/max={min(zs)*100:.1f}/{max(zs)*100:.1f}')
