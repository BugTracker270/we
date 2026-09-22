#!/usr/bin/env python3
"""Recover the module function-name tables.

The string table next to the authmgr build paths is contiguous and ordered:
module file path, then that module's function names, then the next module. On a
plaintext kernel this is effectively a free symbol table for the code we care
about - it lets us LABEL the disassembly instead of reading anonymous offsets.
"""
import re

IMG = r'C:\Users\Kinan\Downloads\JV13.52\kmemfull.bin'
OUT = r'C:\Users\Kinan\Downloads\JV13.52\kernel_symbols.txt'
d = open(IMG, 'rb').read()

LO, HI = 0xAEB000, 0xAEE800
print(f'scanning {LO:#x}..{HI:#x} for the name table\n')

runs = []
for m in re.finditer(rb'[ -~]{4,}', d[LO:HI]):
    runs.append((LO + m.start(), m.group(0).decode('utf-8', 'replace')))

# group into: [build path][names...] repeated
groups = []
cur = None
for off, s in runs:
    if s.startswith('W:\\Build\\'):
        cur = {'path': s, 'off': off, 'names': []}
        groups.append(cur)
    elif cur is not None:
        cur['names'].append((off, s))

for g in groups:
    short = g['path'].split('\\')[-1]
    print('=' * 74)
    print(f"MODULE  {short}")
    print(f"  build  {g['path']}")
    print(f"  @{g['off']:#010x}   {len(g['names'])} name(s)")
    for off, n in g['names']:
        # skip obvious message strings; keep identifier-looking names
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{2,60}', n):
            print(f'      {n}')

print()
print('=' * 74)
print('filtered symbol list (identifier-shaped only)')
print('=' * 74)
syms = []
for g in groups:
    for off, n in g['names']:
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{2,60}', n):
            syms.append((g['path'].split('\\')[-1], off, n))
print(f'total: {len(syms)} symbols')
with open(OUT, 'w', encoding='utf-8') as f:
    f.write('# module\tvaddr\tsymbol\n')
    for mod, off, n in syms:
        f.write(f'{mod}\t{off:#010x}\t{n}\n')
print(f'wrote -> {OUT}')

# cross-check our known offsets against names that appeared
print()
print('--- names matching our offsets_1352.h functions ---')
for pat in ('SmStart', 'SmFinalize', 'LoadSelfBlock', 'IsLoadable', 'AuthHeader',
            'SmRequest', 'ServiceMailbox', 'SmGicGetData', 'SmDriveGetId2'):
    hit = [n for _, _, n in syms if pat.lower() in n.lower()]
    print(f'  {pat:<18} {hit if hit else "(not in this window)"}')
