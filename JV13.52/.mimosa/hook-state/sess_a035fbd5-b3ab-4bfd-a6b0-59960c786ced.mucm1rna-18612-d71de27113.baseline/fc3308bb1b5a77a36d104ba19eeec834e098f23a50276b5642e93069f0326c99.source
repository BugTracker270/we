#!/usr/bin/env python3
"""Every differing byte in the first 0x200 of the 13.52 vs 14.00 kernel SELFs,
annotated with which SELF-header field each offset belongs to.

This is the decisive question for the offline route: if the only differences are
sizes/digests/offsets (things that MUST change when the payload changes), then both
SELFs select the same key bank and a key extracted from any FW decrypts both. If a
key-selector field differs, 14.00 needs a key you do not have.
"""
import struct

A = r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\80010002.self'
B = r'C:\Users\Kinan\Downloads\JV13.52\dec\80010002_kernel_14.00.self'

da = open(A, 'rb').read()
db = open(B, 'rb').read()

FIELDS = [
    (0x00, 4, 'magic'),
    (0x04, 1, 'version'),
    (0x05, 1, 'mode'),
    (0x06, 1, 'endian'),
    (0x07, 1, 'attr (=0x12 for both)'),
    (0x08, 4, 'key_type   <-- THE KEY SELECTOR'),
    (0x0C, 2, 'header_size'),
    (0x0E, 2, 'metadata_size'),
    (0x10, 8, 'file_size'),
    (0x18, 2, 'num_entries'),
    (0x1A, 2, 'flags'),
    (0x20, 0x20 * 4, 'entry table (offsets/sizes/digests)'),
]


def field_of(off):
    for base, ln, name in FIELDS:
        if base <= off < base + ln:
            return name
    return '?'


print(f'A = 13.52 kernel  ({len(da)} B)')
print(f'B = 14.00 kernel  ({len(db)} B)')
print()

n = min(len(da), len(db), 0x200)
diffs = [i for i in range(n) if da[i] != db[i]]
print(f'differing bytes in first {n:#x}: {len(diffs)}')

groups = {}
for i in diffs:
    groups.setdefault(field_of(i), []).append(i)

print('\ndifferences grouped by field:')
for name in dict.fromkeys([f[2] for f in FIELDS]):
    if name in groups:
        offs = groups[name]
        lo, hi = min(offs), max(offs)
        at = ', '.join(f'{o:#x}' for o in offs[:8]) + (' ...' if len(offs) > 8 else '')
        print(f'  {name:<44} {len(offs):>4} byte(s)  range {lo:#x}-{hi:#x}   {at}')
    else:
        print(f'  {name:<44}    -   identical')

print()
kt_a, = struct.unpack_from('<I', da, 0x08)
kt_b, = struct.unpack_from('<I', db, 0x08)
print(f'key_type 13.52 = {kt_a:#010x}')
print(f'key_type 14.00 = {kt_b:#010x}')
print('=> SAME key bank' if kt_a == kt_b else '=> DIFFERENT key bank')
print(f'key-selector bytes 0x08-0x0B differ: '
      f'{da[0x08:0x0C] != db[0x08:0x0C]}')
print(f'signature/digest block 0x40-0x7F differ: {da[0x40:0x80] != db[0x40:0x80]}')
