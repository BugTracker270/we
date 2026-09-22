#!/usr/bin/env python3
"""Find the REAL sysent base in the 13.52 dump by signature.

FreeBSD sysent[i] = { int sy_narg; /*pad*/ sy_call_t *sy_call; ... } with a
0x30 stride. We know the expected argument counts for the low syscalls:

  1  exit    1        4  write   3        7  wait4   4
  2  fork    0        5  open    3        8  creat   2
  3  read    3        6  close   1        9  link    2

Those nine values together are a very strong signature. Any base where all nine
match AND every sy_call is a .text pointer is the real table.
"""
import struct

IMG = r'C:\Users\Kinan\Downloads\JV13.52\kmemfull.bin'
d = open(IMG, 'rb').read()
TEXT_LO, TEXT_HI = 0xFFFFFFFFFF000000, 0xFFFFFFFFD0000000  # loose kernel-VA test
KLO, KHI = 0xFFFFFFFFC5000000, 0xFFFFFFFFC7000000           # observed text VAs

STRIDE = 0x30
EXPECT = {1: 1, 2: 0, 3: 3, 4: 3, 5: 3, 6: 1, 7: 4, 8: 2, 9: 2}


def narg_at(b, i):
    return struct.unpack_from('<i', d, b + i * STRIDE)[0]


def call_at(b, i):
    return struct.unpack_from('<Q', d, b + i * STRIDE + 8)[0]


print('scanning for sysent signature (narg pattern 1,0,3,3,3,1,4,2,2 at [1..9])...')
found = []
for b in range(0x00A00000, 0x01400000, 8):
    if b + 10 * STRIDE > len(d):
        break
    good = True
    for i, want in EXPECT.items():
        if narg_at(b, i) != want:
            good = False
            break
    if not good:
        continue
    # every sy_call must look like a kernel text pointer
    calls = [call_at(b, i) for i in range(1, 10)]
    if not all(KLO <= c <= KHI for c in calls):
        continue
    n_in_text = sum(1 for i in range(0, 64) if KLO <= call_at(b, i) <= KHI)
    found.append((b, n_in_text))

print(f'\ncandidates: {len(found)}')
for b, n in found:
    print(f'  base {b:#010x}   entries 0..63 with text sy_call: {n}/64')

if found:
    b = found[0][0]
    print(f'\n--- table at base {b:#x} ---')
    for i in list(range(0, 12)) + [660, 661, 662]:
        e = b + i * STRIDE
        if e + STRIDE > len(d):
            continue
        n = narg_at(b, i)
        c = call_at(b, i)
        print(f'  sysent[{i:>3}] @{e:#010x}  narg={n}  sy_call={c:#018x}')

    print(f'\n  implied: kbase = 0xffffffffc5530000 (this boot)')
    print(f'           sysent base offset = {b:#x}')

    # where does the table start / end
    lo = b
    while lo - STRIDE >= 0 and KLO <= call_at(lo - STRIDE, 0) <= KHI and abs(narg_at(lo - STRIDE, 0)) < 16:
        lo -= STRIDE
    hi = b
    while hi + STRIDE < len(d) and KLO <= call_at(hi + STRIDE, 0) <= KHI and abs(narg_at(hi + STRIDE, 0)) < 16:
        hi += STRIDE
    print(f'           contiguous run: {lo:#x} .. {hi:#x}  '
          f'({(hi - lo) // STRIDE + 1} entries)')
