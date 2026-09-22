#!/usr/bin/env python3
"""Verify the AUTHORITATIVE 13.52 offsets from raw13g's ps4_offsets.js against
our independently-dumped kernel.

THIS IS THE CROSS-CHECK THE MISSION ASKED FOR: does the chain that jailbroke the
console agree with the kernel we pulled off it?

Note: my earlier check tested the 13.50 values (k_jmp_rsi 0x47b31, k_kl_lock
0xe6c20). Those are NOT 13.52's. The 13.52 entry overrides them:
    k_jmp_rsi : 0x4d6d0
    k_kl_lock : 0xe6c60
    k_sysent  : 0x1102b70   (table BASE)
    k_sysent_661 : 0x110a760 ( = base + 661*0x30 )
"""
import struct

IMG = r'C:\Users\Kinan\Downloads\JV13.52\1352-KERNEL-HANDOFF\kmemfull.bin'
d = open(IMG, 'rb').read()
KBASE = 0xFFFFFFFFC5530000  # this boot (from the dump); offsets are kbase-relative
TEXT_END = 0x00CFE758

# from ps4_offsets.js -> PS4["13.52"] (13.50 base + explicit overrides)
OFF = {
    # name: (value, expected kind)
    'k_jmp_rsi': (0x4D6D0, 'code'),
    'k_kl_lock': (0xE6C60, 'data'),
    'k_evf_cv': (0x785228, 'data'),
    'k_sysctl_handle_int': (0x3FA8E0, 'code'),
    'k_idt_rsvd': (0x1C1E00, 'data'),
    'k_sysent': (0x1102B70, 'data'),
    'k_sysent_661': (0x110A760, 'data'),
    'k_prison0': (0x1A5C0C0, 'data'),
    'k_rootvnode': (0x2136E90, 'data'),
    'k_oid_kern_file': (0x1A2F8A0, 'data'),
    'k_oid_maxfilesperproc': (0x1A2F950, 'data'),
    'k_oid_maxprocperuid': (0x1A3BA88, 'data'),
    'k_oid_maxfiles': (0x1A2F9A8, 'data'),
    'k_arg1_maxfilesperproc': (0x22CC47C, 'data'),
    'k_arg1_maxprocperuid': (0x22CC478, 'data'),
    'k_arg1_maxfiles': (0x22CC474, 'data'),
}

print(f'image {len(d):#x}   .text ends {TEXT_END:#x}\n')

print('=' * 78)
print('A. EVERY 13.52 OFFSET — in range? in the right region?')
print('=' * 78)
bad = []
for name, (off, kind) in sorted(OFF.items()):
    inrange = off + 16 <= len(d)
    region = ('<.text' if off < TEXT_END else '<.data')
    flag = ''
    if not inrange:
        flag = 'OUT OF RANGE'
        bad.append(name)
    elif kind == 'code' and not off < TEXT_END:
        flag = 'EXPECTED CODE BUT IN .data'
        bad.append(name)
    elif kind == 'data' and off < TEXT_END:
        flag = '!! EXPECTED DATA BUT IN .text !!'
        bad.append(name)
    print(f'  {name:<26} {off:#010x}  {region:<8} {kind:<5} {flag}')

print()
print('=' * 78)
print('B. THE GADGET TEST — k_jmp_rsi must be ff e6 (jmp rsi)')
print('=' * 78)
for off in (0x4D6D0, 0x47B31):
    b = d[off:off + 8]
    tag = 'k_jmp_rsi 13.52' if off == 0x4D6D0 else 'k_jmp_rsi 13.50 (old)'
    print(f'  {tag:<22} @{off:#08x}  {b.hex(" ")}  '
          f'{"<<< MATCH" if b[:2] == b"\xff\xe6" else "no"}')

# where are all the ff e6, and is any of them near the claimed value?
hits = []
i = d.find(b'\xff\xe6', 0, TEXT_END)
while i != -1:
    hits.append(i)
    i = d.find(b'\xff\xe6', i + 1, TEXT_END)
print(f'\n  all {len(hits)} "ff e6" in .text: {[hex(h) for h in hits]}')
near = [h for h in hits if abs(h - 0x4D6D0) < 0x1000]
print(f'  any within 0x1000 of 0x4d6d0? {[hex(h) for h in near] if near else "NONE"}')
shift = [h - 0x4D6D0 for h in hits]
print(f'  implied uniform shift if any matches: {[hex(s) for s in shift]}')

print()
print('=' * 78)
print('C. sysent STRUCTURE — base 0x1102b70, and 661*0x30 = 0x7bf0')
print('=' * 78)
base = 0x1102B70
print(f'  base + 661*0x30 = {base + 661 * 0x30:#x} '
      f'(k_sysent_661 claims {0x110A760:#x}) -> '
      f'{"CONSISTENT" if base + 661 * 0x30 == 0x110A760 else "INCONSISTENT"}')
for i in (0, 1, 2, 3, 4, 5, 660, 661, 662):
    e = base + i * 0x30
    if e + 0x18 > len(d):
        continue
    n = struct.unpack_from('<i', d, e)[0]
    c = struct.unpack_from('<Q', d, e + 8)[0]
    ok = 'text-ptr' if KBASE <= c < KBASE + TEXT_END else 'not-a-text-ptr'
    print(f'  sysent[{i:>3}] @{e:#010x}  narg={n:<13} sy_call={c:#018x}  {ok}')

print()
print('=' * 78)
print('D. k_kl_lock — the data-vs-code problem')
print('=' * 78)
for name, off in (('k_kl_lock 13.52', 0xE6C60), ('k_kl_lock 13.50', 0xE6C20)):
    b = d[off:off + 32]
    print(f'  {name:<20} @{off:#08x}  {b.hex(" ")}')
print(f'  (both are < TEXT_END {TEXT_END:#x}, i.e. inside .text)')

print()
print('=' * 78)
print('E. Sanity: do the clearly-data offsets hold plausible pointers?')
print('=' * 78)
for name in ('k_prison0', 'k_rootvnode', 'k_oid_kern_file', 'k_evf_cv'):
    off = OFF[name][0]
    v = struct.unpack_from('<Q', d, off)[0]
    looks = 'kernel-ptr' if (v >> 40) == 0xFFFFFF else f'{v:#x}'
    print(f'  {name:<18} @{off:#010x}  first u64 = {v:#018x}  {looks}')
