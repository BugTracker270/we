#!/usr/bin/env python3
"""Two decisive questions:

Q1  Does k_jmp_rsi = 0x4d6d0 hold "ff e6"? If yes the base convention matches
    and our dump's offset 0 IS the chain's kbase.

Q2  How far does the kernel's mapped image actually extend? Three chain offsets
    (k_rootvnode 0x2136e90, k_arg1_maxfiles* 0x22cc47x) are past our 0x1b265e8
    end, and ps4_offsets.js itself says the reference dump was 36 MB.
"""
import struct

IMG = r'C:\Users\Kinan\Downloads\JV13.52\1352-KERNEL-HANDOFF\kmemfull.bin'
d = open(IMG, 'rb').read()
print(f'our dump: {len(d)} B = {len(d):#x}\n')

print('=' * 78)
print('Q1. k_jmp_rsi = 0x4d6d0  (13.52 value)')
print('=' * 78)
b = d[0x4D6D0:0x4D6D0 + 16]
print(f'  @0x4d6d0  {b.hex(" ")}')
print(f'  first two bytes ff e6? {"YES" if b[:2] == b"\xff\xe6" else "NO"}')

hits = []
i = d.find(b'\xff\xe6')
while i != -1:
    hits.append(i)
    i = d.find(b'\xff\xe6', i + 1)
print(f'\n  all {len(hits)} "ff e6" in the image:')
print(f'    {[hex(h) for h in hits]}')
near = [(h, h - 0x4D6D0) for h in hits if abs(h - 0x4D6D0) < 0x20000]
print(f'  closest to 0x4d6d0: {[(hex(h), hex(s)) for h, s in near]}')

print()
print('=' * 78)
print('Q2. HOW FAR DOES THE IMAGE GO?')
print('=' * 78)
# highest offset with any non-zero byte
last = len(d) - 1
while last > 0 and d[last] == 0:
    last -= 1
print(f'  our dump ends at            {len(d):#x}')
print(f'  last non-zero byte at       {last:#x}')

# does the dump contain kernel pointers pointing past our end?
KBASE = 0xFFFFFFFFC5530000
ptr_hits = 0
maxrel = 0
for off in range(0x1520000, len(d) - 8, 8):
    v = struct.unpack_from('<Q', d, off)[0]
    if KBASE <= v < KBASE + 0x4000000:
        ptr_hits += 1
        rel = v - KBASE
        if rel > maxrel:
            maxrel = rel
print(f'  kernel pointers found in .data: {ptr_hits}')
print(f'  highest pointer target offset : {maxrel:#x}')
print(f'  -> the kernel itself references memory out to at least {maxrel:#x}')

# what does the chain need?
NEED = {
    'k_oid_kern_file': 0x1A2F8A0, 'k_oid_maxfilesperproc': 0x1A2F950,
    'k_oid_maxprocperuid': 0x1A3BA88, 'k_oid_maxfiles': 0x1A2F9A8,
    'k_prison0': 0x1A5C0C0, 'k_rootvnode': 0x2136E90,
    'k_arg1_maxfiles': 0x22CC474, 'k_arg1_maxfilesperproc': 0x22CC47C,
    'k_arg1_maxprocperuid': 0x22CC478,
}
print('\n  chain offsets vs our dump end:')
for n, off in sorted(NEED.items(), key=lambda kv: kv[1]):
    print(f'    {n:<26} {off:#010x}  '
          f'{"OK" if off < len(d) else "*** BEYOND OUR DUMP ***"}')

print()
print('=' * 78)
print('Q3. What is actually AT k_prison0 (0x1a5c0c0)? It read 0x0.')
print('=' * 78)
for off in (0x1A2F8A0, 0x1A2F950, 0x1A3BA88, 0x1A5C0C0):
    vals = [struct.unpack_from('<Q', d, off + k * 8)[0] for k in range(4)]
    nz = sum(1 for v in vals if v)
    print(f'  @{off:#010x}  ' + '  '.join(f'{v:#018x}' for v in vals) +
          f'   non-zero={nz}/4')

print()
print('=' * 78)
print('Q4. Is the region 0x1520000..0x1b265e8 really live data, or mostly zeros?')
print('=' * 78)
for start in range(0x1500000, 0x1b00000, 0x80000):
    blk = d[start:start + 0x80000]
    z = blk.count(0)
    print(f'  {start:#010x}..{start+len(blk):#010x}  zeros {100*z/len(blk):5.1f}%')
