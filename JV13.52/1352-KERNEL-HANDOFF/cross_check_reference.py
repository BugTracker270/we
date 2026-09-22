#!/usr/bin/env python3
"""Cross-check our fresh dump against the reference artefacts that ALREADY exist.

Discovered on disk:
  C:\\Users\\Kinan\\Downloads\\czdji0\\1352k.elf      20,080,104 B  <- reference 13.52
  C:\\Users\\Kinan\\Downloads\\czdji0\\1350.elf       21,657,064 B
  C:\\Users\\Kinan\\Downloads\\czdji0\\1302.elf       21,657,064 B
  C:\\Users\\Kinan\\Downloads\\czdji0\\1150k.elf      20,080,096 B
  C:\\Users\\Kinan\\Downloads\\WORKING-dumper-v6..v9\\   previous working dumpers

Also: the patch blobs are raw x86-64 shellcode (LSTAR/LDR defeat), and the ONLY
per-firmware difference is an embedded address:
    1302.bin -> 0x1b76f3
    1350.bin -> 0x1b7703
    1352.bin -> 0x1b77a3
"""
import struct

OURS = r'C:\Users\Kinan\Downloads\JV13.52\1352-KERNEL-HANDOFF\kmemfull.bin'
REF = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'

d = open(OURS, 'rb').read()
print(f'OURS   kmemfull.bin   {len(d)} B  ({len(d):#x})')
print(f'       sha256 {__import__("hashlib").sha256(d).hexdigest()[:32]}...')
print()

print('=' * 78)
print('1. The 13.52 patch-site address embedded in 1352.bin: 0x1b77a3')
print('=' * 78)
for off in (0x1B77A3, 0x1B7703, 0x1B76F3):
    tag = {0x1B77A3: '13.52 (1352.bin)', 0x1B7703: '13.50', 0x1B76F3: '13.02'}[off]
    b = d[off:off + 16]
    print(f'  {tag:<18} @{off:#09x}  {b.hex(" ")}')

print()
print('=' * 78)
print('2. Reference 1352k.elf — what is it?')
print('=' * 78)
try:
    r = open(REF, 'rb').read()
    print(f'  size {len(r)} ({len(r):#x})')
    print(f'  first 16 bytes: {r[:16].hex(" ")}')
    print(f'  magic: {r[:4]!r}')
    if r[:4] == b'\x7fELF':
        e_type, e_machine = struct.unpack_from('<HH', r, 0x10)
        e_entry = struct.unpack_from('<Q', r, 0x18)[0]
        e_phoff, e_shoff = struct.unpack_from('<QQ', r, 0x20)
        e_phnum = struct.unpack_from('<H', r, 0x38)[0]
        print(f'  ELF: type={e_type:#x} machine={e_machine:#x} entry={e_entry:#x} '
              f'phoff={e_phoff:#x} phnum={e_phnum} shoff={e_shoff:#x}')
    else:
        # raw image? find where our image's first bytes appear
        probe = d[:64]
        j = r.find(probe)
        print(f'  not an ELF. does its content match OURS? our first 64 B at {j:#x}'
              if j >= 0 else '  not an ELF, and our first 64 B are not inside it')
    # does it contain the ORBISYS anchor?
    j = r.find(b'ORBISYS')
    print(f'  "ORBISYS" at {j:#x}' if j >= 0 else '  "ORBISYS" absent')

    # compare overlapping region byte-for-byte
    n = min(len(d), len(r))
    same = sum(1 for i in range(0, n, 4096) if d[i:i + 4096] == r[i:i + 4096])
    total = len(range(0, n, 4096))
    print(f'\n  overlap comparison (first {n:#x} bytes, 4 KiB blocks): '
          f'{same}/{total} identical ({100.0*same/total:.1f}%)')

    # find the shift that aligns ORBISYS
    ko = d.find(b'ORBISYS')
    kr = r.find(b'ORBISYS')
    if ko >= 0 and kr >= 0:
        print(f'  ORBISYS: ours @{ko:#x}, ref @{kr:#x}  -> shift {ko - kr:+#x}')
except FileNotFoundError as e:
    print(f'  {e}')

print()
print('=' * 78)
print('3. What the chain needs vs what our dump has')
print('=' * 78)
need = [('k_rootvnode', 0x2136E90), ('k_arg1_maxfiles', 0x22CC474),
        ('k_arg1_maxprocperuid', 0x22CC478), ('k_arg1_maxfilesperproc', 0x22CC47C)]
for n_, off in need:
    print(f'  {n_:<24} {off:#010x}  {"OK" if off < len(d) else "MISSING"}')
print(f'\n  our dump covers 0x0..{len(d):#x}')
print(f'  chain needs to at least 0x22cc47c  ->'
      f' short by {0x22CC47C - len(d):#x} ({(0x22CC47C - len(d))/1048576:.1f} MiB)')
print(f'  ps4_offsets.js says the reference dump was 36 MB (0x2400000)')
print(f'  -> a second pass over 0x1b265e8..0x2400000 (~{(0x2400000-len(d))/1048576:.1f} MiB) closes it')
