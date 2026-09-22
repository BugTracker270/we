#!/usr/bin/env python3
"""Decode raw13g's patch blobs — especially 1352.bin, the one the console chain
actually applies. The blob is the ground truth for what the chain WRITES, which
settles what the gadget bytes really are.
"""
import struct

BASE = r'C:\Users\Kinan\Downloads\JV13.52\1352-KERNEL-HANDOFF\raw13g-webkit-jb\raw13g.github.io-main\patches'
for name in ('1352.bin', '1350.bin', '1302.bin'):
    p = f'{BASE}\\{name}'
    d = open(p, 'rb').read()
    print('=' * 78)
    print(f'{name}   {len(d)} bytes')
    print('=' * 78)
    print(f'  first 64 bytes: {d[:64].hex(" ")}')
    magic = d[:4]
    print(f'  magic: {magic!r}  ascii={magic.decode("latin-1")!r}')
    print(f'  bytes 4..8: {d[4:8].hex(" ")}')

    # try the documented CTAP layout: magic(4) ver(4) count(4) then N*record
    for hdrsz in (12, 16):
        if len(d) > hdrsz:
            cnt = struct.unpack_from('<I', d, 8)[0]
            rem = len(d) - hdrsz
            for recsz in (8, 12, 16, 24, 32):
                if rem % recsz == 0 and rem // recsz == cnt:
                    print(f'  *** layout fits: header {hdrsz}, count {cnt}, record {recsz}')

    # try: count at 0x04
    for off_cnt in (4, 8):
        if len(d) > off_cnt + 4:
            c = struct.unpack_from('<I', d, off_cnt)[0]
            if 0 < c < 200:
                rem = len(d) - (off_cnt + 4)
                cands = [r for r in (4, 8, 12, 16, 24, 32) if rem % r == 0 and rem // r == c]
                if cands:
                    print(f'  count@{off_cnt:#x} = {c}; record sizes {cands}')

    print('  --- as u32 array (first 24) ---')
    n = min(24, len(d) // 4)
    print('   ', [hex(v) for v in struct.unpack_from(f'<{n}I', d, 0)])
    print('  --- as u64 array (first 12) ---')
    n = min(12, len(d) // 8)
    print('   ', [hex(v) for v in struct.unpack_from(f'<{n}Q', d, 0)])
    print()
