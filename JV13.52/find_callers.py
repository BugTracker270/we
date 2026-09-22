#!/usr/bin/env python3
"""Find every direct `call rel32` (opcode E8) that targets one of the given koffs.

Byte-pattern scan rather than linear disassembly, so it is O(n) over the whole
image and cannot desync.
"""
import struct, sys

ELF = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KB = 0xffffffff82200000
d = open(ELF, 'rb').read()

TARGETS = {}
for a in sys.argv[1:]:
    v = int(a, 16)
    TARGETS[v] = []
    # both a koff (image-relative) and the full kernel VA are accepted
    TARGETS[v].append(a)

n = len(d)
for off in range(0, n - 5):
    if d[off] != 0xE8:
        continue
    disp = struct.unpack_from('<i', d, off + 1)[0]
    tgt = (KB + off + 5 + disp) - KB          # == image-relative target
    key = None
    for k in TARGETS:
        if tgt == k:
            key = k
            break
    if key is None:
        continue
    TARGETS[key].append(f"{off:#09x}")

for k, hits in TARGETS.items():
    print(f"callers of 0x{k:06x}:")
    for h in hits[1:]:
        print(f"    call site 0x{h}")
    if len(hits) == 1:
        print("    (none found by direct call)")
