"""Analyse the v10 128 KiB window: AuthMgr ctx table, SM handle, key banks,
and the pointer graph leaving the block."""
import struct, re, collections

PATH = r'C:\Users\Kinan\Downloads\JV13.52\v10_kmem_img.bin'
WIN  = 0x02680000            # koff the window starts at
KBASE_LO = 0xffffffff80000000

d = open(PATH, 'rb').read()
print(f"window {len(d):,} bytes, koff 0x{WIN:x}..0x{WIN+len(d):x}")

K = lambda ko: ko - WIN      # koff -> file offset


def u32(ko):
    return struct.unpack_from('<I', d, K(ko))[0]


def u64(ko):
    return struct.unpack_from('<Q', d, K(ko))[0]


def inwin(ko):
    return 0 <= K(ko) and K(ko) + 8 <= len(d)


print("\n=== SM / AuthMgr scalars (from offsets_1352.h) ===")
for name, ko, fmt in [("SM_FLAG (byte)", 0x0269C098, 'B'),
                      ("AUTHMGR_HANDLE (u64)", 0x0269C0A0, 'Q'),
                      ("BUF_A (u64)", 0x0269C0B0, 'Q'),
                      ("BUF_B (u64)", 0x0269C0C0, 'Q'),
                      ("SM_MTX (u32)", 0x0269C0C8, 'I')]:
    if inwin(ko):
        v = struct.unpack_from('<' + fmt, d, K(ko))[0]
        print(f"  {name:<24} @0x{ko:x} = 0x{v:x}")

print("\n=== AuthMgr context table: 4 x 0x60 @ 0x0269C140 ===")
for i in range(4):
    base = 0x0269C140 + i * 0x60
    if not inwin(base + 0x48):
        continue
    state = u32(base + 0x00)
    idx = u32(base + 0x30)
    buf = u64(base + 0x38)
    print(f"  ctx[{i}] @0x{base:x}  state={state} idx=0x{idx:x} buffer=0x{buf:x}")

print("\n=== SBL req object @ 0x02681B80 (0x1C0 bytes) ===")
for off in range(0, 0x1C0, 8):
    ko = 0x02681B80 + off
    if inwin(ko):
        v = u64(ko)
        if v:
            print(f"  +0x{off:03x}  0x{v:016x}")

print("\n=== key-bank terminator shape anywhere in the window ===")
pat = re.compile(rb'....\x00\x01\x00\x00....\x08\x00\x00\x00....\x00\x01\x00\x00', re.S)
hits = [m.start() for m in pat.finditer(d)]
print(f"  matches: {len(hits)}")
for h in hits[:20]:
    print(f"    file 0x{h:x}  koff 0x{WIN + h:x}")

print("\n=== pointer census: u64 values that look like kernel addresses ===")
buckets = collections.Counter()
examples = {}
for off in range(0, len(d) - 7, 1):
    v = struct.unpack_from('<Q', d, off)[0]
    if v >= 0xffff000000000000:
        if KBASE_LO <= v < 0xffffffffa0000000:
            b = 'kernel image  (0xffffffff8...)'
        elif 0xffffc00000000000 <= v < 0xffffd00000000000:
            b = 'arena 0xffffc1...'
        elif 0xffff800000000000 <= v < 0xffff900000000000:
            b = 'direct map 0xffff88...'
        else:
            b = 'other 0x%04x...' % (v >> 48)
        buckets[b] += 1
        if b not in examples:
            examples[b] = (WIN + off, v)
for b, n in buckets.most_common():
    ko, v = examples[b]
    print(f"  {n:>5}  {b}   e.g. @koff 0x{ko:x} -> 0x{v:x}")

print("\n=== printable strings >= 6 chars in the window ===")
for m in re.finditer(rb'[\x20-\x7e]{6,}', d):
    print(f"  koff 0x{WIN + m.start():x}  {m.group().decode()[:90]}")
