"""Proper (8-byte aligned) pointer census over the 19 MB dump.

The earlier census stepped byte-by-byte and produced shifted-garbage hits.
This one only reads aligned qwords and buckets every kernel pointer by region,
so we can see the arena's actual layout and pick a dump window for it.
"""
import struct, collections

DUMP = r'C:\Users\Kinan\Downloads\JV13.52\v11_kmem_img.bin'
KOFF = 0x1520000
KBASE = 0xffffffff85680000
IMG_END = KBASE + 0x2834af0


def region(v):
    if KBASE <= v < IMG_END:
        return 'kernel image (kbase..+0x2834af0)'
    if v >= 0xffffffff80000000:
        return 'other kernel-image-range 0xffffffff8...'
    if 0xffffc00000000000 <= v < 0xffffc20000000000:
        return 'arena 0xffffc1...'
    if 0xffff800000000000 <= v < 0xffff900000000000:
        return 'dmap 0xffff88...'
    return 'other 0x%04x...' % (v >> 48)


d = open(DUMP, 'rb').read()
print(f"dump {len(d):,} B, whole-qword scan ({len(d)//8:,} qwords)\n")

counts = collections.Counter()
samples = collections.defaultdict(list)
arena_min, arena_max = None, None

for i in range(0, len(d) - 8, 8):
    v = struct.unpack_from('<Q', d, i)[0]
    if v < 0xffff000000000000:
        continue
    r = region(v)
    counts[r] += 1
    if len(samples[r]) < 6:
        samples[r].append((KOFF + i, v))
    if r == 'arena 0xffffc1...':
        arena_min = v if arena_min is None else min(arena_min, v)
        arena_max = v if arena_max is None else max(arena_max, v)

print("=== pointer buckets ===")
for r, n in counts.most_common():
    print(f"  {n:>6}  {r}")
    for ko, v in samples[r]:
        print(f"            @koff 0x{ko:x} -> 0x{v:x}")

print("\n=== arena 0xffffc1... extent ===")
if arena_min is not None:
    print(f"  min 0x{arena_min:x}")
    print(f"  max 0x{arena_max:x}")
    span = arena_max - arena_min
    print(f"  span 0x{span:x} ({span / 1048576:.2f} MB)")
    # cluster into 16 MB buckets so we can choose windows
    b = collections.Counter()
    for i in range(0, len(d) - 8, 8):
        v = struct.unpack_from('<Q', d, i)[0]
        if 0xffffc00000000000 <= v < 0xffffc20000000000:
            b[v & ~0xFFFFFF] += 1        # 16 MB buckets
    print("\n  top 16 MB buckets:")
    for base, n in b.most_common(20):
        print(f"    0x{base:x} .. 0x{base + 0xFFFFFF:x}   x{n}")
else:
    print("  none")
