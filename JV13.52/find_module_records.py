"""Find the SBL module records for every secure module by their SIZE.

The one record we can read has this shape:

    0x02680808  0xffffff806b8e0000
    0x02680810  0xffffc18716072780     <- arena pointer
    0x02680848  "8001000B"
    0x02680850  0x000000000000e3a4     <- 58,276  == 8001000B's size, exactly
    0x02680858  0xffffffff8616a9eb     <- .text pointer

The names of the other modules are not stored as strings, but the SIZES are
known from the SLB2 directory we already parsed. So: hunt the known sizes.
The one we want is 80010008 (AuthMgr) = 88,304.
"""
import struct, re, collections

DUMP = r'C:\Users\Kinan\Downloads\JV13.52\v11_kmem_img.bin'
KOFF = 0x1520000
d = open(DUMP, 'rb').read()

SIZES = {
    '80010001 SecureKernel': 98672,
    '80010002 Kernel':       10866322,
    '80010006':              41920,
    '80010009':              17348,
    '8001000A':              25524,
    '80010008 AuthMgr':      88304,
    '8001000B':              58276,
}

# build value -> set of aligned file offsets
offsets = collections.defaultdict(list)
for name, sz in SIZES.items():
    v8 = struct.pack('<Q', sz)
    v4 = struct.pack('<I', sz)
    for m in re.finditer(re.escape(v8), d):
        if m.start() % 8 == 0:
            offsets[name].append((m.start(), 'u64'))
    for m in re.finditer(re.escape(v4), d):
        if m.start() % 8 == 0:
            offsets[name].append((m.start(), 'u32'))

print("=== aligned occurrences of each module size ===")
for name, sz in SIZES.items():
    print(f"\n--- {name}  size={sz:,} (0x{sz:x}) ---")
    for fo, kind in offsets[name]:
        ko = KOFF + fo
        # look at a window around it, before and after
        pre = []
        for back in (0x50, 0x48, 0x40, 0x38, 0x30, 0x28, 0x20, 0x18, 0x10, 0x08):
            f = fo - back
            if f >= 0:
                v = struct.unpack_from('<Q', d, f)[0]
                if v:
                    pre.append((back, v))
        arenas = [v for _, v in pre if 0xffffc00000000000 <= v < 0xffffc20000000000]
        imgs = [v for _, v in pre if 0xffffffff80000000 <= v < 0xffffffff85680000 + 0x2834af0]
        strs = re.findall(rb'[\x20-\x7e]{4,16}', d[fo:fo + 64])
        print(f"  koff 0x{ko:x} ({kind})"
              f"  arena_before={[hex(a) for a in arenas]}"
              f"  img_before={[hex(i) for i in imgs]}"
              f"  str_after={[s.decode() for s in strs]}")
