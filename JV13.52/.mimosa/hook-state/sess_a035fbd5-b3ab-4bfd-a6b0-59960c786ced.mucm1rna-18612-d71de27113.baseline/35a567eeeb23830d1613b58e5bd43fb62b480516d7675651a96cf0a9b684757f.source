"""Identify every SELF/ELF artifact we hold locally. Read-only, offline."""
import os, struct

BASE = r'C:\Users\Kinan\Downloads\JV13.52'
FILES = [
    r'dec\80010002_kernel_14.00.self',
    r'dec\1352\80010001.self',
    r'dec\1352\80010002.self',
    r'dec\1352\80010008.self',
    r'1352k.elf',
    r'dec\unpacked1\secure_modules.bin',
    r'dec\unpacked1\orbis_swu.self',
    r'dec\unpacked1\torus2_firmware.bin',
]

SELF_MAGIC = 0x1D3D154F
ELF_MAGIC = b'\x7fELF'


def show(rel):
    p = os.path.join(BASE, rel)
    if not os.path.exists(p):
        print(f"{rel:<44} MISSING")
        return
    d = open(p, 'rb').read()
    head = d[:64]
    if d[:4] == ELF_MAGIC:
        kind = 'ELF (plaintext)'
    elif struct.unpack_from('<I', d, 0)[0] == SELF_MAGIC:
        kind = 'SELF (ENCRYPTED)'
    else:
        kind = 'unknown'
    print(f"{rel:<44} {len(d):>10,} B   {kind}")
    print(f"    first32: {head[:32].hex(' ')}")
    if kind.startswith('SELF'):
        # layout per self.h: magic, ver, mode, endian, attr, keytype, pad,
        # hdr_size, meta_size, file_size, num_entries, flags
        f = struct.unpack_from('<IIIIHHIQQQI', d, 0)
        print(f"    ver={f[1]} mode={f[2]} endian={f[3]} attr={f[4]} keyType={f[5]} "
              f"hdrSize=0x{f[7]:x} metaSize=0x{f[8]:x} fileSize={f[9]:,} entries={f[10]}")
        # walk the entry table (0x20 bytes each) after the 0x20-byte header
        off = 0x20
        tot = 0
        for i in range(min(f[10], 8)):
            if off + 0x20 > len(d):
                break
            eid, eflags, esize, ecomp = struct.unpack_from('<QQQQ', d, off)
            print(f"      entry[{i}] id=0x{eid:08x} flags=0x{eflags:x} "
                  f"size=0x{esize:x} comp=0x{ecomp:x}")
            tot += esize
            off += 0x20
    print()


for rel in FILES:
    show(rel)
