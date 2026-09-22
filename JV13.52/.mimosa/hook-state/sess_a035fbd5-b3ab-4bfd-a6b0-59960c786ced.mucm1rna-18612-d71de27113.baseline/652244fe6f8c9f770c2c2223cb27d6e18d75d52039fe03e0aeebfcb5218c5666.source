#!/usr/bin/env python3
"""Print magic/version/mode/header_size/meta_size/file_size/num_entries for every
SELF on hand, so the 'total_header_size' the console's own contexts carry
(0x750 / 0x780 in the live dump) can be matched against a real module.
"""
import glob, os, struct

SELF_MAGIC = 0x1D3D154F

files = []
for pat in (r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\*.self',
            r'C:\Users\Kinan\Downloads\JV13.52\dec\*.self',
            r'C:\Users\Kinan\Downloads\JV13.52\dec\unpacked1\*.self'):
    files += glob.glob(pat)

print(f'{"file":<28} {"magic":>10} {"ver":>3} {"mode":>4} {"hdrsz":>7} {"meta":>7} '
      f'{"hdrmeta":>8} {"filesz":>10} {"nent":>4} {"keytype":>7} {"elfauth":>7}')
for f in sorted(set(files)):
    d = open(f, 'rb').read(0x40)
    if len(d) < 0x40:
        continue
    magic, ver, mode, endian, attr = struct.unpack_from('<IBBBB', d, 0)
    key_type, = struct.unpack_from('<I', d, 0x08)
    hdr, meta = struct.unpack_from('<HH', d, 0x0C)
    fsz, = struct.unpack_from('<Q', d, 0x10)
    nent, flags = struct.unpack_from('<HH', d, 0x18)
    print(f'{os.path.basename(f):<28} {magic:#010x} {ver:>3} {mode:>4} {hdr:#7x} '
          f'{meta:#7x} {hdr+meta:#8x} {fsz:>10} {nent:>4} {key_type:#7x} {attr:#7x}')
