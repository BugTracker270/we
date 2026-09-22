"""Inspect the two interesting things the arena dump turned up.

  (a) what the 8001000B record actually points at: 0xffffc18716072780
  (b) the SELF image at 0xffffc187160e4200 (only SELF magic in the window)

If (b) is a decrypted module image, its segment data is plaintext and is the
place to look for key banks. If its program_type identifies it as something
other than the AuthMgr, that tells us which module the SBL keeps resident.
"""
import struct

DUMP = r'C:\Users\Kinan\Downloads\JV13.52\v12_kmem_img.bin'
BASE = 0xffffc18716000000
d = open(DUMP, 'rb').read()

OFF_1 = 0xffffc18716072780
OFF_2 = 0xffffc187160e4200


def show(va, span=0x60):
    fo = va - BASE
    print(f"--- 0x{va:x} (file 0x{fo:x}) ---")
    for i in range(0, span, 16):
        row = d[fo + i:fo + i + 16]
        hx = ' '.join(f'{b:02x}' for b in row)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
        print(f"  0x{va+i:016x}  {hx}  {asc}")
    print()


print("=== (a) target of the 8001000B record pointer ===")
show(OFF_1, 0x40)

print("=== (b) the SELF image ===")
show(OFF_2, 0x80)

fo = OFF_2 - BASE
magic, = struct.unpack_from('<I', d, fo)
version, mode, endian, attr = d[fo + 4], d[fo + 5], d[fo + 6], d[fo + 7]
key_type, = struct.unpack_from('<I', d, fo + 8)
hdr_size, meta_size = struct.unpack_from('<HH', d, fo + 0x0c)
file_size, = struct.unpack_from('<Q', d, fo + 0x10)
num_entries, flags = struct.unpack_from('<HH', d, fo + 0x18)

print("SELF header:")
print(f"  magic       0x{magic:08x}   (expect 0x1d3d154f)")
print(f"  version     {version}  mode {mode}  endian {endian}  attr {attr}")
print(f"  key_type    0x{key_type:x}")
print(f"  hdr_size    0x{hdr_size:x}  meta_size 0x{meta_size:x}")
print(f"  file_size   {file_size:,}  num_entries {num_entries}  flags {flags}")

print("\n  entries (props, offset, filesz, memsz):")
for i in range(min(num_entries, 12)):
    eo = fo + 0x20 + i * 0x20
    props, off, fsz, msz = struct.unpack_from('<QQQQ', d, eo)
    enc = (props >> 1) & 1
    comp = (props >> 3) & 1
    print(f"    [{i}] props=0x{props:016x} off=0x{off:x} filesz=0x{fsz:x} "
          f"memsz=0x{msz:x}  enc={enc} comp={comp}")

# is the segment body plaintext?
if num_entries:
    props, off, fsz, msz = struct.unpack_from('<QQQQ', d, fo + 0x20)
    body = fo + off
    if 0 <= body < len(d) - 16:
        print(f"\n  segment[0] body at va 0x{BASE+body:x} (file 0x{body:x}):")
        print(f"    first16: {d[body:body+16].hex(' ')}")
        print(f"    looks like ELF? {d[body:body+4] == b'\x7fELF'}")
