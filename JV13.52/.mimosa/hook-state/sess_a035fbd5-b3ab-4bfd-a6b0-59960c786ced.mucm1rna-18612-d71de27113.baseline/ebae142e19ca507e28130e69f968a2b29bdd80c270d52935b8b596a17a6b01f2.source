"""GO/NO-GO check 1: does the 14.00 kernel SELF use the same key_revision/keyset
as the 13.52 modules the console will hand us?

If the revision differs, the keys we extract from 80010008 (13.52) cannot decrypt
the 14.00 kernel, and the entire plan is worthless. Cheaper to find out now.

Layout per psdevwiki SELF File Format:
  0x00 magic 4F153D1D | 0x04 unknown 00 01 01 12 | 0x08 program_type
  0x0C header_size (u16) | 0x0E sig_size (u16) | 0x10 file_size (u32)
  0x18 num_segments (u16) | 0x1A unknown (0x22)
  then segments (0x20 each), then ELF hdr + phdrs, then Program Identification
  Header, then Segment Certification, then metadata.
"""
import struct

FILES = [
    (r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\80010008.self', '80010008 AuthMgr 13.52'),
    (r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\80010002.self', '80010002 Kernel  13.52'),
    (r'C:\Users\Kinan\Downloads\JV13.52\dec\80010002_kernel_14.00.self', '80010002 Kernel  14.00'),
]


def hdr(d):
    magic, = struct.unpack_from('<I', d, 0)
    h = {}
    h['magic'] = magic
    h['unknown04'] = d[4:8].hex()
    h['program_type'], = struct.unpack_from('<I', d, 8)
    h['header_size'], h['sig_size'] = struct.unpack_from('<HH', d, 0x0C)
    h['file_size'], = struct.unpack_from('<I', d, 0x10)
    h['num_segments'], h['unknown1a'] = struct.unpack_from('<HH', d, 0x18)
    return h


data = {}
for path, name in FILES:
    try:
        d = open(path, 'rb').read()
    except Exception as e:
        print(f"{name}: cannot read ({e})")
        continue
    data[name] = d
    h = hdr(d)
    print(f"=== {name}  ({len(d):,} B) ===")
    print(f"    magic=0x{h['magic']:08x} unknown@4={h['unknown04']} "
          f"program_type=0x{h['program_type']:x}")
    print(f"    header_size=0x{h['header_size']:x} sig_size=0x{h['sig_size']:x} "
          f"file_size={h['file_size']:,} num_segments={h['num_segments']} "
          f"unknown@1a=0x{h['unknown1a']:x}")
    print("    first 0x60 of metadata region (header_size offset):")
    mo = h['header_size']
    print(f"      @0x{mo:x}: {d[mo:mo+0x40].hex(' ')}")
    print()

print("=== segment tables ===")
for name, d in data.items():
    h = hdr(d)
    print(f"--- {name} ---")
    for i in range(h['num_segments']):
        o = 0x20 + i * 0x20
        flags, off, csz, dsz = struct.unpack_from('<QQQQ', d, o)
        print(f"    [{i}] flags=0x{flags:016x} off=0x{off:x} "
              f"enc_comp_size=0x{csz:x} dec_size=0x{dsz:x}")

print("\n=== byte-level: do the 13.52 and 14.00 SELFs share a revision marker? ===")
a = data.get('80010002 Kernel  13.52')
b = data.get('80010002 Kernel  14.00')
c = data.get('80010008 AuthMgr 13.52')
if a and b:
    n = min(len(a), len(b))
    # compare the headers + first 0x400 (metadata/cert area)
    for label, span in [('header 0x00-0x20', (0, 0x20)),
                        ('cert/meta 0x20-0x400', (0x20, 0x400))]:
        diffs = [i for i in range(span[0], min(span[1], n)) if a[i] != b[i]]
        print(f"  {label}: {len(diffs)} differing bytes")
        if diffs and len(diffs) < 40:
            for i in diffs:
                print(f"      0x{i:04x}: 13.52={a[i]:02x}  14.00={b[i]:02x}")
if c:
    print(f"  (80010008 AuthMgr 13.52 header program_type="
          f"0x{hdr(c)['program_type']:x}, num_segments={hdr(c)['num_segments']})")
