import struct, sys, hashlib, os

def rd(p):
    with open(p, 'rb') as f:
        return f.read()

# ---------- 1. SELF parse of console libc.sprx -> firmware version ----------
def parse_self(path):
    b = rd(path)
    print("== SELF:", os.path.basename(path), "size", len(b))
    magic = struct.unpack_from('<I', b, 0)[0]
    print("  magic @0 : 0x%08X  (expect 0x1D3D154F)" % magic)
    if magic != 0x1D3D154F:
        print("  NOT a SELF by magic; first16:", b[:16].hex())
        return
    version, mode, endian, attr = b[4], b[5], b[6], b[7]
    content_type, program_type = b[8], b[9]
    header_size, sig_size = struct.unpack_from('<HH', b, 0x0C)
    self_size, = struct.unpack_from('<Q', b, 0x10)
    num_seg, flags = struct.unpack_from('<HH', b, 0x18)
    print("  version=%d mode=%d endian=%d attr=%d" % (version, mode, endian, attr))
    print("  content_type=0x%X program_type=0x%X" % (content_type, program_type))
    print("  header_size=0x%X signature_size=0x%X self_size=%d" % (header_size, sig_size, self_size))
    print("  num_of_segments=%d flags=0x%X" % (num_seg, flags))

    elf_off = 0x20 + num_seg * 0x20
    print("  elf_header_offset = 0x%X" % elf_off)
    e_ident = b[elf_off:elf_off+4]
    print("  bytes@elf_off:", e_ident.hex(), "(ELF magic 7f454c46 expected)")
    if e_ident != b'\x7fELF':
        print("  !! not ELF at computed offset")
        return
    e_ehsize, e_phentsize, e_phnum = struct.unpack_from('<HHH', b, elf_off + 0x34)
    print("  e_ehsize=0x%X e_phentsize=0x%X e_phnum=%d" % (e_ehsize, e_phentsize, e_phnum))
    sce_off = elf_off + e_ehsize + e_phnum * e_phentsize
    while sce_off % 0x10:
        sce_off += 1
    print("  sce_header_offset = 0x%X" % sce_off)
    pai, ptype, appver, fwver = struct.unpack_from('<QQQQ', b, sce_off)
    print("  program_authority_id = 0x%016X" % pai)
    print("  program_type         = 0x%016X" % ptype)
    print("  app_version          = 0x%016X" % appver)
    print("  fw_version           = 0x%016X   bytes=%s" % (fwver, fwver.to_bytes(8, 'big').hex()))
    b6 = (fwver >> 32) & 0xFF
    b7 = (fwver >> 40) & 0xFF
    print("  >> SDK decoded pair: %%02lx(0x40-47)=0x%02X  %%02lx(0x32-39)=0x%02X" % (b7, b6))
    print("  >> SDK firmware string  = '%02x%02x'" % (b6, b7))
    print("  >> alt (reversed)       = '%02x%02x'" % (b7, b6))
    print("  >> human: %d.%02d  (or %d.%02d reversed)" % (b7, b6, b6, b7))

# ---------- 2. PUP (SLB2 container) parse ----------
def parse_pup(path):
    b = rd(path)
    print("\n== PUP:", os.path.basename(path), "size", len(b))
    print("  sha256:", hashlib.sha256(b).hexdigest())
    print("  first 0x40 bytes:", b[:0x40].hex())
    magic = b[:4]
    print("  first4:", magic, "(SLB2 = 53 4C 42 32)")
    if magic != b'SLB2':
        print("  !! not SLB2"); return
    ver, flags, file_count = struct.unpack_from('<III', b, 4)
    block_size, unk = struct.unpack_from('<II', b, 0x10)
    print("  version=%d flags=0x%X file_count=%d block_size=%d unk=0x%X" % (ver, flags, file_count, block_size, unk))
    base = 0x20
    stride = 0x30
    total = 0
    for i in range(file_count):
        o = base + i * stride
        etype, esize = struct.unpack_from('<II', b, o)
        name = b[o+0x10:o+0x30].split(b'\x00')[0].decode('ascii', 'replace')
        print("  entry[%d] type=%d size=%d name=%r  (offset field 0x%X)" % (i, etype, esize, name, struct.unpack_from('<I', b, o+8)[0]))
        total += esize
    print("  sum(entry sizes)=%d  vs file size=%d" % (total, len(b)))
    # locate PUP fragment magics
    m = b'\x4f\x15\x3d\x1d'
    offs = []
    start = 0
    while True:
        i = b.find(m, start)
        if i < 0: break
        offs.append(i)
        start = i + 1
    print("  PUP magic (4F153D1D) occurrences:", [hex(x) for x in offs[:10]])
    for i in offs[:4]:
        if i + 0x20 <= len(b):
            mg, ver2, u1, u2, fl, hs, ms = struct.unpack_from('>IHHHHHH', b, i)
            print("    frag@0x%X: magic=0x%08X version(BE)=%d u1=%d u2=%d flags=0x%X header_size=0x%X metadata_size=0x%X" % (i, mg, ver2, u1, u2, fl, hs, ms))

parse_self(r'C:\Users\Kinan\Downloads\JV13.52\libc.sprx')
parse_pup(r'C:\Users\Kinan\Downloads\JV13.52\PS4UPDATE.PUP')
