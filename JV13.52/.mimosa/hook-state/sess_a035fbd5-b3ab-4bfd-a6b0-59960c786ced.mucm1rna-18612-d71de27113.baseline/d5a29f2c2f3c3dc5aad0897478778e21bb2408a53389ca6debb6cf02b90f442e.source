import struct, os, glob

def parse_slb2(path):
    b = open(path, 'rb').read()
    print("== %s   (%d bytes grabbed)" % (os.path.basename(path), len(b)))
    if b[:4] != b'SLB2':
        print("   not SLB2; first16 =", b[:16].hex())
        return
    ver, flags, file_count = struct.unpack_from('<III', b, 4)
    print("   SLB2 version=%d flags=0x%X file_count=%d" % (ver, flags, file_count))
    base, stride = 0x20, 0x30
    end = 0
    for i in range(file_count):
        o = base + i * stride
        blk_off, size = struct.unpack_from('<II', b, o)
        name = b[o+0x10:o+0x30].split(b'\x00')[0].decode('ascii', 'replace')
        data_off = blk_off * 512
        end = max(end, data_off + size)
        print("   [%d] name=%-28r size=%-10d data@0x%-8X (§%d)" % (i, name, size, data_off, blk_off))
        # magic of the entry payload if we grabbed it
        if data_off + 16 <= len(b):
            m = b[data_off:data_off+16]
            kind = "ELF" if m[:4] == b'\x7fELF' else ("SELF/PUP" if m[:4] == b'\x4f\x15\x3d\x1d' else ("SLB2" if m[:4] == b'SLB2' else "??"))
            print("        first16 = %s   => %s" % (m.hex(' '), kind))
        else:
            print("        (payload beyond grabbed range)")
    print("   container total size (from table) = %d bytes (%.1f MB)" % (end, end/1048576))

for f in sorted(glob.glob(r'C:\Users\Kinan\Downloads\JV13.52\probe\dev_*.bin')):
    parse_slb2(f)
    print()
