import struct

BLOB = open(r'C:\Users\Kinan\Downloads\JV13.52\probe\dev_dev_sflash0s1.cryptx3.bin','rb').read()

PROG = {0x0:'PUP',0x8:'NPDRM Application',0x9:'PLUGIN',0xC:'Kernel',0xE:'Security Module',0xF:'Secure Kernel'}

def dump_self(tag, off, limit=0x7C00):
    b = BLOB
    magic = struct.unpack_from('<I', b, off)[0]
    if magic != 0x1D3D154F:
        print("%s @0x%X : magic=0x%08X (not SELF)" % (tag, off, magic)); return
    content_type, program_type = b[off+8], b[off+9]
    header_size, sig_size = struct.unpack_from('<HH', b, off+0x0C)
    self_size, = struct.unpack_from('<Q', b, off+0x10)
    num_seg, flags = struct.unpack_from('<HH', b, off+0x18)
    print("%s @0x%X : program_type=0x%02X (%s) header_size=0x%X sig_size=0x%X self_size=%d segs=%d flags=0x%X"
          % (tag, off, program_type, PROG.get(program_type,'?'), header_size, sig_size, self_size, num_seg, flags))
    for i in range(num_seg):
        eo = off + 0x20 + i*0x20
        props, _res, eoff, fsz, msz = struct.unpack_from('<IIQQQ', b, eo)
        enc = bool(props & 2); comp = bool(props & 8)
        print("    seg[%d] props=0x%06X enc=%d comp=%d offset=0x%-8X filesz=%-9d memsz=%-9d"
              % (i, props, enc, comp, eoff, fsz, msz))
        seg = off + eoff
        avail = seg + 8 <= min(len(b), off + limit)
        if avail:
            m = b[seg:seg+8]
            kind = "ELF(magic 7f454c46)" if m[:4]==b'\x7fELF' else "not-ELF"
            print("             -> segment data first8 = %s  %s" % (m.hex(' '), kind))
        else:
            print("             -> segment data beyond grabbed range (need file offset 0x%X)" % seg)

dump_self("80010001 SecureKernel", 0x200)
dump_self("80010002 Kernel",       0x18400)
