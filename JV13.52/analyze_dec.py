import struct, os, datetime, hashlib

P = r'C:\Users\Kinan\Downloads\JV13.52\dec\PS4UPDATE1.PUP.dec'
b = open(P, 'rb').read()
print("file:", os.path.basename(P), format(len(b), ','))

magic, unk04, unk08, pflags, unk0b, unk0c, unk0e = struct.unpack_from('<IIHBBHH', b, 0)
file_size, seg_count, unk1a, unk1c = struct.unpack_from('<QHHI', b, 0x10)
print("PUP magic 0x%08X  file_size %s  segment_count %d  flags 0x%02X  unk_1A 0x%04X" %
      (magic, format(file_size, ','), seg_count, pflags, unk1a))
print()

PROG = {0x0:'PUP', 0x8:'NPDRM App', 0x9:'PLUGIN', 0xC:'*** KERNEL ***',
        0xE:'SECURITY MODULE', 0xF:'*** SECURE KERNEL ***'}

def self_info(off):
    if b[off:off+4] != b'\x4f\x15\x3d\x1d':
        return None
    ct, pt = b[off+8], b[off+9]
    hs, ss = struct.unpack_from('<HH', b, off+0x0C)
    sz, = struct.unpack_from('<Q', b, off+0x10)
    ns, fl = struct.unpack_from('<HH', b, off+0x18)
    fw = None
    try:
        eo = off + 0x20 + ns*0x20
        if b[eo:eo+4] == b'\x7fELF':
            eh, ph, pn = struct.unpack_from('<HHH', b, eo+0x34)
            sce = eo + eh + pn*ph
            while sce % 0x10:
                sce += 1
            pai, ptype, appver, fwver = struct.unpack_from('<QQQQ', b, sce)
            fw = "%02x%02x" % ((fwver >> 32) & 0xFF, (fwver >> 40) & 0xFF)
            fw_hex = fwver
        else:
            fw_hex = None
    except Exception:
        fw_hex = None
    return dict(ct=ct, pt=pt, hs=hs, sig=ss, size=sz, ns=ns, flags=fl, fw=fw, fw_hex=fw_hex)

print("%-4s %-12s %-16s %-6s %-6s %-20s %-10s %-6s %s" %
      ("idx","offset","compressed","magic","prog","name","self_size","segs","fw_version"))
rows = []
for i in range(seg_count):
    o = 0x20 + i*0x20
    sflags, _p = struct.unpack_from('<II', b, o)
    soff, csize, usize = struct.unpack_from('<QQQ', b, o+8)
    head = b[soff:soff+4]
    if head == b'\x4f\x15\x3d\x1d':
        m = 'SELF'; si = self_info(soff)
    elif head == b'SLB2':
        m = 'SLB2'; si = None
    elif head == b'\x7fELF':
        m = 'ELF'; si = None
    else:
        m = head.hex(' '); si = None
    if si:
        print("%-4d 0x%-10X %-16s %-6s 0x%02X   %-20s %-10s %-6d %s" %
              (i, soff, format(csize,','), m, si['pt'], PROG.get(si['pt'],'?'),
               format(si['size'],','), si['ns'], si['fw'] or ''))
    else:
        print("%-4d 0x%-10X %-16s %-6s" % (i, soff, format(csize,','), m))
    rows.append((i, soff, csize, usize, m, si, sflags))

print()
for i, soff, csize, usize, m, si, sflags in rows:
    if si and si['pt'] in (0xC, 0xF, 0xE):
        print(">> candidate idx %d: prog=0x%02X (%s) self_size=%s fw=%s @0x%X" %
              (i, si['pt'], PROG.get(si['pt']), format(si['size'],','), si['fw'], soff))
        # segment encryption flags for the SELF body
        eo = soff + 0x20
        for k in range(min(si['ns'], 4)):
            pr, _r, eoff, fsz, msz = struct.unpack_from('<IIQQQ', b, soff+0x20+k*0x20)
            print("     seg[%d] props=0x%06X enc=%d comp=%d offset=0x%X filesz=%s memsz=%s  data=%s" %
                  (k, pr, bool(pr & 2), bool(pr & 8), eoff, format(fsz,','), format(msz,','),
                   b[soff+eoff:soff+eoff+8].hex(' ')))
