import struct, os

P = r'C:\Users\Kinan\Downloads\JV13.52\dec\PS4UPDATE1.PUP.dec'
COREOS = r'C:\Users\Kinan\Downloads\JV13.52\probe\dev_dev_sflash0s1.cryptx3.bin'
b = open(P, 'rb').read()
seg_count = struct.unpack_from('<H', b, 0x18)[0]

# ---------- 1. validate the fw_version decoder against the console's own 13.52 kernel SELF ----------
print("=== decoder validation: console's own kernel SELF (80010002, known 13.52) ===")
c = open(COREOS, 'rb').read()
off = 0x18400
ct, pt = c[off+8], c[off+9]
hs, sg = struct.unpack_from('<HH', c, off+0x0C)
sz, = struct.unpack_from('<Q', c, off+0x10)
ns, fl = struct.unpack_from('<HH', c, off+0x18)
eo = off + 0x20 + ns*0x20
eh, ph, pn = struct.unpack_from('<HHH', c, eo+0x34)
sce = eo + eh + pn*ph
while sce % 0x10: sce += 1
pai, ptype, appver, fwver = struct.unpack_from('<QQQQ', c, sce)
print("   prog_type=0x%02X  fw_version=0x%016X" % (pt, fwver))
print("   decoded as %%02x(>>40)%%02x(>>32) -> '%02x%02x'" % ((fwver>>40)&0xFF, (fwver>>32)&0xFF))
print("   decoded swapped                    -> '%02x%02x'" % ((fwver>>32)&0xFF, (fwver>>40)&0xFF))

# SELF inside the decrypted PUP with fw info
print("\n=== fw_version of the SELF found inside the decrypted 14.00 PUP (idx 4) ===")
off2 = 0x20 + 4*0x20
soff = struct.unpack_from('<Q', b, off2+8)[0]
hs2 = struct.unpack_from('<H', b, soff+0x0C)[0]
ns2 = struct.unpack_from('<H', b, soff+0x18)[0]
eo2 = soff + 0x20 + ns2*0x20
eh2, ph2, pn2 = struct.unpack_from('<HHH', b, eo2+0x34)
sce2 = eo2 + eh2 + pn2*ph2
while sce2 % 0x10: sce2 += 1
pai2, ptype2, appver2, fwver2 = struct.unpack_from('<QQQQ', b, sce2)
print("   fw_version=0x%016X -> '%02x%02x' / swapped '%02x%02x'" %
      (fwver2, (fwver2>>40)&0xFF, (fwver2>>32)&0xFF, (fwver2>>32)&0xFF, (fwver2>>40)&0xFF))

# ---------- 2. parse every SLB2 container found in the PUP ----------
def parse_bls(off, limit=0x400):
    if b[off:off+4] != b'SLB2':
        return None
    mg, ver, flags, fc, bc = struct.unpack_from('<IIIII', b, off)
    entries = []
    for i in range(fc):
        eo = off + 0x20 + i*0x30
        blk, size = struct.unpack_from('<II', b, eo)
        name = b[eo+0x10:eo+0x30].split(b'\x00')[0].decode('ascii','replace')
        entries.append((name, blk*512, size))
    return ver, fc, bc, entries

print("\n=== SLB2 containers inside the decrypted PUP ===")
for i in range(seg_count):
    o = 0x20 + i*0x20
    soff, csize, usize = struct.unpack_from('<QQQ', b, o+8)
    r = parse_bls(soff)
    if not r:
        continue
    ver, fc, bc, entries = r
    print("\n   --- segment idx %d @0x%X  SLB2 v%d  entries=%d  blocks=%d" % (i, soff, ver, fc, bc))
    for name, doff, size in entries[:40]:
        kind = ''
        if b[soff+doff:soff+doff+4] == b'\x4f\x15\x3d\x1d':
            pp = b[soff+doff+9]
            kind = 'SELF prog=0x%02X %s' % (pp, {0xC:'KERNEL',0xF:'SECURE KERNEL',0xE:'SECURITY MODULE',0x8:'NPDRM APP'}.get(pp,''))
        elif b[soff+doff:soff+doff+4] == b'SLB2':
            kind = 'SLB2 (nested)'
        elif b[soff+doff:soff+doff+4] == b'\x7fELF':
            kind = 'ELF'
        else:
            kind = b[soff+doff:soff+doff+4].hex(' ')
        print("        %-14s size=%-12s @+0x%-9X  %s" % (name, format(size,','), doff, kind))
