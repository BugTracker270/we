import struct, os

P = r'C:\Users\Kinan\Downloads\JV13.52\dec\PS4UPDATE1.PUP.dec'
b = open(P, 'rb').read()
print("scanning", os.path.basename(P), format(len(b), ','), "bytes")

PROG = {0x0:'PUP', 0x8:'NPDRM App', 0x9:'PLUGIN', 0xC:'*** KERNEL ***',
        0xE:'SECURITY MODULE', 0xF:'*** SECURE KERNEL ***'}
SIG = b'\x4f\x15\x3d\x1d\x00\x01\x01\x12'

hits = []
start = 0
while True:
    i = b.find(SIG, start)
    if i < 0:
        break
    start = i + 1
    pt = b[i+9]
    hits.append((i, pt))

print("total SELF-signature occurrences:", len(hits))
print()
print("%-12s %-10s %-22s %-16s %-6s %s" % ("offset", "prog", "kind", "self_size", "segs", "fw_version"))
interesting = []
for i, pt in hits:
    ns, fl = struct.unpack_from('<HH', b, i+0x18)
    sz, = struct.unpack_from('<Q', b, i+0x10)
    hs = struct.unpack_from('<H', b, i+0x0C)[0]
    fw = ''
    fwv = None
    try:
        eo = i + 0x20 + ns*0x20
        if b[eo:eo+4] == b'\x7fELF':
            eh, ph, pn = struct.unpack_from('<HHH', b, eo+0x34)
            sce = eo + eh + pn*ph
            while sce % 0x10: sce += 1
            _pai, _pt2, _av, fwv = struct.unpack_from('<QQQQ', b, sce)
            fw = "%02x%02x" % ((fwv >> 40) & 0xFF, (fwv >> 32) & 0xFF)
    except Exception:
        pass
    if pt in (0xC, 0xF, 0xE, 0x8) or (fw not in ('', '0000')):
        print("%-12s 0x%02X      %-22s %-16s %-6d %s" %
              ("0x%X" % i, pt, PROG.get(pt, '?'), format(sz, ','), ns, fw))
    if pt in (0xC, 0xF, 0xE):
        interesting.append((i, pt, sz, bw := None))

print()
print("== STRUCTURALLY INTERESTING (kernel / secure kernel / security module) ==")
for i, pt, sz, _ in interesting:
    print("   0x%-10X prog=0x%02X %-20s size=%s" % (i, pt, PROG.get(pt), format(sz, ',')))

print()
print("== every SLB2 container in the file ==")
start = 0
n = 0
while True:
    i = b.find(b'SLB2', start)
    if i < 0:
        break
    start = i + 1
    try:
        mg, ver, flags, fc, bc = struct.unpack_from('<IIIII', b, i)
        if ver > 4 or fc > 64 or bc > 0x100000:
            continue
        names = []
        for k in range(fc):
            eo = i + 0x20 + k*0x30
            name = b[eo+0x10:eo+0x30].split(b'\x00')[0].decode('ascii','replace')
            blk, size = struct.unpack_from('<II', b, eo)
            names.append("%s(%s)" % (name, format(size, ',')))
        n += 1
        print("   0x%-10X v%d entries=%d blocks=%d  %s" % (i, ver, fc, bc, ' '.join(names[:12])))
    except Exception:
        pass
print("   total SLB2 containers:", n)
