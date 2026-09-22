import struct, os

def bls(p, label):
    b = open(p, 'rb').read()
    print("=== %s ===" % label)
    print("   %s  %s bytes  first4=%r" % (os.path.basename(p), format(len(b), ','), b[:4]))
    mg, ver, flags, fc, bc = struct.unpack_from('<IIIII', b, 0)
    print("   SLB2 v%d entries=%d blocks=%d" % (ver, fc, bc))
    out = {}
    for i in range(fc):
        eo = 0x20 + i*0x30
        blk, size = struct.unpack_from('<II', b, eo)
        name = b[eo+0x10:eo+0x30].split(b'\x00')[0].decode('ascii', 'replace')
        out[name] = (blk*512, size)
        print("      %-12s %12s" % (name, format(size, ',')))
    return b, out

cb, co = bls(r'C:\Users\Kinan\Downloads\JV13.52\probe\coreos_full.bin', "console coreos  (13.52)")
pb, po = bls(r'C:\Users\Kinan\Downloads\JV13.52\dec\unpacked1\secure_modules.bin', "PUP secure_modules.bin  (14.00)")

print("\n=== module size comparison ===")
for k in sorted(set(co) | set(po)):
    a = co.get(k, (0,0))[1]
    c = po.get(k, (0,0))[1]
    print("   %-12s 13.52=%-12s 14.00=%-12s %s" % (k, format(a,','), format(c,','),
          'same' if a == c else 'DIFFERENT'))

outdir = r'C:\Users\Kinan\Downloads\JV13.52\dec\1352'
os.makedirs(outdir, exist_ok=True)
for k, (o, s) in co.items():
    with open(os.path.join(outdir, k + '.self'), 'wb') as f:
        f.write(cb[o:o+s])
print("\nextracted 13.52 modules ->", outdir)
for f in sorted(os.listdir(outdir)):
    fp = os.path.join(outdir, f)
    h = open(fp,'rb').read(16)
    print("   %-20s %12s  %s" % (f, format(os.path.getsize(fp), ','), h.hex(' ')))
