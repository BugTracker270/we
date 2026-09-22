import os, struct, glob

OUT = r'C:\Users\Kinan\Downloads\JV13.52\dec\unpacked1'
print("=== unpacked output ===")
files = []
for root, dirs, fs in os.walk(OUT):
    for f in fs:
        p = os.path.join(root, f)
        files.append((os.path.relpath(p, OUT), os.path.getsize(p)))
files.sort(key=lambda x: -x[1])
for name, size in files[:30]:
    print("   %-46s %s" % (name, format(size, ',')))
print("   total files:", len(files))

# locate secure_modules.bin
cand = [p for p in glob.glob(os.path.join(OUT, '**', 'secure_modules.bin'), recursive=True)]
if not cand:
    cand = [p for n, _ in files for p in [os.path.join(OUT, n)] if 'secure_modules' in n]
print("\n=== secure_modules.bin ===")
for p in cand:
    b = open(p, 'rb').read()
    print("   path:", os.path.relpath(p, OUT), " size:", format(len(b), ','))
    print("   first16:", b[:16].hex(' '))
    if b[:4] != b'SLB2':
        print("   not SLB2"); continue
    mg, ver, flags, fc, bc = struct.unpack_from('<IIIII', b, 0)
    print("   SLB2 v%d flags=0x%X entries=%d blocks=%d" % (ver, flags, fc, bc))
    PROG = {0xC:'*** KERNEL ***', 0xF:'*** SECURE KERNEL ***', 0xE:'SECURITY MODULE', 0x8:'NPDRM App'}
    print("\n   %-14s %-14s %-16s %-6s %-8s %s" % ("name", "size", "prog_type", "segs", "enc_flags", "fw_version"))
    for k in range(fc):
        eo = 0x20 + k*0x30
        blk, size = struct.unpack_from('<II', b, eo)
        name = b[eo+0x10:eo+0x30].split(b'\x00')[0].decode('ascii','replace')
        off = blk*512
        if b[off:off+4] == b'\x4f\x15\x3d\x1d':
            ct, pt = b[off+8], b[off+9]
            ns, fl = struct.unpack_from('<HH', b, off+0x18)
            sz, = struct.unpack_from('<Q', b, off+0x10)
            enc = comp = 0
            eo2 = off + 0x20
            for j in range(min(ns, 1)):
                pr = struct.unpack_from('<I', b, eo2 + j*0x20)[0]
                enc |= (pr >> 1) & 1
                comp |= (pr >> 3) & 1
            fw = ''
            try:
                elfo = off + 0x20 + ns*0x20
                if b[elfo:elfo+4] == b'\x7fELF':
                    eh, ph, pn = struct.unpack_from('<HHH', b, elfo+0x34)
                    sce = elfo + eh + pn*ph
                    while sce % 0x10: sce += 1
                    _a, _t, _v, fwv = struct.unpack_from('<QQQQ', b, sce)
                    fw = "%02x%02x" % ((fwv>>40)&0xFF, (fwv>>32)&0xFF)
            except Exception:
                pass
            print("   %-14s %-14s 0x%02X %-12s %-6d 0x%-6X %s" %
                  (name, format(size,','), pt, PROG.get(pt,'?'), ns, fl, fw))
        else:
            print("   %-14s %-14s %s" % (name, format(size,','), b[off:off+4].hex(' ')))
    # extract the kernel
    for k in range(fc):
        eo = 0x20 + k*0x30
        blk, size = struct.unpack_from('<II', b, eo)
        name = b[eo+0x10:eo+0x30].split(b'\x00')[0].decode('ascii','replace')
        off = blk*512
        if name == '80010002' or (b[off:off+4] == b'\x4f\x15\x3d\x1d' and b[off+9] == 0xC):
            out = r'C:\Users\Kinan\Downloads\JV13.52\dec\80010002_kernel_14.00.self'
            open(out, 'wb').write(b[off:off+size])
            print("\n   >>> EXTRACTED KERNEL SELF ->", out, "(%s bytes)" % format(size, ','))
