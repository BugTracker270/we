import struct, os

A = r'C:\Users\Kinan\Downloads\JV13.52\probe\dev_dev_sflash0s1.cryptx3.bin'   # cryptx3
B = r'C:\Users\Kinan\Downloads\JV13.52\probe\t_dev_sflash0s1.cryptx3b.bin'    # cryptx3b

def table(path, label):
    b = open(path,'rb').read()
    print("== %s  (%d bytes)" % (label, len(b)))
    ver, flags, fc = struct.unpack_from('<III', b, 4)
    print("   SLB2 v%d flags=0x%X file_count=%d" % (ver, flags, fc))
    ent = []
    for i in range(fc):
        o = 0x20 + i*0x30
        blk, size = struct.unpack_from('<II', b, o)
        name = b[o+0x10:o+0x30].split(b'\x00')[0].decode('ascii','replace')
        ent.append((name, blk*512, size))
        print("   [%d] %-12s size=%-9d data@0x%-8X" % (i, name, size, blk*512))
    return b, ent

a, ea = table(A, "cryptx3")
b, eb = table(B, "cryptx3b")
print()
print("tables identical:", [(n,o,s) for n,o,s in ea] == [(n,o,s) for n,o,s in eb])
print()
print("%-12s %-28s %-28s %s" % ("entry","cryptx3 first16","cryptx3b first16","verdict"))
for (n,o,s), (n2,o2,s2) in zip(ea, eb):
    fa = a[o:o+16].hex(' ') if o+16 <= len(a) else "(beyond)"
    fb = b[o2:o2+16].hex(' ') if o2+16 <= len(b) else "(beyond)"
    if fb.startswith("7f 45 4c 46"): v = "x3b = PLAINTEXT ELF"
    elif fb.startswith("4f 15 3d 1d"): v = "x3b = SELF header (still wrapped)"
    elif fa == fb: v = "IDENTICAL to x3"
    else: v = "DIFFERENT"
    print("%-12s %-28s %-28s %s" % (n, fa, fb, v))
