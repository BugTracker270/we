import hashlib, struct

def mods(p):
    b = open(p, 'rb').read()
    fc = struct.unpack_from('<I', b, 0x0C)[0]
    o = {}
    for i in range(fc):
        eo = 0x20 + i*0x30
        blk, size = struct.unpack_from('<II', b, eo)
        n = b[eo+0x10:eo+0x30].split(b'\x00')[0].decode('ascii', 'replace')
        o[n] = b[blk*512:blk*512+size]
    return o

a = mods(r'C:\Users\Kinan\Downloads\JV13.52\probe\coreos_full.bin')                    # 13.52 console
b = mods(r'C:\Users\Kinan\Downloads\JV13.52\dec\unpacked1\secure_modules.bin')         # 14.00 PUP

ROLE = {'80010001':'Secure Kernel','80010002':'KERNEL','80010006':'sec module',
        '80010008':'AuthMgr (SELF keys!)','80010009':'sec module','8001000A':'sec module',
        '8001000B':'sec module'}

print("%-11s %-26s %-11s %-11s %s" % ("module","role","13.52","14.00","verdict"))
same = []
for k in sorted(a):
    ha = hashlib.sha256(a[k]).hexdigest()
    hb = hashlib.sha256(b.get(k, b'')).hexdigest()
    ident = ha == hb
    if ident:
        same.append(k)
    print("%-11s %-26s %-11d %-11d %s" % (k, ROLE.get(k,''), len(a[k]), len(b.get(k,b'')),
                                          "BYTE-IDENTICAL" if ident else "differs"))
print()
print("byte-identical modules between the console's 13.52 coreos and the 14.00 PUP:")
for k in same:
    print("   %s  (%s)" % (k, ROLE.get(k, '')))
print()
print("80010008 (AuthMgr) hashes:")
print("   13.52:", hashlib.sha256(a['80010008']).hexdigest())
print("   14.00:", hashlib.sha256(b['80010008']).hexdigest())
