import struct, glob, os, hashlib

DEC = r'C:\Users\Kinan\Downloads\JV13.52\dec'
KSELF = os.path.join(DEC, '80010002_kernel_14.00.self')

def self_report(path, label):
    b = open(path, 'rb').read()
    print("=== %s ===" % label)
    print("   file:", os.path.basename(path), format(len(b), ','), "bytes")
    print("   sha256:", hashlib.sha256(b).hexdigest())
    ct, pt = b[8], b[9]
    hs, sigs = struct.unpack_from('<HH', b, 0x0C)
    sz, = struct.unpack_from('<Q', b, 0x10)
    ns, fl = struct.unpack_from('<HH', b, 0x18)
    print("   SELF magic ok: %s   content_type=0x%02X program_type=0x%02X" % (b[:4].hex(' ') == '4f153d1d', ct, pt))
    print("   header_size=0x%X signature_size=0x%X self_size=%s num_segments=%d flags=0x%X" %
          (hs, sigs, format(sz, ','), ns, fl))
    elf = 0x20 + ns*0x20
    if b[elf:elf+4] == b'\x7fELF':
        eh, ph, pn = struct.unpack_from('<HHH', b, elf+0x34)
        sce = elf + eh + pn*ph
        while sce % 0x10: sce += 1
        pai, ptype, appver, fwv = struct.unpack_from('<QQQQ', b, sce)
        print("   SceHeader: authority_id=0x%016X program_type=0x%016X app_version=0x%016X" % (pai, ptype, appver))
        print("   SceHeader: fw_version=0x%016X  ->  '%02x%02x'" % (fwv, (fwv>>40)&0xFF, (fwv>>32)&0xFF))
    print("   segment entries:")
    for j in range(ns):
        pr, _r, eoff, fsz, msz = struct.unpack_from('<IIQQQ', b, 0x20 + j*0x20)
        data = b[eoff:eoff+8]
        kind = 'ELF(decrypted!)' if data[:4] == b'\x7fELF' else 'encrypted/compressed'
        print("      seg[%d] props=0x%06X signed=%d encrypted=%d compressed=%d offset=0x%-9X filesz=%-11s memsz=%-11s %s %s" %
              (j, pr, (pr>>2)&1, (pr>>1)&1, (pr>>3)&1, eoff, format(fsz,','), format(msz,','), data.hex(' '), kind))
    print()

self_report(KSELF, "14.00 KERNEL (80010002) extracted from decrypted PUP")
am = glob.glob(os.path.join(DEC, '**', '80010008*'), recursive=True)
print()

# secure loader revision nonce comparison: console 13.52 vs PUP 14.00
print("=== Secure Loader (80000001) revision nonce: 13.52 console vs 14.00 PUP ===")
consol = glob.glob(r'C:\Users\Kinan\Downloads\JV13.52\probe\*cryptx2b*.bin')
pup_sl = glob.glob(os.path.join(DEC, '**', 'sflash0s1.cryptx2b'), recursive=True)
def nonce(path):
    b = open(path, 'rb').read()
    i = b.find(b'\x5e\xd7\x9a\x0b')
    if i < 0:
        return None
    return b[i:i+0x140]
for c in consol:
    b = open(c,'rb').read()
    i = b.find(b'\x5e\xd7\x9a\x0b')
    if i >= 0:
        print("   console (13.52): magic@0x%X  nonce@0x120 = %s" % (i, b[i+0x120:i+0x140].hex()))
for p in pup_sl:
    b = open(p,'rb').read()
    i = b.find(b'\x5e\xd7\x9a\x0b')
    if i >= 0:
        print("   PUP (14.00)   : magic@0x%X  nonce@0x120 = %s" % (i, b[i+0x120:i+0x140].hex()))

print()
print("=== magic of other unpacked artifacts ===")
for n in ['system_fs_image.img', 'eap_fs_image.img', 'orbis_swu.self', 'dev\\sflash0s1.cryptx2b', 'dev\\sflash0s0x32b']:
    p = os.path.join(DEC, 'unpacked1', n)
    if os.path.exists(p):
        b = open(p, 'rb').read(32)
        print("   %-28s %s  %s" % (n, b[:8].hex(' '), ''.join(chr(c) if 32 <= c < 127 else '.' for c in b[:16])))
