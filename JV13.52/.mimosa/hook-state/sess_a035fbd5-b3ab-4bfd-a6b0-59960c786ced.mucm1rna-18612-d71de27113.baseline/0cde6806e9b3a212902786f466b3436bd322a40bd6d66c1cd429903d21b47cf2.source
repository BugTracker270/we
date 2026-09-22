import struct, datetime
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121
PATH = '/mnt/usb0/PS4UPDATE1.PUP.dec'

PROG = {0x0:'PUP', 0x8:'NPDRM App', 0x9:'PLUGIN', 0xC:'** KERNEL **',
        0xE:'SECURITY MODULE', 0xF:'** SECURE KERNEL **'}

def rd(off, n):
    f = FTP(); f.connect(HOST, PORT, timeout=15); f.login('anonymous','anonymous')
    sock = f.transfercmd('RETR ' + PATH, rest=off)
    buf = b''
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c: break
        buf += c
    try: sock.close()
    except Exception: pass
    try: f.voidresp()
    except Exception: pass
    f.quit()
    return buf

hdr = rd(0, 0x20 + 40*0x20)
seg_count = struct.unpack_from('<H', hdr, 0x18)[0]

print("segment SELF-header survey of PS4UPDATE1.PUP.dec  @", datetime.datetime.now().strftime('%H:%M:%S'))
print()
print("%-4s %-14s %-18s %-16s %-8s %-9s %s" % ("idx","offset","self_size","prog_type","segs","self_flags","fw_version"))
targets = []
for i in range(seg_count):
    o = 0x20 + i*0x20
    soff, csize, usize = struct.unpack_from('<QQQ', hdr, o+8)
    try:
        b = rd(soff, 0x2000)
    except Exception as e:
        print("%-4d 0x%-12X read fail %s" % (i, soff, type(e).__name__)); continue
    if b[:4] != b'\x4f\x15\x3d\x1d':
        print("%-4d 0x%-12X not a SELF (%s)" % (i, soff, b[:8].hex(' '))); continue
    content_type, program_type = b[8], b[9]
    header_size, sig_size = struct.unpack_from('<HH', b, 0x0C)
    self_size, = struct.unpack_from('<Q', b, 0x10)
    num_seg, self_flags = struct.unpack_from('<HH', b, 0x18)
    fw = ''
    try:
        elf_off = 0x20 + num_seg * 0x20
        if b[elf_off:elf_off+4] == b'\x7fELF':
            e_ehsize, e_phentsize, e_phnum = struct.unpack_from('<HHH', b, elf_off + 0x34)
            sce = elf_off + e_ehsize + e_phnum * e_phentsize
            while sce % 0x10:
                sce += 1
            pai, ptype, appver, fwver = struct.unpack_from('<QQQQ', b, sce)
            b6, b7 = (fwver >> 32) & 0xFF, (fwver >> 40) & 0xFF
            fw = "%02x%02x (0x%016X)" % (b6, b7, fwver)
            if program_type in (0xC, 0xF):
                fw += "   <-- system software version"
        else:
            fw = "(no ELF at 0x%X)" % elf_off
    except Exception as e:
        fw = "parse err " + type(e).__name__
    print("%-4d 0x%-12X %-18s 0x%02X %-11s %-8d 0x%-7X %s" %
          (i, soff, format(self_size, ','), program_type, PROG.get(program_type,'?'), num_seg, self_flags, fw))
    if program_type in (0xC, 0xF, 0xE):
        targets.append((i, soff, program_type, self_size))

print()
print("== candidates ==")
for i, soff, pt, ss in targets:
    print("   idx %-3d @0x%-10X prog=0x%02X (%s)  self_size=%s" % (i, soff, pt, PROG.get(pt,'?'), format(ss,',')))
