import struct, datetime
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121
PATH = '/mnt/usb0/PS4UPDATE1.PUP.dec'

def head_bytes(path, off, n):
    f = FTP(); f.connect(HOST, PORT, timeout=12); f.login('anonymous','anonymous')
    sock = f.transfercmd('RETR ' + path, rest=off)
    buf = b''
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            break
        buf += c
    try: sock.close()
    except Exception: pass
    try: f.voidresp()
    except Exception: pass
    f.quit()
    return buf

def magic_of(b):
    if b[:4] == b'SLB2': return 'SLB2 container'
    if b[:4] == b'\x7fELF': return 'ELF (plain executable)'
    if b[:4] == b'\x4f\x15\x3d\x1d': return 'SELF (encrypted module)'
    if b[:4] == b'\x5e\xd7\x9a\x0b': return 'SECURE LOADER header'
    if b[:4] == b'PFS\x00': return 'PFS image'
    if b[:3] == b'SCE': return 'SCE (pfs/slb?)'
    return 'unknown'

# read the decrypted header/segment table
hdr = head_bytes(PATH, 0, 0x20 + 40*0x20)
seg_count = struct.unpack_from('<H', hdr, 0x18)[0]
print("PS4UPDATE1.PUP.dec   segment_count =", seg_count)
print("probe @", datetime.datetime.now().strftime('%H:%M:%S'))
print()
print("%-4s %-12s %-12s %-14s %-14s %s" % ("idx","seg_flags","head16","offset","compressed","magic"))
rows = []
for i in range(seg_count):
    o = 0x20 + i*0x20
    sflags, _p = struct.unpack_from('<II', hdr, o)
    soff, csize, usize = struct.unpack_from('<QQQ', hdr, o+8)
    try:
        b = head_bytes(PATH, soff, 16)
        m = magic_of(b)
        hx = b[:8].hex(' ')
    except Exception as e:
        m, hx = 'READ FAIL ' + type(e).__name__, ''
    rows.append((i, sflags, soff, csize, usize, m, hx))
    print("%-4d 0x%-10X %-12s 0x%-12X %-14s %s" % (i, sflags, hx, soff, format(csize,','), m))

print()
print("== notable segments ==")
for i, sflags, soff, csize, usize, m, hx in rows:
    if m in ('SLB2 container', 'SELF (encrypted module)', 'ELF (plain executable)', 'SECURE LOADER header'):
        print("   idx %-3d  %-26s comp=%-13s uncomp=%-13s @0x%X" % (i, m, format(csize,','), format(usize,','), soff))
