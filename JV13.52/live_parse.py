import re, time, struct, datetime, socket
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121

def connect():
    f = FTP(); f.connect(HOST, PORT, timeout=10); f.login('anonymous','anonymous'); return f

def listing():
    f = connect()
    lines = []
    f.retrlines('LIST /mnt/usb0', lines.append)
    f.quit()
    out = {}
    for L in lines:
        m = re.match(r'\S+\s+\S+\s+\S+\s+\S+\s+(\d+)\s+\S+\s+\d+\s+\S+\s+(.+)$', L)
        if m and not m.group(2).startswith('System Volume'):
            out[m.group(2).strip()] = int(m.group(1))
    return out

def head_bytes(path, n):
    f = connect()
    sock = f.transfercmd('RETR ' + path)
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(min(4096, n - len(buf)))
        if not chunk:
            break
        buf += chunk
    try:
        sock.close()
    except Exception:
        pass
    try:
        f.voidresp()
    except Exception:
        pass
    f.quit()
    return buf

print("=== live listing @", datetime.datetime.now().strftime('%H:%M:%S'), "===")
a = listing()
for k in sorted(a):
    print("   %-30s %s" % (k, format(a[k], ',')))
dec = [k for k in a if k.endswith('.dec')]
if dec:
    k = dec[0]
    s0 = a[k]
    time.sleep(10)
    b = listing()
    s1 = b.get(k, s0)
    print("\n   %s: +%s bytes in 10s  (~%.2f MB/s)" % (k, format(s1-s0, ','), (s1-s0)/10/1048576))

print("\n=== decrypted header of PS4UPDATE1.PUP.dec ===")
try:
    d = head_bytes('/mnt/usb0/PS4UPDATE1.PUP.dec', 0x1000)
except Exception as e:
    print("   read failed:", type(e).__name__, e); raise SystemExit

print("   got %d bytes" % len(d))
magic, unk04, unk08, flags, unk0b, unk0c, unk0e = struct.unpack_from('<IIHBBHH', d, 0)
print("   magic             = 0x%08X   (expect 0x1D3D154F)" % magic)
print("   unknown_04        = 0x%08X" % unk04)
print("   unknown_08        = 0x%04X" % unk08)
print("   flags             = 0x%02X" % flags)
print("   unknown_0C        = 0x%04X   unknown_0E = 0x%04X" % (unk0c, unk0e))
file_size, seg_count, unk1a, unk1c = struct.unpack_from('<QHHI', d, 0x10)
print("   file_size         = %s" % format(file_size, ','))
print("   segment_count     = %d" % seg_count)
print("   unknown_1A/1C     = 0x%04X / 0x%08X" % (unk1a, unk1c))

SEG_ID = {0:'PS4UPDATE(header)',1:'EMC_IPL',2:'EAP_KBL',3:'EAP_KERNEL?',4:'SECURE_LOADER',
          5:'COREOS  <-- KERNEL LIVES HERE',6:'SYSTEM',7:'SYSTEM_EX',8:'APP?',9:'APP2?',
          10:'VTRM',11:'MANU',12:'EULA',13:'EMC_IPL_2',14:'EAP_KBL_2',15:'EAP_KERNEL_2?',
          16:'WATERMARK',17:'?',18:'?',19:'?',20:'?',32:'EMC_IPL?',33:'EAP_KBL?',39:'?',40:'?'}

print("\n   %-4s %-14s %-18s %-14s %-14s" % ("idx","flags","offset","compressed","uncompressed"))
for i in range(min(seg_count, 40)):
    off = 0x20 + i*0x20
    if off + 0x20 > len(d):
        print("   ...table beyond read window"); break
    sflags, _pad = struct.unpack_from('<II', d, off)
    soff, csize, usize = struct.unpack_from('<QQQ', d, off+8)
    print("   %-4d 0x%-12X 0x%-16X %-14s %-14s %s" %
          (i, sflags, soff, format(csize, ','), format(usize, ','), SEG_ID.get(i, '')))

# look for the firmware version in the (now decrypted) info area
info_off = 0x20 + seg_count*0x20
window = d[info_off:info_off+0x400]
print("\n   info area @0x%X (first 128 bytes):" % info_off)
for r in range(0, 128, 16):
    row = window[r:r+16]
    print("      %04X  %-47s  %s" % (info_off+r, row.hex(' '), ''.join(chr(c) if 32 <= c < 127 else '.' for c in row)))
txt = ''.join(chr(c) if 32 <= c < 127 else ' ' for c in window)
for pat in ['14.00','14.0','1400']:
    if pat in txt:
        print("   !! found %r in info area" % pat)
