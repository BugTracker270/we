"""Stage the arena-targeted dump (absolute addressing).

Why this window:
  8001000B's module record says its image lives at 0xffffc18716072780.
  8001000B is index 6 (last) in the SLB2 directory; 80010008 (AuthMgr) is
  index 5, immediately before it. Module images are clustered, so AuthMgr's
  image should sit within a few MB of that address.

Window 0xffffc18716000000 .. 0xffffc18716800000 = 8 MB, 2048 reads of 4 KiB.
Cheap enough to be low risk, broad enough to cover the cluster + margin.
"""
import io, os
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121
LOCAL = r'C:\Users\Kinan\Downloads\JV13.52\kmemdump\kmemdump.bin'
DEST = ['/mnt/usb0/kmemdump.bin',
        '/data/GoldHEN/payloads/kmemdump.bin',
        '/data/payloads/kmemdump.bin']

CFG = b"start=0xffffc18716000000\nend=0xffffc18716800000\nchunk=0x1000\nabs=1\n"

size = os.path.getsize(LOCAL)
print(f"payload {size:,} B")
print("cfg:\n" + CFG.decode())

ftp = FTP()
ftp.connect(HOST, PORT, timeout=60)
print("welcome:", ftp.getwelcome())
ftp.login('anonymous', 'anonymous')

for d in DEST:
    with open(LOCAL, 'rb') as f:
        ftp.storbinary(f'STOR {d}', f)
    print(f"  {'OK  ' if ftp.size(d) == size else 'SIZE'} {d}")

ftp.storbinary('STOR /mnt/usb0/kmem.cfg', io.BytesIO(CFG))
print("  cfg:", ftp.size('/mnt/usb0/kmem.cfg'), "B")

for name in ['/mnt/usb0/kmem_img.bin', '/mnt/usb0/kmem_img.txt',
             '/mnt/usb0/kmem_status.txt']:
    try:
        ftp.delete(name); print("  deleted", name)
    except Exception as e:
        print(f"  {name}: {e}")

print("\n--- /mnt/usb0 ---")
lines = []
ftp.retrlines('LIST /mnt/usb0', lines.append)
for L in lines:
    p = L.split(None, 8)
    print(f"  {p[4]:>12}  {p[8]}" if len(p) >= 9 else "  " + L)

ftp.quit()
print(f"\nwindow 8 MB = {0x800000 // 0x1000} reads")
