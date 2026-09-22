"""Stage v9 and clear the stale 0-byte dump. FTP 2121 only."""
import os, sys
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121
LOCAL = r'C:\Users\Kinan\Downloads\JV13.52\kmemdump\kmemdump.bin'
DEST = ['/mnt/usb0/kmemdump.bin',
        '/data/GoldHEN/payloads/kmemdump.bin',
        '/data/payloads/kmemdump.bin']

if not os.path.exists(LOCAL):
    print("missing", LOCAL); sys.exit(3)
size = os.path.getsize(LOCAL)
print(f"local: {LOCAL} ({size:,} B)")

ftp = FTP()
ftp.connect(HOST, PORT, timeout=30)
print("welcome:", ftp.getwelcome())
ftp.login('anonymous', 'anonymous')

for d in DEST:
    try:
        with open(LOCAL, 'rb') as f:
            ftp.storbinary(f'STOR {d}', f)
        print(f"  {'OK  ' if ftp.size(d) == size else 'SIZE'} {d}")
    except Exception as e:
        print(f"  FAIL {d}: {e}")

print("\n--- clearing stale v7 leftovers ---")
for name in ['/mnt/usb0/kmem_img.bin', '/mnt/usb0/kmem_img.txt',
             '/mnt/usb0/kmem_status.txt', '/mnt/usb0/kmem_peek.bin',
             '/mnt/usb0/kmem.cfg']:
    try:
        ftp.delete(name)
        print("  deleted", name)
    except Exception as e:
        print(f"  {name}: {e}")

print("\n--- /mnt/usb0 now ---")
lines = []
ftp.retrlines('LIST /mnt/usb0', lines.append)
for L in lines:
    p = L.split(None, 8)
    print(f"  {p[4]:>12}  {p[8]}" if len(p) >= 9 else "  " + L)

ftp.quit()
print("\nstaged. kbase is ASLR-slid, so offsets in the probe are relative (correct).")
