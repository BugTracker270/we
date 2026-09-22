"""Pull the kmemdump artifacts off the console. FTP 2121 only."""
import os
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121
DEST = r'C:\Users\Kinan\Downloads\JV13.52'

ftp = FTP()
ftp.connect(HOST, PORT, timeout=60)
print("welcome:", ftp.getwelcome())
ftp.login('anonymous', 'anonymous')

print("\n--- /mnt/usb0 ---")
lines = []
ftp.retrlines('LIST /mnt/usb0', lines.append)
for L in lines:
    p = L.split(None, 8)
    print(f"  {p[4]:>12}  {p[8]}" if len(p) >= 9 else "  " + L)

for name in ['kmem_img.bin', 'kmem_img.txt', 'kmem_status.txt']:
    try:
        sz = ftp.size('/mnt/usb0/' + name)
        print(f"\n{name} = {sz:,} B")
        if sz:
            out = os.path.join(DEST, 'v10_' + name)
            with open(out, 'wb') as f:
                ftp.retrbinary('RETR /mnt/usb0/' + name, f.write)
            print("   saved", out, os.path.getsize(out), "B")
    except Exception as e:
        print(f"\n{name} absent ({e})")

ftp.quit()
