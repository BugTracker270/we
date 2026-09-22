"""Pull the arena dump. FTP 2121 only."""
import os, time
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121
DEST = r'C:\Users\Kinan\Downloads\JV13.52'

ftp = FTP()
ftp.connect(HOST, PORT, timeout=120)
print("welcome:", ftp.getwelcome())
ftp.login('anonymous', 'anonymous')

print("\n--- /mnt/usb0 ---")
lines = []
ftp.retrlines('LIST /mnt/usb0', lines.append)
for L in lines:
    p = L.split(None, 8)
    print(f"  {p[4]:>12}  {p[8]}" if len(p) >= 9 else "  " + L)

for name in ['kmem_img.txt', 'kmem_status.txt', 'kmem_img.bin']:
    try:
        sz = ftp.size('/mnt/usb0/' + name)
        print(f"\n{name} = {sz:,} B")
        if sz:
            out = os.path.join(DEST, 'v12_' + name)
            t0 = time.time()
            with open(out, 'wb') as f:
                ftp.retrbinary('RETR /mnt/usb0/' + name, f.write)
            print(f"   saved {out} ({os.path.getsize(out):,} B in {time.time()-t0:.1f}s)")
    except Exception as e:
        print(f"\n{name} absent ({e})")

ftp.quit()
