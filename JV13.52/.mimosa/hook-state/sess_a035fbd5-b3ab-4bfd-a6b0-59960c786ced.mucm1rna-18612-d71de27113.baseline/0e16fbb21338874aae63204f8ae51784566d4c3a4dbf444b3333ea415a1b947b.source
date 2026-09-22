"""Pull the v7 failure offset off the console over FTP.

FTP only (2121). Never touches 9090.
"""
import socket, sys
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121
LOCAL_DIR = r'C:\Users\Kinan\Downloads\JV13.52'

# --- is it up?
s = socket.socket()
s.settimeout(4)
try:
    s.connect((HOST, 2121))
    s.recv(80)
except Exception as e:
    print("console 2121 not reachable:", type(e).__name__, e)
    sys.exit(2)
finally:
    s.close()

ftp = FTP()
ftp.connect(HOST, PORT, timeout=30)
print("welcome:", ftp.getwelcome())
ftp.login('anonymous', 'anonymous')

WANT = ['kmem_img.bin', 'kmem_img.txt', 'kmem_status.txt', 'kmem_peek.bin',
        'kmem.cfg', 'selfdec.bin']

print("\n--- /mnt/usb0 with sizes ---")
try:
    lines = []
    ftp.retrlines('LIST /mnt/usb0', lines.append)
    for L in lines:
        parts = L.split(None, 8)
        if len(parts) >= 9:
            print(f"  {parts[4]:>12}  {parts[8]}")
        else:
            print("  ", L)
except Exception as e:
    print("  LIST failed:", e)

print("\n--- sizes of interest + partial download ---")
for name in WANT:
    remote = '/' + name if name.startswith('mnt') else '/mnt/usb0/' + name
    try:
        sz = ftp.size(remote)
        print(f"  {name:<18} {sz:>12,} B")
        if name in ('kmem_img.bin', 'kmem_img.txt', 'kmem_status.txt') and sz:
            out = fr'{LOCAL_DIR}\pulled_{name}'
            with open(out, 'wb') as f:
                ftp.retrbinary(f'RETR {remote}', f.write)
            print(f"      -> saved {out}")
    except Exception as e:
        print(f"  {name:<18} absent ({e})")

print("\n--- /mnt/usb0 free space ---")
try:
    lines = []
    ftp.retrlines('STAT /mnt/usb0', lines.append)
    for L in lines:
        print("  ", L[:160])
except Exception as e:
    print("  ", e)

ftp.quit()
