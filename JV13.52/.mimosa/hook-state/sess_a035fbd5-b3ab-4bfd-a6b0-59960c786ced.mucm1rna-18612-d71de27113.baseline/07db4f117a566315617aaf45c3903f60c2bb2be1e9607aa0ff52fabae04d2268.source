"""Remove /mnt/usb0/selfdec.mode so the payload reverts to probe-only."""
from ftplib import FTP

HOST = '172.20.10.3'
MODE = '/mnt/usb0/selfdec.mode'

ftp = FTP()
ftp.connect(HOST, 2121, timeout=20)
ftp.login('anonymous', 'anonymous')
try:
    ftp.delete(MODE)
    print("deleted", MODE)
except Exception as e:
    print("delete failed (may already be gone):", e)

try:
    names = [n.split('/')[-1] for n in ftp.nlst('/mnt/usb0')]
    present = [n for n in names if n.lower() in ('selfdec.mode', 'selfdec.bin')]
    print("still present in /mnt/usb0:", present)
except Exception as e:
    print("list error:", e)
ftp.quit()
