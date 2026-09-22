"""ONE operation on a fresh FTP session: RETR /mnt/usb0/sd_status.txt.

No nlst/LIST/MLSD (kills GoldHEN FTP). No SIZE. No second op.
"""
import sys
from ftplib import FTP

HOSTS = ['172.20.10.3', '192.168.1.100', '192.168.0.100', '172.20.10.2']
SRC = '/mnt/usb0/sd_status.txt'
DST = r'C:\Users\Kinan\Downloads\JV13.52\sd_status.txt'

data = bytearray()


def grab(h):
    ftp = FTP()
    ftp.connect(h, 2121, timeout=20)
    try:
        ftp.login('anonymous', 'anonymous')
    except Exception:
        pass
    ftp.retrbinary('RETR ' + SRC, data.extend, blocksize=8192)
    try:
        ftp.quit()
    except Exception:
        pass


ok = None
for h in HOSTS:
    try:
        grab(h)
        ok = h
        break
    except Exception as e:
        print(f"  {h}: {type(e).__name__}: {e}")

if ok is None:
    print("no host answered - console offline or FTP down")
    sys.exit(2)

print(f"got {len(data)} bytes from {ok}")
open(DST, 'wb').write(bytes(data))
print("saved:", DST)
print("----")
print(bytes(data).decode(errors='replace'))
