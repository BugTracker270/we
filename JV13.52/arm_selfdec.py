"""Deploy selfdec.bin and ARM the stage-1 call by creating /mnt/usb0/selfdec.mode.

The payload removes that file itself after the attempt, so a bad result cannot
repeat on the next launch.
"""
from ftplib import FTP
import hashlib, io, os

HOST = '172.20.10.3'
LOCAL = r'C:\Users\Kinan\Downloads\JV13.52\selfdec\selfdec.bin'
TARGETS = ['/data/GoldHEN/payloads/selfdec.bin',
           '/data/payloads/selfdec.bin',
           '/mnt/usb0/selfdec.bin']
MODE = '/mnt/usb0/selfdec.mode'

data = open(LOCAL, 'rb').read()
want = hashlib.sha256(data).hexdigest().upper()
print(f"payload {len(data)} bytes  sha256 {want}")

ftp = FTP()
ftp.connect(HOST, 2121, timeout=25)
ftp.login('anonymous', 'anonymous')
print("connected:", ftp.getwelcome())

print("\n--- upload payload ---")
for t in TARGETS:
    with open(LOCAL, 'rb') as f:
        ftp.storbinary('STOR ' + t, f)
    print("  uploaded", t)

print("\n--- verify payload ---")
ok = 0
for t in TARGETS:
    buf = io.BytesIO()
    ftp.retrbinary('RETR ' + t, buf.write)
    good = hashlib.sha256(buf.getvalue()).hexdigest().upper() == want
    ok += good
    print(f"  {t:42} {len(buf.getvalue()):7d} B  {'OK' if good else 'MISMATCH'}")
print(f"  {ok}/{len(TARGETS)} verified")

print("\n--- arm ---")
ftp.storbinary('STOR ' + MODE, io.BytesIO(b"decrypt\n"))
buf = io.BytesIO()
ftp.retrbinary('RETR ' + MODE, buf.write)
print(f"  {MODE} contents = {buf.getvalue()!r}")
print("  -> next launch will run the stage-1 IsLoadable call")

ftp.quit()
print("\nARMED.")
