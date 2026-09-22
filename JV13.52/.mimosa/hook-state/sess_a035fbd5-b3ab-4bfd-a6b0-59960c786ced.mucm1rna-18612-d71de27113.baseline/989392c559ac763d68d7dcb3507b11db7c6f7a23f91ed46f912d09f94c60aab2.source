#!/usr/bin/env python3
"""EXACTLY one operation: STOR the payload to /data/GoldHEN/payloads/.

No nlst/LIST. No SIZE. No status read. No second connection. Close and exit.
/data/payloads/target.self is already staged (88304 B) so it is not re-sent.
"""
import os, sys
from ftplib import FTP

HOST = '172.20.10.3'
PAYLOAD = r'C:\Users\Kinan\Downloads\JV13.52\selfdec2\selfdec2.bin'
DEST = '/data/GoldHEN/payloads/selfdec2.bin'

size = os.path.getsize(PAYLOAD)
print(f"single STOR: {PAYLOAD} ({size} B) -> {DEST}")

f = FTP()
f.encoding = 'latin-1'
f.connect(HOST, 2121, timeout=90)
print("connected:", f.getwelcome())
f.login('anonymous', 'anonymous')
f.voidcmd('TYPE I')

with open(PAYLOAD, 'rb') as fh:
    f.storbinary(f'STOR {DEST}', fh, blocksize=16384)
print("STOR returned")

try:
    f.quit()
except Exception:
    pass
print("done - exactly one operation performed")
