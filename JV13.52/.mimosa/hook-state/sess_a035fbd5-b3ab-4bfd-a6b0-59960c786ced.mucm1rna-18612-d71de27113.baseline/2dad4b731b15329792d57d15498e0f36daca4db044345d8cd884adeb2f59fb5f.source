#!/usr/bin/env python3
"""Confirm every staged copy is the fixed 27164 B build, then we can run.

One connection, SIZE only (no nlst - that is what killed GoldHEN's FTP).
A SIZE failure and a missing file look identical, so failures are reported as
"unknown", never as "absent".
"""
import os, sys, time
from ftplib import FTP

HOST = '172.20.10.3'
LOCAL = os.path.getsize(r'C:\Users\Kinan\Downloads\JV13.52\selfdec2\selfdec2.bin')
DESTS = ['/mnt/usb0/selfdec2.bin',
         '/data/GoldHEN/payloads/selfdec2.bin',
         '/data/payloads/selfdec2.bin',
         '/mnt/usb0/target.self',
         '/data/payloads/target.self']

print(f"local fixed payload = {LOCAL} B\n")

f = None
for a in range(5):
    try:
        f = FTP(); f.encoding = 'latin-1'
        f.connect(HOST, 2121, timeout=60)
        f.login('anonymous', 'anonymous')
        f.voidcmd('TYPE I')
        break
    except Exception as e:
        print(f"  connect {a+1}/5: {type(e).__name__}: {str(e)[:60]}")
        time.sleep(2)
if f is None:
    sys.exit(3)

for d in DESTS:
    try:
        s = f.size(d)
        mark = ""
        if d.endswith('selfdec2.bin'):
            mark = "  <== FIXED" if s == LOCAL else "  <== STALE!"
        print(f"  {str(s):>9}  {d}{mark}")
    except Exception as e:
        print(f"  {'unknown':>9}  {d}  ({type(e).__name__})")

try:
    f.quit()
except Exception:
    pass
