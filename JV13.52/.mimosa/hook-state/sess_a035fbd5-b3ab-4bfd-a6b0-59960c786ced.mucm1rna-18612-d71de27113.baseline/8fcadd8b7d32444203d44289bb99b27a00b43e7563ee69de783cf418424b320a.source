#!/usr/bin/env python3
"""Push the FIXED payload everywhere a GoldHEN payload menu might read from.

Root cause of the last two runs: the fixed build was only staged at
/data/GoldHEN/payloads/, while the launched copy came from the FAT stick -
which still holds deploy #1's stale build. The stale build has `svcreq` (that's
why run 1's notification showed it) but not the g_a fix, so it still recorded
rc=-1 with a garbage step.

One connection, sequential STORs, each outcome logged. No nlst. Never 9090.
"""
import os, sys, time
from ftplib import FTP

HOST = '172.20.10.3'
PAYLOAD = r'C:\Users\Kinan\Downloads\JV13.52\selfdec2\selfdec2.bin'
DESTS = [
    '/mnt/usb0/selfdec2.bin',            # deploy #1 left a stale build here
    '/mnt/usb0/payloads/selfdec2.bin',
    '/data/GoldHEN/payloads/selfdec2.bin',
    '/data/payloads/selfdec2.bin',
]

size = os.path.getsize(PAYLOAD)
print(f"fixed payload: {size} B -> {len(DESTS)} destinations\n")

f = None
for a in range(6):
    try:
        f = FTP(); f.encoding = 'latin-1'
        f.connect(HOST, 2121, timeout=90)
        f.login('anonymous', 'anonymous')
        f.voidcmd('TYPE I')
        print("connected")
        break
    except Exception as e:
        print(f"  connect {a+1}/6: {type(e).__name__}: {str(e)[:60]}")
        time.sleep(2)
if f is None:
    sys.exit(3)

results = []
for dest in DESTS:
    try:
        with open(PAYLOAD, 'rb') as fh:
            f.storbinary(f'STOR {dest}', fh, blocksize=16384)
        print(f"  OK    {dest}")
        results.append((dest, True))
    except Exception as e:
        print(f"  FAIL  {dest}  {type(e).__name__}: {str(e)[:60]}")
        results.append((dest, False))

try:
    f.quit()
except Exception:
    pass

print("\n=== summary ===")
for d, ok in results:
    print(f"  {'ok  ' if ok else 'FAIL'}  {d}")
print("\nNow verify which copy is the fixed one:")
print(f"  local fixed size = {size} B")
