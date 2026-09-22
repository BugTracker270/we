#!/usr/bin/env python3
"""Re-stage the target SELF. It went missing - run 5's status reported self=0,
so neither /data/payloads/target.self nor /mnt/usb0/target.self could be read.

One connection, 2 STORs, ordered primary-path-first. No nlst. Never 9090.
"""
import os, sys, time
from ftplib import FTP

HOST = '172.20.10.3'
SRC = r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\80010008.self'
DESTS = ['/data/payloads/target.self', '/mnt/usb0/target.self']

size = os.path.getsize(SRC)
print(f"target: {SRC}\n        {size} B (must match the SELF header's file_size)")
if size != 88304:
    print(f"!! unexpected size, expected 88304")
print()

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
        with open(SRC, 'rb') as fh:
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
print(f"\nexpected remote size = {size} B")
sys.exit(0 if all(o for _, o in results) else 1)
