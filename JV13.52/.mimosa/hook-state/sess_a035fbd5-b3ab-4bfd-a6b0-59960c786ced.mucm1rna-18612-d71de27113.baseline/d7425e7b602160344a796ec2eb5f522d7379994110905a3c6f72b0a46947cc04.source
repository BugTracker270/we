#!/usr/bin/env python3
"""Single RETR of the payload's status file. One operation, one connection."""
import os, sys, time
from ftplib import FTP

HOST = '172.20.10.3'
DEST = sys.argv[1] if len(sys.argv) > 1 else '/data/payloads/sd_status.txt'
LOCAL = r'C:\Users\Kinan\Downloads\JV13.52\recovered\sd_status_latest.txt'
os.makedirs(os.path.dirname(LOCAL), exist_ok=True)

for a in range(5):
    f = None
    try:
        f = FTP(); f.encoding = 'latin-1'
        f.connect(HOST, 2121, timeout=60)
        f.login('anonymous', 'anonymous')
        f.voidcmd('TYPE I')
        with open(LOCAL, 'wb') as fh:
            f.retrbinary(f'RETR {DEST}', fh.write)
        try:
            f.quit()
        except Exception:
            pass
        print(f"got {DEST} -> {LOCAL} ({os.path.getsize(LOCAL)} B)\n")
        print(open(LOCAL, encoding='utf-8', errors='replace').read())
        sys.exit(0)
    except Exception as e:
        print(f"  try {a+1}/5: {type(e).__name__}: {str(e)[:60]}")
    finally:
        try:
            if f: f.close()
        except Exception:
            pass
    time.sleep(2)

# fall back to the usb copy
if DEST != '/mnt/usb0/sd_status.txt':
    print("retrying from /mnt/usb0 ...")
    os.system(f'python "{os.path.abspath(__file__)}" /mnt/usb0/sd_status.txt')
sys.exit(1)
