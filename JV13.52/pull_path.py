#!/usr/bin/env python3
"""RETR specific paths, one fresh session each. Read-only, cannot hang anything.

Goal: find out whether the last run actually executed, and whether the file on
the console is byte-identical to what I built.
"""
import hashlib, os, sys
from ftplib import FTP

HOST = '172.20.10.3'
DEST = r'C:\Users\Kinan\Downloads\JV13.52\pulled'

PATHS = sys.argv[1:] or [
    '/data/payloads/sd_status.txt',
    '/data/payloads/sd_keys.txt',
    '/mnt/usb0/sd_keys.txt',
    '/mnt/usb0/sd_status.txt',
]

os.makedirs(DEST, exist_ok=True)
for remote in PATHS:
    data = bytearray()
    f = None
    try:
        f = FTP()
        f.encoding = 'latin-1'
        f.connect(HOST, 2121, timeout=25)
        try:
            f.login('anonymous', 'anonymous')
        except Exception:
            pass
        f.retrbinary('RETR ' + remote, data.extend, blocksize=8192)
        try:
            f.quit()
        except Exception:
            pass
        local = os.path.join(DEST, remote.strip('/').replace('/', '_'))
        open(local, 'wb').write(bytes(data))
        print(f"=== {remote}  ({len(data)} B)  sha256="
              f"{hashlib.sha256(bytes(data)).hexdigest()[:16]}")
        print(bytes(data).decode(errors='replace').rstrip())
        print()
    except Exception as e:
        print(f"=== {remote}  -- FAILED: {type(e).__name__}: {e}\n")
    finally:
        try:
            if f:
                f.close()
        except Exception:
            pass
