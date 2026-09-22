#!/usr/bin/env python3
"""GoldHEN's FTP drops connections constantly. One fresh connection per file,
retries, and verify by size. This is the only reliable way to read from it."""
import os, socket, sys, time
from ftplib import FTP

HOST = '172.20.10.3'
RECOVER = r'C:\Users\Kinan\Downloads\JV13.52\recovered'
os.makedirs(RECOVER, exist_ok=True)

WANT = ['/mnt/usb0/sd_status.txt',
        '/mnt/usb0/sd_hdr20.bin',
        '/mnt/usb0/plain.bin']


def get(dest, tries=6):
    for a in range(tries):
        f = None
        try:
            f = FTP(); f.encoding = 'latin-1'
            f.connect(HOST, 2121, timeout=45)
            f.login('anonymous', 'anonymous')
            f.voidcmd('TYPE I')
            expect = f.size(dest)
            local = os.path.join(RECOVER, os.path.basename(dest.replace('/', '_')))
            with open(local, 'wb') as fh:
                f.retrbinary(f'RETR {dest}', fh.write)
            try:
                f.quit()
            except Exception:
                pass
            got = os.path.getsize(local)
            if expect is None or got == expect:
                return local, got
            print(f"    size mismatch {got} != {expect}, retrying")
        except Exception as e:
            print(f"    try {a+1}/{tries}: {type(e).__name__}: {str(e)[:60]}")
        finally:
            try:
                if f: f.close()
            except Exception:
                pass
        time.sleep(1.5)
    return None, None


for d in WANT:
    print(f"\n=== {d} ===")
    local, sz = get(d)
    if not local:
        print("  FAILED to download")
        continue
    data = open(local, 'rb').read()
    print(f"  -> {local}  ({sz} B)")
    if 'status' in d:
        print("  ---- raw ----")
        print("  " + data.decode(errors='replace').replace('\n', '\n  '))
    else:
        print("  hex:", data.hex())
