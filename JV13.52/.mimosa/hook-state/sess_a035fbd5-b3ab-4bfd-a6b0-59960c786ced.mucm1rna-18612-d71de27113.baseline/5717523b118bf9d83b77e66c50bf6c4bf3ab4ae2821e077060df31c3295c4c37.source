#!/usr/bin/env python3
"""Push the step-7 matrix payload + its config.

STOR only. No NLST/LIST/MLSD anywhere - listing /mnt/usb0 is what killed
GoldHEN's FTP server before, and target.self is already staged (88304 B, which
is exactly what the last run reported as self=88304), so it is not re-sent.
"""
import os, time
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121
ROOT = r'C:\Users\Kinan\Downloads\JV13.52'
PAYLOAD = os.path.join(ROOT, r'selfdec2\selfdec2.bin')
CFG = os.path.join(ROOT, 'sd.cfg')

CFG_TEXT = "maxstep=7\nlock=1\nsvcreq=0\nseg=0\nctxidx=0\nsmcall=0\n"
open(CFG, 'wb').write(CFG_TEXT.encode())

JOBS = [('/data/payloads/sd.cfg', CFG),
        ('/data/GoldHEN/payloads/selfdec2.bin', PAYLOAD),
        ('/data/payloads/selfdec2.bin', PAYLOAD)]


def put(local, dest, tries=3):
    size = os.path.getsize(local)
    last = ''
    for a in range(tries):
        f = None
        try:
            f = FTP()
            f.encoding = 'latin-1'
            f.connect(HOST, PORT, timeout=90)
            f.login('anonymous', 'anonymous')
            f.voidcmd('TYPE I')
            with open(local, 'rb') as fh:
                f.storbinary('STOR ' + dest, fh, blocksize=8192)
            try:
                got = f.size(dest)
            except Exception:
                got = None
            try:
                f.quit()
            except Exception:
                pass
            if got is None or got == size:
                print(f"  OK   {dest}  {size} B"
                      + ("  (size unreported)" if got is None else ""))
                return True
            last = f"size mismatch local={size} remote={got}"
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
        finally:
            try:
                if f:
                    f.close()
            except Exception:
                pass
        print(f"  retry {a+1}/{tries} {dest}: {last}")
        time.sleep(1.0)
    print(f"  FAIL {dest}: {last}")
    return False


print("sd.cfg:")
print(CFG_TEXT)
print("uploading (STOR only):")
ok = True
for dest, local in JOBS:
    if not put(local, dest):
        ok = False
print("\nRESULT:", "staged" if ok else "SOME FILES FAILED")
