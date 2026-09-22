#!/usr/bin/env python3
"""Upload the payload in exactly ONE STOR on ONE fresh connection.

GoldHEN's FTP has been observed to survive only ~2 operations per session and
to die outright when an operation fails, so this deliberately does the single
most important thing and nothing else:
    STOR /data/GoldHEN/payloads/selfdec2.bin

/data/payloads/target.self is ALREADY staged (88304 B, verified), so it is not
re-uploaded. No sd.cfg is needed - the payload's built-in defaults are
maxstep=6, lock=1, svcreq=1, seg=0.

No nlst / LIST / MLSD. Never touches 9090.
"""
import os, socket, sys, time
from ftplib import FTP

HOST = '172.20.10.3'
ROOT = r'C:\Users\Kinan\Downloads\JV13.52'
PAYLOAD = os.path.join(ROOT, r'selfdec2\selfdec2.bin')
DEST = '/data/GoldHEN/payloads/selfdec2.bin'


def port_open(p, t=4.0):
    s = socket.socket(); s.settimeout(t)
    try:
        s.connect((HOST, p)); return True
    except Exception:
        return False
    finally:
        s.close()


if not port_open(2121):
    print("FTP 2121 closed")
    sys.exit(2)

size = os.path.getsize(PAYLOAD)
print(f"uploading {PAYLOAD} ({size} B) -> {DEST}")

for attempt in range(4):
    f = None
    try:
        f = FTP(); f.encoding = 'latin-1'
        f.connect(HOST, 2121, timeout=90)
        f.login('anonymous', 'anonymous')
        f.voidcmd('TYPE I')
        print(f"  attempt {attempt+1}: connected")
        with open(PAYLOAD, 'rb') as fh:
            f.storbinary(f'STOR {DEST}', fh, blocksize=16384)
        print("  STOR returned")
        try:
            f.quit()
        except Exception:
            pass
        # confirm on a SEPARATE connection so a dead session cannot mislead us
        time.sleep(1.0)
        g = FTP(); g.encoding = 'latin-1'
        g.connect(HOST, 2121, timeout=45)
        g.login('anonymous', 'anonymous')
        g.voidcmd('TYPE I')
        got = g.size(DEST)
        try:
            g.quit()
        except Exception:
            pass
        print(f"  remote size = {got} (expected {size})")
        if got == size:
            print("\nRESULT: payload staged & size-verified")
            sys.exit(0)
        print("  size mismatch, retrying")
    except Exception as e:
        print(f"  attempt {attempt+1} failed: {type(e).__name__}: {str(e)[:70]}")
    finally:
        try:
            if f: f.close()
        except Exception:
            pass
    time.sleep(2.0)

print("\nRESULT: staging failed")
sys.exit(1)
