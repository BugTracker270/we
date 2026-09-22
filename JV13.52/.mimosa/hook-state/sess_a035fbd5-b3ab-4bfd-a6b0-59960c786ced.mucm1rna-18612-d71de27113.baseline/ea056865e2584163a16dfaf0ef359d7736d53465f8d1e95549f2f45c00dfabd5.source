#!/usr/bin/env python3
"""Stage selfdec2 for the real run.

GoldHEN's FTP crashes on directory listing (nlst/LIST) and is unhappy with
rapid reconnects, so this script:
  * never issues nlst / LIST / MLSD
  * opens exactly one connection, uploads everything, verifies by SIZE, closes
  * writes /data/payloads only - the FAT stick at /mnt/usb0 is what killed FTP
    before, and the payload now prefers /data/payloads anyway

Never touches 9090.
"""
import os, socket, sys, time
from ftplib import FTP

HOST = '172.20.10.3'
ROOT = r'C:\Users\Kinan\Downloads\JV13.52'

PAYLOAD = os.path.join(ROOT, r'selfdec2\selfdec2.bin')
TARGET  = os.path.join(ROOT, r'dec\1352\80010008.self')
CFG     = os.path.join(ROOT, 'sd.cfg')

MAXSTEP = sys.argv[1] if len(sys.argv) > 1 else '6'
LOCK    = sys.argv[2] if len(sys.argv) > 2 else '1'
SVCREQ  = sys.argv[3] if len(sys.argv) > 3 else '1'
SEG     = sys.argv[4] if len(sys.argv) > 4 else '0'

cfg_text = f"maxstep={MAXSTEP}\nlock={LOCK}\nsvcreq={SVCREQ}\nseg={SEG}\n"
with open(CFG, 'wb') as f:
    f.write(cfg_text.encode())

JOBS = [
    (CFG,     '/data/payloads/sd.cfg'),
    (TARGET,  '/data/payloads/target.self'),
    (PAYLOAD, '/data/payloads/selfdec2.bin'),
    (PAYLOAD, '/data/GoldHEN/payloads/selfdec2.bin'),
]


def port_open(p, t=4.0):
    s = socket.socket(); s.settimeout(t)
    try:
        s.connect((HOST, p)); return True
    except Exception:
        return False
    finally:
        s.close()


if not port_open(2121):
    print("FTP 2121 is closed - ask for it to be restarted")
    sys.exit(2)

print(f"sd.cfg ->\n{cfg_text}")
print("uploading (one connection, SIZE-verified, no listing):")

f = None
for attempt in range(5):
    try:
        f = FTP(); f.encoding = 'latin-1'
        f.connect(HOST, 2121, timeout=90)
        f.login('anonymous', 'anonymous')
        f.voidcmd('TYPE I')
        break
    except Exception as e:
        print(f"  connect retry {attempt+1}/5: {type(e).__name__}: {str(e)[:60]}")
        time.sleep(2.0)
if f is None:
    print("could not connect"); sys.exit(3)

ok = True
for local, dest in JOBS:
    size = os.path.getsize(local)
    done = False
    for attempt in range(3):
        try:
            with open(local, 'rb') as fh:
                f.storbinary(f'STOR {dest}', fh, blocksize=16384)
            try:
                got = f.size(dest)
            except Exception:
                got = None
            if got is None or got == size:
                print(f"  OK   {dest}  {size} B"
                      + (" (size unverified)" if got is None else ""))
                done = True
                break
            print(f"  retry {dest}: local={size} remote={got}")
        except Exception as e:
            print(f"  retry {dest}: {type(e).__name__}: {str(e)[:60]}")
            # reconnect once
            try:
                f.close()
            except Exception:
                pass
            try:
                f = FTP(); f.encoding = 'latin-1'
                f.connect(HOST, 2121, timeout=90)
                f.login('anonymous', 'anonymous')
                f.voidcmd('TYPE I')
            except Exception as e2:
                print(f"    reconnect failed: {str(e2)[:60]}")
                break
        time.sleep(1.0)
    if not done:
        ok = False
        print(f"  FAIL {dest}")

try:
    f.quit()
except Exception:
    pass

print("\nRESULT:", "staged" if ok else "INCOMPLETE")
sys.exit(0 if ok else 1)
