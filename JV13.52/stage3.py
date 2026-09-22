#!/usr/bin/env python3
"""One-shot staging session for selfdec2.

Hard-won constraints about this console's FTP server:
  * it must NEVER be sent nlst / LIST / MLSD - that is what has now killed it
    twice, taking the whole GoldHEN process (2121, 3232 and 9090) down with it
  * it survives only a couple of operations per session, so operations are
    ordered most-valuable-first and every outcome is logged
  * a failed SIZE is indistinguishable from "file absent", so absence is never
    concluded from SIZE alone

Session order:
  1. RETR /mnt/usb0/sd_status.txt   <- tells us how far run 1 got (steps 1..4)
  2. STOR /data/payloads/target.self
  3. STOR /data/payloads/selfdec2.bin
  4. STOR /data/GoldHEN/payloads/selfdec2.bin

No sd.cfg is written: the payload's built-in defaults are already
maxstep=6, lock=1, svcreq=1, seg=0, which is exactly what we want.

Never touches 9090.
"""
import os, socket, sys, time
from ftplib import FTP

HOST = '172.20.10.3'
ROOT = r'C:\Users\Kinan\Downloads\JV13.52'
RECOVER = os.path.join(ROOT, 'recovered')
os.makedirs(RECOVER, exist_ok=True)

PAYLOAD = os.path.join(ROOT, r'selfdec2\selfdec2.bin')
TARGET  = os.path.join(ROOT, r'dec\1352\80010008.self')


def port_open(p, t=4.0):
    s = socket.socket(); s.settimeout(t)
    try:
        s.connect((HOST, p)); return True
    except Exception:
        return False
    finally:
        s.close()


if not port_open(2121):
    print("FTP 2121 closed - needs a restart")
    sys.exit(2)

# ONE connection for the whole session, treated as disposable
f = None
for a in range(6):
    try:
        f = FTP(); f.encoding = 'latin-1'
        f.connect(HOST, 2121, timeout=60)
        f.login('anonymous', 'anonymous')
        f.voidcmd('TYPE I')
        print("connected")
        break
    except Exception as e:
        print(f"  connect {a+1}/6: {type(e).__name__}: {str(e)[:60]}")
        time.sleep(2.0)
if f is None:
    sys.exit(3)

log = []


def op(label, fn):
    try:
        r = fn()
        print(f"  OK    {label}  {r}")
        log.append((label, True))
        return r
    except Exception as e:
        print(f"  FAIL  {label}  {type(e).__name__}: {str(e)[:70]}")
        log.append((label, False))
        return None


# ---- 1. the most valuable thing: how far did run 1 get? ----
print("\n[1] retrieving run-1 status")
loc = os.path.join(RECOVER, 'sd_status_run1.txt')


def _status():
    with open(loc, 'wb') as fh:
        f.retrbinary('RETR /mnt/usb0/sd_status.txt', fh.write)
    return f"{os.path.getsize(loc)} B"


if op('RETR /mnt/usb0/sd_status.txt', _status):
    print("\n  ---- sd_status.txt (run 1) ----")
    print("  " + open(loc, encoding='utf-8', errors='replace')
          .read().replace('\n', '\n  '))

# ---- 2..4. stage ----
print("\n[2-4] staging")
for local, dest in ((TARGET, '/data/payloads/target.self'),
                    (PAYLOAD, '/data/payloads/selfdec2.bin'),
                    (PAYLOAD, '/data/GoldHEN/payloads/selfdec2.bin')):
    size = os.path.getsize(local)

    def _put(local=local, dest=dest, size=size):
        with open(local, 'rb') as fh:
            f.storbinary(f'STOR {dest}', fh, blocksize=16384)
        try:
            got = f.size(dest)
        except Exception:
            got = None
        return f"{size} B" + ("" if got in (None, size) else f" !! remote={got}")

    op(f'STOR {dest}', _put)

try:
    f.quit()
except Exception:
    pass

print("\n=== session summary ===")
for label, ok in log:
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
miss = [l for l, o in log if not o]
print("\nRESULT:", "all done" if not miss else f"incomplete: {miss}")
sys.exit(0 if not miss else 1)
