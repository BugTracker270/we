#!/usr/bin/env python3
"""Stage selfdec2 + target + config on the console over FTP (2121 only).

GoldHEN's FTP server drops connections readily, so every file gets its own
connection and up to 4 attempts with verification by size.
Never touches 9090 - BinLoader is a one-shot listener.
"""
import os, sys, time, socket
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121
ROOT = r'C:\Users\Kinan\Downloads\JV13.52'

PAYLOAD = os.path.join(ROOT, r'selfdec2\selfdec2.bin')
TARGET  = os.path.join(ROOT, r'dec\1352\80010008.self')
CFG     = os.path.join(ROOT, 'sd.cfg')

MAXSTEP = sys.argv[1] if len(sys.argv) > 1 else '6'
LOCK    = sys.argv[2] if len(sys.argv) > 2 else '1'
SVCREQ  = sys.argv[3] if len(sys.argv) > 3 else '1'
SEG     = sys.argv[4] if len(sys.argv) > 4 else '0'


def conn():
    f = FTP()
    f.encoding = 'latin-1'
    f.connect(HOST, PORT, timeout=90)
    f.login('anonymous', 'anonymous')
    f.voidcmd('TYPE I')
    return f


def put(local, dest, tries=4):
    size = os.path.getsize(local)
    last = ''
    for a in range(tries):
        f = None
        try:
            f = conn()
            with open(local, 'rb') as fh:
                f.storbinary(f'STOR {dest}', fh, blocksize=8192)
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
                      + (f" (size unreported)" if got is None else ""))
                return True
            last = f"size mismatch local={size} remote={got}"
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
        finally:
            try:
                if f: f.close()
            except Exception:
                pass
        print(f"  retry {a+1}/{tries} {dest}: {last}")
        time.sleep(1.0)
    print(f"  FAIL {dest}: {last}")
    return False


def ls(d, tries=3):
    for _ in range(tries):
        f = None
        try:
            f = conn()
            names = f.nlst(d)
            f.quit()
            return names
        except Exception as e:
            print(f"  ls {d} failed: {type(e).__name__}: {e}")
        finally:
            try:
                if f: f.close()
            except Exception:
                pass
        time.sleep(1.0)
    return []


print("--- before ---")
for d in ('/mnt/usb0', '/data/GoldHEN/payloads'):
    n = ls(d)
    print(f"  {d}: {n}")

cfg_text = f"maxstep={MAXSTEP}\nlock={LOCK}\nsvcreq={SVCREQ}\nseg={SEG}\n"
with open(CFG, 'wb') as f:
    f.write(cfg_text.encode())
print(f"\nsd.cfg contents:\n{cfg_text}")

# /data/payloads is primary. The FAT stick at /mnt/usb0 is written last and
# best-effort only: an FTP write there is what killed GoldHEN's FTP server last
# time, so a failure there must not abort the staging.
print("--- uploading ---")
ok = True
CRITICAL = [('/data/payloads/sd.cfg', CFG),
            ('/data/payloads/target.self', TARGET),
            ('/data/GoldHEN/payloads/selfdec2.bin', PAYLOAD),
            ('/data/payloads/selfdec2.bin', PAYLOAD)]
BEST_EFFORT = [('/mnt/usb0/selfdec2.bin', PAYLOAD)]

for dest, local in CRITICAL:
    if not put(local, dest):
        ok = False
for dest, local in BEST_EFFORT:
    put(local, dest, tries=1)

print("\n--- after ---")
for d in ('/mnt/usb0', '/data/GoldHEN/payloads'):
    print(f"  {d}: {ls(d)}")

print("\nRESULT:", "all staged" if ok else "SOME FILES FAILED")
