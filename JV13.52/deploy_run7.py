#!/usr/bin/env python3
"""Stage the patched selfdec2 plus a FULL sd.cfg for the transport-probe run.

deploy_selfdec2.py only writes maxstep/lock/svcreq/seg, so smcall would fall back
to its default of 0 and step 7 would return early again - i.e. the whole point of
this run. This writes all six keys.

Config for this run:
    maxstep=7   steps 1..6 already proven by run 7
    lock=1
    svcreq=0    MUST be 0: step 7 aborts before the mailbox when svcreq && id==0,
                and *(0x269C0A0) is 0 on this console
    seg=0
    ctxidx=0    pin slot 0 (all four read 3, so this also matches "first free")
    smcall=1    actually issue finalize() + verify_header()

Nothing is written to /mnt/usb0: an FTP write there is what killed GoldHEN's FTP
before. /data/payloads is read first by sd_cfg_parse, so that is sufficient.
"""
import os, time
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121
ROOT = r'C:\Users\Kinan\Downloads\JV13.52'

PAYLOAD = os.path.join(ROOT, r'selfdec2\selfdec2.bin')
TARGET  = os.path.join(ROOT, r'dec\1352\80010008.self')
CFG     = os.path.join(ROOT, 'sd.cfg')

CFG_TEXT = "maxstep=7\nlock=1\nsvcreq=0\nseg=0\nctxidx=0\nsmcall=1\n"


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
                print(f'  OK   {dest}  {size} B'
                      + ('  (size unreported)' if got is None else ''))
                return True
            last = f'size mismatch local={size} remote={got}'
        except Exception as e:
            last = f'{type(e).__name__}: {e}'
        finally:
            try:
                if f:
                    f.close()
            except Exception:
                pass
        print(f'  retry {a+1}/{tries} {dest}: {last}')
        time.sleep(1.0)
    print(f'  FAIL {dest}: {last}')
    return False


with open(CFG, 'wb') as fh:
    fh.write(CFG_TEXT.encode())
print('sd.cfg contents:')
print(CFG_TEXT)

print('--- uploading ---')
ok = True
for dest, local in [('/data/payloads/sd.cfg', CFG),
                    ('/data/payloads/target.self', TARGET),
                    ('/data/payloads/selfdec2.bin', PAYLOAD),
                    ('/data/GoldHEN/payloads/selfdec2.bin', PAYLOAD)]:
    if not put(local, dest):
        ok = False

print('\nRESULT:', 'all staged' if ok else 'SOME FILES FAILED')
raise SystemExit(0 if ok else 1)
