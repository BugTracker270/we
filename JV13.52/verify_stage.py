#!/usr/bin/env python3
"""One FTP connection: confirm sd.cfg content and target.self size, then stop.

Deliberately NO nlst/LIST/MLSD - directory listing is what has killed GoldHEN's
FTP server before. SIZE + a single RETR only.
"""
import os, time
from ftplib import FTP

HOST = '172.20.10.3'
ROOT = r'C:\Users\Kinan\Downloads\JV13.52'
LOCAL_TARGET = os.path.getsize(os.path.join(ROOT, r'dec\1352\80010008.self'))
WANT = b"maxstep=7\nlock=1\nsvcreq=0\nseg=0\nctxidx=0\nsmcall=1\n"

f = None
for a in range(6):
    try:
        f = FTP(); f.encoding = 'latin-1'
        f.connect(HOST, 2121, timeout=60)
        f.login('anonymous', 'anonymous')
        f.voidcmd('TYPE I')
        break
    except Exception as e:
        print(f'  connect {a+1}/6: {type(e).__name__}: {str(e)[:60]}')
        time.sleep(2)
        f = None
if f is None:
    raise SystemExit('FTP unreachable')

local_payload = os.path.getsize(os.path.join(ROOT, r'selfdec2\selfdec2.bin'))

for d in ('/data/payloads/target.self',
          '/data/payloads/selfdec2.bin',
          '/data/GoldHEN/payloads/selfdec2.bin'):
    try:
        s = f.size(d)
        note = ''
        if d.endswith('target.self'):
            note = '  <== FULL TARGET OK' if s == LOCAL_TARGET else '  <== WRONG SIZE'
        else:
            note = '  <== ok' if s == local_payload else '  <== not needed anyway'
        print(f'  {str(s):>9}  {d}{note}')
    except Exception as e:
        print(f'  {"absent":>9}  {d}  ({type(e).__name__})')

buf = bytearray()
try:
    f.retrbinary('RETR /data/payloads/sd.cfg', buf.extend, blocksize=8192)
    got = bytes(buf)
    print(f'\n/data/payloads/sd.cfg = {got!r}')
    print('  MATCHES what we want to run' if got == WANT else '  *** DOES NOT MATCH ***')
except Exception as e:
    print(f'\n  RETR sd.cfg failed: {type(e).__name__}: {e}')

try:
    f.quit()
except Exception:
    pass
