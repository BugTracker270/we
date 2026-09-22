#!/usr/bin/env python3
"""Fire kmemfull v1 — the full 13.52 kernel image dump.

Same deploy discipline as go_kdump.py / go_run8.py, which is the pattern that
works on this console:
  - attach the 3232 log stream FIRST (live-only, no replay)
  - send the payload to 9090 EXACTLY ONCE (BinLoader is a one-shot listener;
    connect/close probing can consume it)
  - NO FTP. kmemfull needs nothing staged: config and output live on the USB.

The console keeps dumping after we stop listening, so a short watch window does
not abort the payload — it only ends our view of it. The durable record is
/mnt/usb0/kmemfull.txt on the stick.
"""
import os
import socket
import threading
import time
import hashlib

HOST = '172.20.10.3'
LOGSTREAM = 3232
BINLOADER = 9090
ROOT = r'C:\Users\Kinan\Downloads\JV13.52'
PAYLOAD = os.path.join(ROOT, r'kmemfull\kmemfull.bin')
WATCH = 180

data = open(PAYLOAD, 'rb').read()
print('=== kmemfull deploy ===')
print('  payload :', os.path.basename(PAYLOAD), len(data), 'B',
      hashlib.sha256(data).hexdigest().upper()[:16])
print('  range   : kbase+0x0 .. kbase+0x1b265e8  (28.5 MB)')
print('  chunk   : 0x1000 default (override via /mnt/usb0/kmemfull.cfg)')
print()

buf = bytearray()
stop = threading.Event()


def reader():
    while not stop.is_set():
        s = None
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((HOST, LOGSTREAM))
            print('  [log] connected')
            s.settimeout(3)
            while not stop.is_set():
                try:
                    c = s.recv(8192)
                    if not c:
                        break
                    buf.extend(c)
                except socket.timeout:
                    continue
        except Exception as e:
            if not stop.is_set():
                print(f'  [log] {type(e).__name__}: {str(e)[:60]}')
                time.sleep(1)
        finally:
            try:
                if s:
                    s.close()
            except Exception:
                pass


print('=== A. attaching 3232 log stream ===')
threading.Thread(target=reader, daemon=True).start()
time.sleep(3)

print('\n=== B. sending to BinLoader (9090) ===')
try:
    s = socket.socket()
    s.settimeout(20)
    s.connect((HOST, BINLOADER))
    s.sendall(data)
    try:
        s.shutdown(socket.SHUT_WR)
    except Exception:
        pass
    s.settimeout(5)
    rep = b''
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            rep += c
    except socket.timeout:
        pass
    s.close()
    print(f'  sent {len(data)} B; reply {rep[:160]!r}')
except Exception as e:
    print(f'  FAILED: {type(e).__name__}: {e}')
    stop.set()
    raise SystemExit(3)

print(f'\n=== C. watching log ({WATCH}s) ===')
t_end = time.time() + WATCH
while time.time() < t_end:
    time.sleep(2)
stop.set()
time.sleep(0.5)

txt = buf.decode(errors='replace')
out = os.path.join(ROOT, 'kmemfull_run.log')
open(out, 'w', encoding='utf-8').write(txt)
print(f'  captured {len(buf)} bytes -> {os.path.basename(out)}')

print('\n--- KMEMFULL lines ---')
hit = False
for L in txt.splitlines():
    if 'kmemfull' in L.lower():
        print('  ', L[:190])
        hit = True
if not hit:
    print('   (none seen)')

print('\n--- last 12 lines ---')
for L in txt.splitlines()[-12:]:
    print('  ', L[:190])

print('\nNEXT: pull the USB. You want /mnt/usb0/kmemfull.bin (28.5 MB image)')
print('      and /mnt/usb0/kmemfull.txt (reads_ok + holes).')
