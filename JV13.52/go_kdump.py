#!/usr/bin/env python3
"""Fire kmemdump v10 at the console and capture the ladder result.

Modelled on go_run8.py, which is the deploy pattern that actually works here:
  - attach the 3232 log stream FIRST (it is live-only, no replay)
  - send the payload to 9090 exactly once (BinLoader is a one-shot listener;
    probing it with connect/close may consume it)
  - NO FTP. kmemdump v10 needs nothing staged: its config and output all live
    on the USB stick (/mnt/usb0/...). FTP stays untouched.

RUN 1 (this script): USB has NO kmem.cfg -> v10 uses its built-in defaults
  (128 KiB window at kbase+0x02680000, the region v9 already proved readable).
  That is the safe probe. We want one number out of it: "ladder max=".

RUN 2 (after): copy kmem.cfg to the USB root and run this again.
"""
import os
import socket
import threading
import time
import hashlib

HOST = '172.20.10.3'          # edit if the console IP changed
LOGSTREAM = 3232
BINLOADER = 9090
ROOT = r'C:\Users\Kinan\Downloads\JV13.52'
PAYLOAD = os.path.join(ROOT, r'kmemdump\kmemdump.bin')
WATCH = 90                    # seconds to collect after firing

data = open(PAYLOAD, 'rb').read()
print('=== kmemdump deploy ===')
print('  payload :', os.path.basename(PAYLOAD), len(data), 'B',
      hashlib.sha256(data).hexdigest().upper()[:16])
print('  target  :', f'{HOST}:{BINLOADER}', '(log', f'{HOST}:{LOGSTREAM})')
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
out = os.path.join(ROOT, 'kmem_run1.log')
open(out, 'w', encoding='utf-8').write(txt)
print(f'  captured {len(buf)} bytes -> {os.path.basename(out)}')

print('\n--- KMEMv10 lines ---')
hit = False
for L in txt.splitlines():
    if 'kmem' in L.lower() or 'ladder' in L.lower():
        print('  ', L[:190])
        hit = True
if not hit:
    print('   (none seen)')

print('\n--- last 12 lines of the stream ---')
for L in txt.splitlines()[-12:]:
    print('  ', L[:190])

print('\nNEXT: pull the USB stick and send me /mnt/usb0/kmem_img.txt')
print('      (it contains the "ladder max=" number we need for run 2).')
