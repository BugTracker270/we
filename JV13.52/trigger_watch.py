#!/usr/bin/env python3
"""Trigger selfdec2 on the console and capture its output from the kernel log.

Why the 3232 log stream instead of the sd_status.txt file: GoldHEN's FTP server
accepted a connection then died on the first command (EOFError on SIZE/RETR), so
the file pull is not reliable right now. The payload calls printf_notification()
after every step and on every rejection, and those land in the kernel log that
port 3232 streams.

Order matters: the 3232 stream is LIVE-ONLY (no replay), so the reader is
connected and reading BEFORE the payload is sent to BinLoader on 9090.

Usage: trigger_watch.py [seconds]
"""
import socket, sys, threading, time, hashlib, os

HOST = '172.20.10.3'
BINLOADER = 9090
LOGSTREAM = 3232
PAYLOAD = r'C:\Users\Kinan\Downloads\JV13.52\selfdec2\selfdec2.bin'
SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 60

data = open(PAYLOAD, 'rb').read()
print('payload :', os.path.basename(PAYLOAD), len(data), 'bytes')
print('sha256  :', hashlib.sha256(data).hexdigest().upper())

buf = bytearray()
stop = threading.Event()


def reader():
    while not stop.is_set():
        s = None
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((HOST, LOGSTREAM))
            print('[log] stream connected')
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
            print(f'[log] {type(e).__name__}: {str(e)[:60]}')
            time.sleep(1)
        finally:
            try:
                if s:
                    s.close()
            except Exception:
                pass


t = threading.Thread(target=reader, daemon=True)
t.start()
time.sleep(3)                      # let the stream attach before we fire

print('\n--- sending payload to BinLoader ---')
sent = 0
try:
    s = socket.socket()
    s.settimeout(20)
    s.connect((HOST, BINLOADER))
    s.sendall(data)
    sent = len(data)
    try:
        s.shutdown(socket.SHUT_WR)
    except Exception:
        pass
    s.settimeout(6)
    reply = b''
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            reply += c
    except socket.timeout:
        pass
    s.close()
    print(f'  sent {sent}/{len(data)} bytes; reply {reply[:200]!r}')
except Exception as e:
    print(f'  FAILED: {type(e).__name__}: {e}')
    stop.set()
    raise SystemExit(2)

print(f'\n--- watching log for {SECONDS}s ---')
deadline = time.time() + SECONDS
while time.time() < deadline:
    time.sleep(2)
    if stop.is_set():
        break
stop.set()
time.sleep(0.5)

txt = buf.decode(errors='replace')
open(r'C:\Users\Kinan\Downloads\JV13.52\console_log_run8.txt',
     'w', encoding='utf-8').write(txt)
print(f'  captured {len(buf)} bytes -> console_log_run8.txt')

keys = ('selfdec2', 'selfdec', 'sd_status', 'verify', 'step 7', 'step 6',
        'target.self', 'plain.bin', 'kbase', 'ctx')
print('\n--- lines from our payload ---')
hit = False
for L in txt.splitlines():
    low = L.lower()
    if any(k in low for k in keys):
        print('  ', L[:190])
        hit = True
if not hit:
    print('   (none)')

print('\n--- last 15 lines of stream ---')
for L in txt.splitlines()[-15:]:
    print('  ', L[:190])
