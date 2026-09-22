#!/usr/bin/env python3
"""Fire the payload with ZERO FTP use, and read the result from the log stream.

Rationale: GoldHEN's FTP server dies on its first data command and takes GoldHEN
with it, so FTP is off the critical path entirely. Staging from attempt 1 should
still be present in /data/payloads (it persists across reboots and that STOR was
verified at 50 B for sd.cfg).

GoldHEN's liveness is checked **through 3232 only** - the very stream this script
needs anyway. 2121 is not touched (its data commands are the killer) and 9090 is
not touched until the real send, because BinLoader is a one-shot listener.

The payload itself reports whether the target was found ("self=<n>B hdr=..." in
printf_notification, and sd_status.txt), so this single send answers both
"is staging intact" and "what is rd[9]".
"""
import os, socket, sys, threading, time, hashlib

HOST = '172.20.10.3'
LOGSTREAM, BINLOADER = 3232, 9090
ROOT = r'C:\Users\Kinan\Downloads\JV13.52'
SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 55
PAYLOAD = (sys.argv[2] if len(sys.argv) > 2
           else os.path.join(ROOT, r'selfdec2\selfdec2.bin'))

data = open(PAYLOAD, 'rb').read()
print('payload:', os.path.basename(PAYLOAD), len(data), 'B',
      hashlib.sha256(data).hexdigest().upper()[:16])

buf = bytearray()
stop = threading.Event()
attached = threading.Event()


def reader():
    while not stop.is_set():
        s = None
        try:
            s = socket.socket(); s.settimeout(5)
            s.connect((HOST, LOGSTREAM))
            attached.set()
            print('[log] 3232 connected -> GoldHEN is up')
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
            if not stop.is_set() and not attached.is_set():
                print(f'[log] 3232 unavailable: {type(e).__name__}')
                time.sleep(1)
        finally:
            try:
                if s: s.close()
            except Exception:
                pass


threading.Thread(target=reader, daemon=True).start()
if not attached.wait(timeout=12):
    print('3232 never came up - GoldHEN is not running. Not touching 9090.')
    stop.set()
    raise SystemExit(2)

time.sleep(2)                      # make sure we are well inside the stream

print('\n--- sending payload to BinLoader 9090 (first and only touch) ---')
try:
    s = socket.socket(); s.settimeout(20)
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
            if not c: break
            rep += c
    except socket.timeout:
        pass
    s.close()
    print(f'  sent {len(data)} B; reply {rep[:160]!r}')
except Exception as e:
    print(f'  FAILED to reach 9090: {type(e).__name__}: {e}')
    stop.set()
    raise SystemExit(3)

print(f'\n--- watching log for {SECONDS}s ---')
t_end = time.time() + SECONDS
while time.time() < t_end:
    time.sleep(2)
stop.set()
time.sleep(0.5)

txt = buf.decode(errors='replace')
out = os.path.join(ROOT, 'console_log_run8.txt')
open(out, 'w', encoding='utf-8').write(txt)
print(f'  captured {len(buf)} bytes -> {os.path.basename(out)}')

keys = ('selfdec2', 'sd_status', 'verify', 'step ', 'target.self',
        'plain.bin', 'kbase', 'ctx', 'self=')
print('\n--- our payload\'s lines ---')
hit = False
for L in txt.splitlines():
    low = L.lower()
    if any(k in low for k in keys):
        print('  ', L[:190]); hit = True
if not hit:
    print('   (none seen)')

print('\n--- last 12 lines of stream ---')
for L in txt.splitlines()[-12:]:
    print('  ', L[:190])
