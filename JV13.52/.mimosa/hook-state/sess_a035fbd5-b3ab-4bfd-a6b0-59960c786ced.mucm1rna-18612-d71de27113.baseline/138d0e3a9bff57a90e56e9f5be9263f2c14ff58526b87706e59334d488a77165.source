#!/usr/bin/env python3
"""Attempt 3: stage with minimum FTP, then trigger once and read the kernel log.

Order is deliberate:
  A. FTP check  - ONE connection, SIZE/SIZE/RETR only. No nlst ever.
  B. Upload     - only what phase A proves is missing/wrong, and only small files
                  (sd.cfg 50 B, target4k.self 4 KB). The 88 KB target write is what
                  took GoldHEN down on attempt 1.
  C. Attach 3232 log stream BEFORE firing, because it is live-only (no replay).
  D. Send to 9090 - the FIRST and ONLY touch of 9090 in this session. BinLoader is
     a one-shot listener; probing it with connect/close may consume it.
  E. Read the result from the log; sd_status.txt is a bonus, never a dependency.
"""
import os, socket, sys, threading, time, hashlib
from ftplib import FTP

HOST = '172.20.10.3'
LOGSTREAM, BINLOADER = 3232, 9090
ROOT = r'C:\Users\Kinan\Downloads\JV13.52'
PAYLOAD = os.path.join(ROOT, r'selfdec2\selfdec2.bin')
CFG      = os.path.join(ROOT, 'sd.cfg')
T4K      = os.path.join(ROOT, 'target4k.self')
WANT_CFG = b"maxstep=7\nlock=1\nsvcreq=0\nseg=0\nctxidx=0\nsmcall=1\n"
FULL_TARGET = os.path.getsize(os.path.join(ROOT, r'dec\1352\80010008.self'))

needs_upload = []


def ftp_conn():
    f = FTP(); f.encoding = 'latin-1'
    f.connect(HOST, 2121, timeout=45)
    f.login('anonymous', 'anonymous')
    f.voidcmd('TYPE I')
    return f


def ftp_put(local, dest, tries=3):
    size = os.path.getsize(local)
    for a in range(tries):
        f = None
        try:
            f = ftp_conn()
            with open(local, 'rb') as fh:
                f.storbinary('STOR ' + dest, fh, blocksize=8192)
            got = None
            try:
                got = f.size(dest)
            except Exception:
                pass
            try:
                f.quit()
            except Exception:
                pass
            print(f'    OK {dest} {size} B' + ('' if got in (None, size)
                                               else f'  *** remote says {got}'))
            return True
        except Exception as e:
            print(f'    retry {a+1}/{tries} {dest}: {type(e).__name__}: {str(e)[:70]}')
            time.sleep(1.5)
        finally:
            try:
                if f: f.close()
            except Exception:
                pass
    print(f'    FAIL {dest}')
    return False


# ---------------------------------------------------------------- A. FTP check
print('=== A. FTP check (1 connection, no listing) ===')
tgt_ok = False
try:
    f = ftp_conn()
    try:
        s = f.size('/data/payloads/target.self')
        tgt_ok = (s == FULL_TARGET)
        print(f'  target.self : {s} B'
              + ('  FULL - no upload needed' if tgt_ok
                 else f'  (want {FULL_TARGET}) -> will upload 4 KB version'))
    except Exception as e:
        print(f'  target.self : SIZE failed ({type(e).__name__}) -> will upload 4 KB version')
    try:
        buf = bytearray()
        f.retrbinary('RETR /data/payloads/sd.cfg', buf.extend, blocksize=8192)
        cfg_ok = (bytes(buf) == WANT_CFG)
        print(f'  sd.cfg      : {"MATCHES" if cfg_ok else "MISMATCH -> will rewrite"}')
    except Exception as e:
        cfg_ok = False
        print(f'  sd.cfg      : RETR failed ({type(e).__name__}) -> will rewrite')
    try:
        f.quit()
    except Exception:
        pass
except Exception as e:
    print(f'  FTP not usable: {type(e).__name__}: {e}')
    cfg_ok = False
print()

# ---------------------------------------------------------------- B. uploads
print('=== B. uploads (small only) ===')
if not tgt_ok:
    if not ftp_put(T4K, '/data/payloads/target.self'):
        print('  cannot place target.self - aborting BEFORE touching 9090')
        raise SystemExit(2)
if not cfg_ok:
    if not ftp_put(CFG, '/data/payloads/sd.cfg'):
        print('  cannot place sd.cfg - aborting BEFORE touching 9090')
        raise SystemExit(2)
if tgt_ok and cfg_ok:
    print('  nothing to do - both already correct')
print()

# ---------------------------------------------------------------- C. log reader
data = open(PAYLOAD, 'rb').read()
print('=== C. attaching 3232 log stream ===')
print('  payload:', os.path.basename(PAYLOAD), len(data), 'B',
      hashlib.sha256(data).hexdigest().upper()[:16])

buf = bytearray()
stop = threading.Event()


def reader():
    while not stop.is_set():
        s = None
        try:
            s = socket.socket(); s.settimeout(5)
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
                if s: s.close()
            except Exception:
                pass


threading.Thread(target=reader, daemon=True).start()
time.sleep(3)

# ---------------------------------------------------------------- D. trigger
print('\n=== D. sending to BinLoader (9090) ===')
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
    print(f'  FAILED: {type(e).__name__}: {e}')
    stop.set()
    raise SystemExit(3)

# ---------------------------------------------------------------- E. collect
print('\n=== E. watching log (50s) ===')
t_end = time.time() + 50
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

print('\n--- last 12 lines of the stream ---')
for L in txt.splitlines()[-12:]:
    print('  ', L[:190])
