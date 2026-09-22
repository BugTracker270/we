#!/usr/bin/env python3
"""Capture the console's live debug stream while selfdec2 runs, then pull the
result files back over FTP and check them.

Port 3232 has NO replay buffer, so the capture has to already be running when
the payload is launched. Start this, then launch selfdec2 from GoldHEN.

Only 2121 (FTP) and 3232 (log) are touched. Never 9090.
"""
import os, socket, sys, threading, time, hashlib
from ftplib import FTP

HOST = '172.20.10.3'
LOG3232 = 3232
CAPTURE_S = int(sys.argv[1]) if len(sys.argv) > 1 else 180
ROOT = r'C:\Users\Kinan\Downloads\JV13.52'
OUTLOG = os.path.join(ROOT, 'console_log_sd.txt')

TARGET_LOCAL = os.path.join(ROOT, r'dec\1352\80010008.self')

PULL = ['/data/payloads/sd_status.txt',
        '/data/payloads/sd_hdr20.bin',
        '/data/payloads/plain.bin']

buf = bytearray()
stop = threading.Event()


def cap():
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((HOST, LOG3232))
        print("  [3232] connected, capturing...", flush=True)
        s.settimeout(2)
        t0 = time.time()
        while not stop.is_set() and time.time() - t0 < CAPTURE_S:
            try:
                c = s.recv(8192)
                if not c:
                    break
                buf.extend(c)
            except socket.timeout:
                continue
        s.close()
    except Exception as e:
        print(f"  [3232] {type(e).__name__}: {e}", flush=True)


print(f"capturing port {LOG3232} for {CAPTURE_S}s - LAUNCH selfdec2 NOW")
th = threading.Thread(target=cap, daemon=True)
th.start()

# wait until the payload's first notification shows up, then keep going a bit
seen = False
t0 = time.time()
while time.time() - t0 < CAPTURE_S:
    if not seen and b'selfdec2' in bytes(buf):
        seen = True
        print("  payload detected in stream", flush=True)
    time.sleep(1)
stop.set()
th.join(timeout=5)

txt = bytes(buf).decode(errors='replace')
with open(OUTLOG, 'w', encoding='utf-8') as f:
    f.write(txt)
print(f"\ncaptured {len(buf)} bytes -> {OUTLOG}")

print("\n--- selfdec2 lines ---")
hit = False
for L in txt.splitlines():
    if 'selfdec2' in L.lower():
        print("  ", L[:190])
        hit = True
if not hit:
    print("   (no selfdec2 lines captured - payload not launched, or launched "
          "before the capture started)")

# ---------------------------------------------------------------- pull results
print("\n--- pulling results over FTP ---")
got = {}
for dest in PULL:
    for attempt in range(3):
        try:
            f = FTP()
            f.encoding = 'latin-1'
            f.connect(HOST, 2121, timeout=60)
            f.login('anonymous', 'anonymous')
            f.voidcmd('TYPE I')
            local = os.path.join(ROOT, os.path.basename(dest))
            with open(local, 'wb') as fh:
                f.retrbinary(f'RETR {dest}', fh.write)
            f.quit()
            size = os.path.getsize(local)
            print(f"  OK   {dest} -> {local}  ({size:,} B)")
            got[dest] = local
            break
        except Exception as e:
            print(f"  retry {attempt+1}/3 {dest}: {type(e).__name__}: {e}")
            time.sleep(1)
    else:
        print(f"  ABSENT {dest}")

# ---------------------------------------------------------------- verify
st = got.get('/data/payloads/sd_status.txt')
if st:
    print("\n--- sd_status.txt ---")
    print(open(st, encoding='utf-8', errors='replace').read())

h = got.get('/data/payloads/sd_hdr20.bin')
if h and os.path.exists(TARGET_LOCAL):
    a = open(h, 'rb').read()
    b = open(TARGET_LOCAL, 'rb').read()[:0x20]
    print("\n--- copyin/copyout round-trip check ---")
    print("  from kernel:", a.hex())
    print("  on disk    :", b.hex())
    if a == b:
        print("  MATCH - copyin and copyout both work end to end")
    else:
        print("  MISMATCH - investigate before trusting later steps")

p = got.get('/data/payloads/plain.bin')
if p and os.path.exists(TARGET_LOCAL):
    pd = open(p, 'rb').read()
    print(f"\n--- plain.bin ({len(pd):,} B) ---")
    tgt = open(TARGET_LOCAL, 'rb').read()
    seg = tgt[0x13e0:0x13e0 + 0x10f9c]
    print("  first 0x20 encrypted:", seg[:0x20].hex())
    print("  first 0x20 returned :", pd[:0x20].hex())
    if pd[:0x20] == seg[:0x20]:
        print("  IDENTICAL -> the SM did not decrypt (or we copied the wrong thing)")
    else:
        print("  DIFFERENT -> decryption happened")
    print("  sha256:", hashlib.sha256(pd).hexdigest())
