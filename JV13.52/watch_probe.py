"""Watch for selfdec's output on the console's own debug stream (port 3232).

The console runs a log channel on 3232 that mirrors printf_notification(). It
replays its ring buffer on connect, so we do NOT have to be connected at the
exact moment the payload runs - connect afterwards and read the buffer.

Also tails /mnt/usb0 over FTP for any file the payload writes.

Usage:  python watch_probe.py [seconds]
"""
import socket, time, sys, re
from ftplib import FTP

HOST = '172.20.10.3'
SECS = int(sys.argv[1]) if len(sys.argv) > 1 else 12

MARKERS = ("selfdec", "probe", "handle@", "ctx[", "sblreq", "kbase",
           "stage=", "entries=", "wrote target")

print("=" * 68)
print(f"reading console log stream {HOST}:3232 for {SECS}s")
print("=" * 68)

buf = b""
last = 0
deadline = time.time() + SECS
try:
    s = socket.socket(); s.settimeout(SECS)
    s.connect((HOST, 3232))
    while time.time() < deadline:
        try:
            s.settimeout(max(1.0, deadline - time.time()))
            c = s.recv(16384)
            if not c:
                break
            buf += c
        except socket.timeout:
            break
    s.close()
except Exception as e:
    print("stream error:", e)

txt = buf.decode(errors="replace")
open(r'C:\Users\Kinan\Downloads\JV13.52\console_log_probe.txt', 'w',
     encoding='utf-8').write(txt)
print(f"captured {len(buf)} bytes -> console_log_probe.txt")

hit = [L for L in txt.splitlines()
       if any(m in L.lower() for m in MARKERS)]
print(f"\n--- {len(hit)} line(s) matching selfdec output ---")
for L in hit[-40:]:
    print("  ", L[:200])
if not hit:
    print("   (none - payload has not run, or ran before the buffer window)")

print("\n--- tail of stream ---")
for L in txt.splitlines()[-12:]:
    print("  ", L[:160])

print("\n--- /mnt/usb0 ---")
try:
    f = FTP(); f.connect(HOST, 2121, timeout=12); f.login('anonymous', 'anonymous')
    for L in f.nlst('/mnt/usb0'):
        b = L.split('/')[-1]
        if any(k in b.lower() for k in ('selfdec', 'target', 'mode')):
            print("   ", b)
    print("    (full listing suppressed; checking for selfdec/target/mode)")
    f.quit()
except Exception as e:
    print("    FTP error:", e)
