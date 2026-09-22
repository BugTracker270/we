"""Launch selfdec.bin on the console via GoldHEN's BinLoader, then watch the
console's own debug stream for the payload's output.

BinLoader executes whatever payload is sent to it. Our selfdec.bin runs
PHASE 1 (probe) ONLY unless /mnt/usb0/selfdec.mode exists - it does not.
"""
import socket, time, hashlib

HOST = '172.20.10.3'
BINLOADER = 9090
LOGSTREAM = 3232
PAYLOAD = r'C:\Users\Kinan\Downloads\JV13.52\selfdec\selfdec.bin'

data = open(PAYLOAD, 'rb').read()
print("payload:", PAYLOAD.split('\\')[-1], len(data), "bytes")
print("sha256 :", hashlib.sha256(data).hexdigest().upper())
print()

# ---------------------------------------------------------------- 1. is BinLoader up?
print("--- step 1: BinLoader reachable? ---")
try:
    t = socket.socket(); t.settimeout(4)
    t.connect((HOST, BINLOADER))
    print("  port %d OPEN" % BINLOADER)
    t.settimeout(2)
    try:
        b = t.recv(64)
        print("  banner:", repr(b))
    except socket.timeout:
        print("  no banner (waiting for payload - expected)")
    t.close()
except Exception as e:
    print("  port %d NOT reachable: %s: %s" % (BINLOADER, type(e).__name__, e))
    print("  -> cannot launch remotely. Use the GoldHEN payload menu on the console.")
    raise SystemExit(1)

# ---------------------------------------------------------------- 2. send it
print("\n--- step 2: sending payload ---")
s = socket.socket(); s.settimeout(20)
s.connect((HOST, BINLOADER))
sent = 0
try:
    s.sendall(data)
    sent = len(data)
except Exception as e:
    print("  send error after %d bytes: %s" % (sent, e))

try:
    s.shutdown(socket.SHUT_WR)
except Exception:
    pass

reply = b""
s.settimeout(6)
try:
    while True:
        c = s.recv(4096)
        if not c:
            break
        reply += c
except socket.timeout:
    pass
s.close()
print("  sent %d / %d bytes" % (sent, len(data)))
print("  reply from BinLoader:", repr(reply[:300]))

# ---------------------------------------------------------------- 3. watch the log
print("\n--- step 3: watching console debug stream (25s) ---")
time.sleep(2)
buf = b""
try:
    l = socket.socket(); l.settimeout(25)
    l.connect((HOST, LOGSTREAM))
    deadline = time.time() + 25
    while time.time() < deadline:
        try:
            l.settimeout(max(1, deadline - time.time()))
            c = l.recv(8192)
            if not c:
                break
            buf += c
        except socket.timeout:
            break
    l.close()
except Exception as e:
    print("  log stream error:", e)

txt = buf.decode(errors='replace')
print("  captured %d bytes" % len(buf))
open(r'C:\Users\Kinan\Downloads\JV13.52\console_log_after_launch.txt',
     'w', encoding='utf-8').write(txt)

print("\n--- lines mentioning our payload ---")
hit = False
for L in txt.splitlines():
    low = L.lower()
    if any(k in low for k in ("selfdec", "probe", "handle@", "ctx[", "sblreq", "kbase")):
        print("  ", L[:180]); hit = True
if not hit:
    print("   (none yet)")

print("\n--- last 25 lines of stream ---")
for L in txt.splitlines()[-25:]:
    print("  ", L[:180])
