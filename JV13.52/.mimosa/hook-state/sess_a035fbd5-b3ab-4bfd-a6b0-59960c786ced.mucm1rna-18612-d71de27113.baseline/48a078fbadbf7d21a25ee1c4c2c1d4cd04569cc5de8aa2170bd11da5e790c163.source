"""Capture the console's debug/log stream on 3232 and identify what 9090 is."""
import socket, datetime

HOST = '172.20.10.3'

# ---- 3232 : log stream
print("=== 3232 : reading for 8s ===")
buf = b""
try:
    s = socket.socket()
    s.settimeout(8)
    s.connect((HOST, 3232))
    while True:
        try:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            break
    s.close()
except Exception as e:
    print("error:", e)

txt = buf.decode(errors="replace")
print(f"received {len(buf)} bytes")
path = r"C:\Users\Kinan\Downloads\JV13.52\console_log_3232.txt"
open(path, "w", encoding="utf-8").write(txt)
print("saved:", path)

print("\n--- first 60 lines ---")
for L in txt.splitlines()[:60]:
    print("  ", L[:160])

print("\n--- lines mentioning decrypt / SELF / auth / elf ---")
seen = set()
for L in txt.splitlines():
    low = L.lower()
    if any(k in low for k in ("self", "auth", "decrypt", "elf", "kernel", "goldhen", "payload")):
        if L not in seen:
            seen.add(L)
            print("  ", L[:170])

# ---- 9090 : what is it
print("\n=== 9090 : HTTP probe ===")
try:
    s = socket.socket()
    s.settimeout(4)
    s.connect((HOST, 9090))
    s.sendall(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % HOST.encode())
    d = b""
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            d += c
            if len(d) > 8192: break
    except socket.timeout:
        pass
    s.close()
    print(f"  got {len(d)} bytes")
    print("  ", d[:400])
except Exception as e:
    print("  error:", e)
