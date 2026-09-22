"""Safe liveness check. Touches ONLY 2121 (FTP) and 3232 (log stream).

Deliberately does NOT touch 9090: every connect to BinLoader consumes its
single-shot listener. Do not add it back.
"""
import socket, datetime, io

HOST = '172.20.10.3'
LOG3232 = r'C:\Users\Kinan\Downloads\JV13.52\console_log_3232.txt'

now = datetime.datetime.now().strftime('%H:%M:%S')
print(f"=== check_alive @ {now} ===")

# ---- 2121 FTP : is the kernel/filesystem still scheduling?
print("\n[2121 FTP]")
ftp_ok = False
try:
    s = socket.socket()
    s.settimeout(6)
    s.connect((HOST, 2121))
    banner = s.recv(160)
    print("  OPEN  banner:", banner[:80])
    ftp_ok = True
    s.close()
except Exception as e:
    print("  FAIL ", type(e).__name__, e)

# ---- 3232 log stream : drain whatever is buffered
print("\n[3232 log stream]")
buf = b""
try:
    s = socket.socket()
    s.settimeout(6)
    s.connect((HOST, 3232))
    while True:
        try:
            c = s.recv(8192)
            if not c:
                break
            buf += c
            if len(buf) > 262144:
                break
        except socket.timeout:
            break
    s.close()
    print(f"  OPEN  received {len(buf)} bytes")
except Exception as e:
    print("  FAIL ", type(e).__name__, e)

txt = buf.decode(errors='replace')
if txt:
    with open(LOG3232, 'a', encoding='utf-8') as f:
        f.write(f"\n=== drained {now} ===\n")
        f.write(txt)
    print("  appended to", LOG3232)
    print("\n--- tail of stream ---")
    for L in txt.splitlines()[-40:]:
        print("   ", L[:170])
else:
    print("  (nothing buffered - stream is live-only, no replay)")

print("\nVERDICT:",
      "console ALIVE (kernel still scheduling)" if ftp_ok
      else "console DEAD / frozen - needs power cycle")
