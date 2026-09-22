"""Attach to the console's 3232 log stream and keep it, reconnecting on drops.

The v6 softlock taught us the stream has no replay buffer: if nothing is
listening when the payload runs, its output is gone forever. So this runs
BEFORE the click and stays attached.

Stops early once a KMEMv7 completion/abort marker is seen.
"""
import socket, sys, time, datetime

HOST, PORT = '172.20.10.3', 3232
OUT = r'C:\Users\Kinan\Downloads\JV13.52\console_log_v11.txt'
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 1200
STOP = [b'KMEMv7 done', b'KMEMv7 ABORT']

deadline = time.time() + DUR
tail = b''

with open(OUT, 'ab') as f:
    while time.time() < deadline:
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((HOST, PORT))
            f.write(f"\n=== capture attached {datetime.datetime.now():%H:%M:%S} ===\n".encode())
            f.flush()
            while time.time() < deadline:
                try:
                    c = s.recv(8192)
                except socket.timeout:
                    continue
                if not c:
                    break
                f.write(c)
                f.flush()
                tail = (tail + c)[-8192:]
                for m in STOP:
                    if m in tail:
                        f.write(b"\n=== stop marker seen, detaching ===\n")
                        f.flush()
                        sys.exit(0)
            s.close()
        except Exception as e:
            try:
                f.write(f"\n=== attach failed: {e} ===\n".encode())
                f.flush()
            except Exception:
                pass
            time.sleep(2)
