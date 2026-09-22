#!/usr/bin/env python3
"""Capture the console's debug stream (3232) to a file.

Port 3232 has no replay buffer, so this must already be connected when the
payload runs. Read-only, separate server from FTP.
"""
import socket, sys, time, os

HOST = '172.20.10.3'
PORT = 3232
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 900
OUT = r'C:\Users\Kinan\Downloads\JV13.52\capture_3232.log'

t0 = time.time()
s = socket.socket()
s.settimeout(20)
try:
    s.connect((HOST, PORT))
except Exception as e:
    print("connect failed:", type(e).__name__, e)
    sys.exit(2)

with open(OUT, 'a', encoding='utf-8', errors='replace') as f:
    f.write(f"\n===== capture start {time.strftime('%Y-%m-%d %H:%M:%S')} "
            f"(up to {DUR}s) =====\n")
    f.flush()
    while time.time() - t0 < DUR:
        try:
            s.settimeout(5)
            b = s.recv(8192)
            if not b:
                f.write("===== stream closed by console =====\n")
                f.flush()
                break
            f.write(b.decode('utf-8', 'replace'))
            f.flush()
        except socket.timeout:
            continue
        except Exception as e:
            f.write(f"===== {type(e).__name__}: {e} =====\n")
            f.flush()
            break
    f.write("===== capture end =====\n")
print("capture finished ->", OUT)
