#!/usr/bin/env python3
"""Resilient capture of the console debug stream (3232).

Observed behaviour: 3232 delivers its buffered backlog on connect and then the
console closes the socket. So this loops: connect, drain until close, reconnect.
Runs for DUR seconds total.
"""
import socket, sys, time

HOST = '172.20.10.3'
PORT = 3232
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 900
OUT = (sys.argv[2] if len(sys.argv) > 2
       else r'C:\Users\Kinan\Downloads\JV13.52\capture_3232.log')

t0 = time.time()
f = open(OUT, 'a', encoding='utf-8', errors='replace')
f.write(f"\n===== reconnecting capture start {time.strftime('%H:%M:%S')} "
        f"({DUR}s) =====\n")
f.flush()

conns = 0
while time.time() - t0 < DUR:
    s = socket.socket()
    s.settimeout(8)
    try:
        s.connect((HOST, PORT))
    except Exception as e:
        f.write(f"--- connect failed: {type(e).__name__} ---\n"); f.flush()
        time.sleep(3)
        continue
    conns += 1
    while time.time() - t0 < DUR:
        try:
            b = s.recv(8192)
            if not b:
                break
            f.write(b.decode('utf-8', 'replace'))
            f.flush()
        except socket.timeout:
            continue
        except Exception:
            break
    try:
        s.close()
    except Exception:
        pass
    time.sleep(0.5)

f.write(f"===== capture end after {conns} connections =====\n")
f.close()
print("capture finished", OUT)
