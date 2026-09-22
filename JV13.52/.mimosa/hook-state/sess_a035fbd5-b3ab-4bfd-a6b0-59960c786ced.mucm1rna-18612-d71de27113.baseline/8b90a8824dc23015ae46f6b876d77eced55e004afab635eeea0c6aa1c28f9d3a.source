#!/usr/bin/env python3
"""Poll the console until GoldHEN's FTP (2121) is back. Never touches 9090."""
import socket, sys, time

HOST = '172.20.10.3'
LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 120

def open_(port, t=3.0):
    s = socket.socket()
    s.settimeout(t)
    try:
        s.connect((HOST, port))
        return True
    except Exception:
        return False
    finally:
        s.close()

t0 = time.time()
last = None
while time.time() - t0 < LIMIT:
    f = open_(2121)
    l = open_(3232)
    state = (f, l)
    if state != last:
        print(f"  t={time.time()-t0:5.1f}s  ftp2121={'OPEN ' if f else 'closed'}  "
              f"log3232={'OPEN ' if l else 'closed'}", flush=True)
        last = state
    if f:
        s = socket.socket(); s.settimeout(4)
        s.connect((HOST, 2121))
        print("  banner:", s.recv(120))
        s.close()
        print("GoldHEN FTP is UP.")
        sys.exit(0)
    time.sleep(3)

print("timed out waiting for GoldHEN FTP.")
sys.exit(1)
