#!/usr/bin/env python3
"""Poll 2121 and 3232 until GoldHEN's stack answers. NEVER touches 9090.

9090 is BinLoader and appears to be one-shot, so it is not probed here; the
payload send must be its first contact.
"""
import socket, sys, time

HOST = '172.20.10.3'
LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 90

t0 = time.time()
last = ''
while time.time() - t0 < LIMIT:
    res = []
    for p in (2121, 3232):
        s = socket.socket(); s.settimeout(4)
        try:
            s.connect((HOST, p))
            res.append(f'{p}:OPEN')
        except Exception as e:
            res.append(f'{p}:{type(e).__name__}')
        finally:
            s.close()
    line = '  '.join(res)
    if line != last:
        print(f'[{int(time.time()-t0):3d}s] {line}', flush=True)
        last = line
    if all(r.endswith('OPEN') for r in res):
        print('GoldHEN stack is up.')
        raise SystemExit(0)
    time.sleep(3)

print('timed out - GoldHEN (or the console) is not answering')
raise SystemExit(1)
