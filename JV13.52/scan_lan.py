#!/usr/bin/env python3
"""Find the console: ping + probe GoldHEN FTP across the hotspot subnet."""
import socket, subprocess, concurrent.futures as cf

SUBNETS = ['172.20.10.', '172.29.32.']

def ping(ip):
    r = subprocess.run(['ping', '-n', '1', '-w', '700', ip],
                       capture_output=True, text=True)
    return r.returncode == 0

def port(ip, p, t=1.2):
    s = socket.socket(); s.settimeout(t)
    try:
        s.connect((ip, p)); return True
    except Exception:
        return False
    finally:
        s.close()

hits = []
with cf.ThreadPoolExecutor(max_workers=64) as ex:
    jobs = {}
    for base in SUBNETS:
        for i in range(1, 30):
            ip = base + str(i)
            jobs[ex.submit(ping, ip)] = ip
    for f in cf.as_completed(jobs):
        ip = jobs[f]
        try:
            if f.result():
                hits.append(ip)
        except Exception:
            pass

print("responding to ping:", sorted(hits) or "(none)")

with cf.ThreadPoolExecutor(max_workers=32) as ex:
    jobs = {}
    for ip in hits:
        for p in (2121, 3232, 80, 8080, 9295):
            jobs[ex.submit(port, ip, p)] = (ip, p)
    for f in cf.as_completed(jobs):
        ip, p = jobs[f]
        try:
            if f.result():
                print(f"  OPEN {ip}:{p}")
        except Exception:
            pass
