"""Re-check the console: is it alive, and is any payload listener up now?"""
import socket, time
from ftplib import FTP

HOST = '172.20.10.3'
PORTS = [2121, 3232, 9090, 9091, 9020, 9021, 9022, 9092]

def try_port(p, tmo=2.0):
    s = socket.socket(); s.settimeout(tmo)
    try:
        s.connect((HOST, p))
        b = b""
        try:
            s.settimeout(1.0); b = s.recv(80)
        except Exception:
            pass
        return True, b
    except Exception as e:
        return False, type(e).__name__
    finally:
        s.close()

print("--- console alive? (FTP) ---")
try:
    f = FTP(); f.connect(HOST, 2121, timeout=10); f.login('anonymous', 'anonymous')
    print("  FTP OK:", f.getwelcome())
    f.quit()
except Exception as e:
    print("  FTP FAILED:", e)

print("\n--- port sweep, 3 passes over 15s ---")
for rnd in range(3):
    print(f"\n  pass {rnd+1}:")
    for p in PORTS:
        ok, info = try_port(p)
        print(f"    {p:5} {'OPEN' if ok else 'closed':7} {info if not ok else repr(info)}")
    if rnd < 2:
        time.sleep(6)
