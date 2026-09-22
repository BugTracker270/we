"""Look for a remote-launch mechanism: GoldHEN autoload dirs, config, and what 9090 is."""
import socket
from ftplib import FTP

HOST = '172.20.10.3'

ftp = FTP()
ftp.connect(HOST, 2121, timeout=20)
ftp.login('anonymous', 'anonymous')

def ls(path, label):
    print(f"\n=== {label}  ({path}) ===")
    try:
        for L in ftp.nlst(path):
            print("   ", L)
    except Exception as e:
        print("    error:", e)

for p, lbl in [('/', 'root'),
               ('/data', '/data'),
               ('/data/GoldHEN', '/data/GoldHEN'),
               ('/data/GoldHEN/payloads', 'GoldHEN payloads')]:
    ls(p, lbl)

# look for autoload / config style names
print("\n=== scanning for autoload / config ===")
for base in ('/data/GoldHEN', '/data', '/mnt/usb0', '/user/data'):
    try:
        for n in ftp.nlst(base):
            b = n.split('/')[-1].lower()
            if any(k in b for k in ('auto', 'config', 'ini', 'cfg', 'boot', 'startup', 'loader')):
                print("   FOUND:", n)
    except Exception as e:
        print(f"   ({base}: {e})")

ftp.quit()

print("\n=== 9090 HTTP probe ===")
try:
    s = socket.socket()
    s.settimeout(5)
    s.connect((HOST, 9090))
    s.sendall(b"GET / HTTP/1.0\r\nHost: 172.20.10.3\r\n\r\n")
    d = b""
    try:
        while len(d) < 4096:
            c = s.recv(1024)
            if not c: break
            d += c
    except socket.timeout:
        pass
    s.close()
    print("  bytes:", len(d))
    print("  repr:", d[:300])
except Exception as e:
    print("  error:", e)
