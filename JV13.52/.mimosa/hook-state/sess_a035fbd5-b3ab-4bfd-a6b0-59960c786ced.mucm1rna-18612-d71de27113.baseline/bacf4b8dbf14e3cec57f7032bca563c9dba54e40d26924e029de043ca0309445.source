"""Fetch GoldHEN config and the loader log to find the launch mechanism."""
import io
from ftplib import FTP

HOST = '172.20.10.3'
ftp = FTP()
ftp.connect(HOST, 2121, timeout=20)
ftp.login('anonymous', 'anonymous')

def fetch(path, maxbytes=12000):
    buf = io.BytesIO()
    try:
        ftp.retrbinary('RETR ' + path, buf.write)
    except Exception as e:
        return None, str(e)
    d = buf.getvalue()
    return d, None

for path in ['/data/GoldHEN/config.ini', '/data/Loader_Logs.txt']:
    d, err = fetch(path)
    print("=" * 70)
    print(path, "->", "ERROR " + err if err else f"{len(d)} bytes")
    print("=" * 70)
    if d:
        try:
            txt = d.decode('utf-8', errors='replace')
        except Exception:
            txt = repr(d[:2000])
        lines = txt.splitlines()
        if path.endswith('Loader_Logs.txt') and len(lines) > 80:
            print(f"[showing last 80 of {len(lines)} lines]")
            lines = lines[-80:]
        for L in lines[:200]:
            print("  ", L[:180])
    print()

ftp.quit()
