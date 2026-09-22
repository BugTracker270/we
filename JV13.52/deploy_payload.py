from ftplib import FTP
import hashlib, os, sys

HOST, PORT = '172.20.10.3', 2121
NEW = r'C:\Users\Kinan\Downloads\JV13.52\pup-decrypt-1352.bin'
STALE = [
    '/data/GoldHEN/payloads/ps4-pup-decrypt.bin',
    '/data/payloads/ps4-pup-decrypt.bin',
    '/mnt/usb0/ps4-pup-decrypt.bin',
]
TARGETS = [
    '/data/GoldHEN/payloads/pup-decrypt-1352.bin',
    '/data/payloads/pup-decrypt-1352.bin',
    '/mnt/usb0/pup-decrypt-1352.bin',
]

data = open(NEW, 'rb').read()
want = hashlib.sha256(data).hexdigest().upper()
print("payload:", os.path.basename(NEW), len(data), "bytes")
print("sha256 :", want)
print()

try:
    ftp = FTP()
    ftp.connect(HOST, PORT, timeout=25)
    print("welcome:", ftp.getwelcome())
    ftp.login('anonymous', 'anonymous')
except Exception as e:
    print("CONSOLE NOT REACHABLE:", e)
    sys.exit(1)

print("\n--- removing stale payloads ---")
for p in STALE:
    try:
        ftp.delete(p)
        print("  deleted", p)
    except Exception as e:
        print("  (not present / skip)", p, e)

print("\n--- uploading new payload ---")
for t in TARGETS:
    try:
        with open(NEW, 'rb') as f:
            ftp.storbinary('STOR ' + t, f)
        print("  uploaded", t)
    except Exception as e:
        print("  FAILED", t, e)

print("\n--- verify listings ---")
for d in ['/data/GoldHEN/payloads', '/data/payloads', '/mnt/usb0']:
    print("=", d)
    try:
        ftp.dir(d, lambda line: print("   ", line))
    except Exception as e:
        print("    list error:", e)

ftp.quit()
