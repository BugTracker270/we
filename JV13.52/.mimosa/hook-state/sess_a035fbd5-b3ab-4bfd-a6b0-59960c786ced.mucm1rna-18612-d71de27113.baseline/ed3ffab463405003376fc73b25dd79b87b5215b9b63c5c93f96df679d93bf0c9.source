"""Deploy selfdec.bin to the console over its FTP server.

Same route the previous session used for pup-decrypt-1352.bin:
upload to /data/GoldHEN/payloads, /data/payloads and /mnt/usb0, then verify by hash.

SAFETY: this script deliberately does NOT create /mnt/usb0/selfdec.mode.
Without that file the payload runs PHASE 1 (probe) ONLY and cannot attempt
the kernel decrypt path. If a selfdec.mode already exists on the USB it is
reported and removed.
"""
from ftplib import FTP
import hashlib, os, sys, io

HOST, PORT = '172.20.10.3', 2121
LOCAL = r'C:\Users\Kinan\Downloads\JV13.52\selfdec\selfdec.bin'

STALE = [
    '/data/GoldHEN/payloads/ps4-pup-decrypt.bin',
    '/mnt/usb0/selfdec.mode',              # must not exist for a probe run
]
TARGETS = [
    '/data/GoldHEN/payloads/selfdec.bin',
    '/data/payloads/selfdec.bin',
    '/mnt/usb0/selfdec.bin',
]

data = open(LOCAL, 'rb').read()
want = hashlib.sha256(data).hexdigest().upper()
print("payload:", os.path.basename(LOCAL), len(data), "bytes")
print("sha256 :", want)
print()

try:
    ftp = FTP()
    ftp.connect(HOST, PORT, timeout=25)
    print("welcome:", ftp.getwelcome())
    ftp.login('anonymous', 'anonymous')
except Exception as e:
    print("CONSOLE NOT REACHABLE at %s:%d -> %s: %s" % (HOST, PORT, type(e).__name__, e))
    print()
    print("Console is probably off, not jailbroken, or on a different network.")
    sys.exit(1)

print("\n--- current state ---")
for d in ['/data/GoldHEN/payloads', '/data/payloads', '/mnt/usb0']:
    try:
        names = ftp.nlst(d)
        print("  %-24s %d entries" % (d, len(names)))
        for n in names:
            base = n.split('/')[-1]
            if any(k in base.lower() for k in ('selfdec', 'pup', 'decrypt', 'mode', 'target')):
                print("      ->", base)
    except Exception as e:
        print("  %-24s list error: %s" % (d, e))

print("\n--- removing blockers ---")
for p in STALE:
    try:
        ftp.delete(p)
        print("  deleted", p)
    except Exception as e:
        print("  (not present) ", p)

print("\n--- uploading ---")
for t in TARGETS:
    try:
        with open(LOCAL, 'rb') as f:
            ftp.storbinary('STOR ' + t, f)
        print("  uploaded", t)
    except Exception as e:
        print("  FAILED  ", t, e)

print("\n--- verify (sha256 round-trip) ---")
ok = 0
for t in TARGETS:
    try:
        buf = io.BytesIO()
        ftp.retrbinary('RETR ' + t, buf.write)
        got = hashlib.sha256(buf.getvalue()).hexdigest().upper()
        match = (got == want)
        ok += match
        print("  %-44s %7d B  %s" % (t, len(buf.getvalue()),
                                     "OK identical" if match else "MISMATCH " + got))
    except Exception as e:
        print("  %-44s RETR FAILED %s" % (t, e))

print("\n%d/%d verified" % (ok, len(TARGETS)))

print("\n--- /mnt/usb0 contents ---")
try:
    ftp.retrlines('LIST /mnt/usb0', lambda L: print("   ", L))
except Exception as e:
    print("    list error:", e)

ftp.quit()
print("\nDONE. Payload is staged. It now needs to be LAUNCHED from the console")
print("(GoldHEN payload menu) - that part cannot be done over FTP.")
