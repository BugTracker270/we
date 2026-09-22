"""Wait for the console, then stage kmemdump.bin for the launchpad.

FTP only (2121). Never touches 9090 (BinLoader is a one-shot listener).
"""
import os, socket, sys, time
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121
LOCAL = r'C:\Users\Kinan\Downloads\JV13.52\kmemdump\kmemdump.bin'
DEST = ['/mnt/usb0/kmemdump.bin',
        '/data/GoldHEN/payloads/kmemdump.bin',
        '/data/payloads/kmemdump.bin']

WAIT_S = int(sys.argv[1]) if len(sys.argv) > 1 else 210


def up(timeout=3.0):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((HOST, PORT))
        s.recv(80)
        return True
    except Exception:
        return False
    finally:
        s.close()


print(f"waiting up to {WAIT_S}s for {HOST}:{PORT} ...")
t0 = time.time()
while time.time() - t0 < WAIT_S:
    if up():
        print(f"  console UP after {time.time() - t0:.1f}s")
        break
    time.sleep(3)
else:
    print("  still down - console not booted yet. Re-run this script.")
    sys.exit(2)

if not os.path.exists(LOCAL):
    print("missing local payload:", LOCAL)
    sys.exit(3)

size = os.path.getsize(LOCAL)
print(f"\nlocal payload: {LOCAL} ({size:,} B)")

ftp = FTP()
ftp.connect(HOST, PORT, timeout=30)
print("welcome:", ftp.getwelcome())
ftp.login('anonymous', 'anonymous')

for dest in DEST:
    try:
        with open(LOCAL, 'rb') as f:
            ftp.storbinary(f'STOR {dest}', f)
        got = ftp.size(dest)
        ok = (got == size)
        print(f"  {'OK  ' if ok else 'SIZE'} {dest}  remote={got}")
    except Exception as e:
        print(f"  FAIL {dest}: {e}")

print("\n--- /mnt/usb0 ---")
try:
    for n in ftp.nlst('/mnt/usb0'):
        print("   ", n)
except Exception as e:
    print("   ", e)
print("--- /data/GoldHEN/payloads ---")
try:
    for n in ftp.nlst('/data/GoldHEN/payloads'):
        print("   ", n)
except Exception as e:
    print("   ", e)

ftp.quit()
print("\nstaged. Start the live log capture BEFORE clicking.")
