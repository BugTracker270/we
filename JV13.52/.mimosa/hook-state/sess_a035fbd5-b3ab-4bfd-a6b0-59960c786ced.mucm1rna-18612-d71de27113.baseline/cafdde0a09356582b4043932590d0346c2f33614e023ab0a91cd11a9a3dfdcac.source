import re, time, datetime
from ftplib import FTP

def snap():
    ftp = FTP(); ftp.connect('172.20.10.3', 2121, timeout=8); ftp.login('anonymous','anonymous')
    lines = []
    ftp.retrlines('LIST /mnt/usb0', lines.append)
    ftp.quit()
    out = {}
    for L in lines:
        m = re.match(r'\S+\s+\S+\s+\S+\s+\S+\s+(\d+)\s+\S+\s+\d+\s+\S+\s+(.+)$', L)
        if m:
            name = m.group(2).strip()
            if name in ('.','..') or name.startswith('System Volume'):
                continue
            out[name] = int(m.group(1))
    return out

print("=== t0", datetime.datetime.now().strftime('%H:%M:%S'), "===")
try:
    a = snap()
    for k, v in sorted(a.items()):
        print("   %-32s %d" % (k, v))
except Exception as e:
    print("   FTP problem:", type(e).__name__, e)
    a = {}

dec = [k for k in a if k.endswith('.dec')]
print("\n   .dec files present:", dec if dec else "NONE YET")

if dec:
    time.sleep(12)
    print("\n=== t1 (+12s) ===")
    try:
        b = snap()
        for k in sorted(b):
            if k.endswith('.dec'):
                delta = b[k] - a.get(k, 0)
                print("   %-32s %d   (+%d in 12s -> %s)" % (k, b[k], delta,
                      "WRITING" if delta > 0 else "stalled/finished"))
    except Exception as e:
        print("   second read failed:", type(e).__name__)

print("\n=== monitor log tail ===")
try:
    with open(r'C:\Users\Kinan\Downloads\JV13.52\monitor_usb.log', encoding='utf-8', errors='replace') as f:
        for line in f.readlines()[-10:]:
            print("   " + line.rstrip())
except Exception as e:
    print("   log read failed:", e)
