"""Emergency disarm + config dump. FTP only (2121). Never touches 9090."""
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121
MODE = '/mnt/usb0/selfdec.mode'

ftp = FTP()
ftp.connect(HOST, PORT, timeout=20)
print("welcome:", ftp.getwelcome())
ftp.login('anonymous', 'anonymous')

print("\n--- /mnt/usb0 before ---")
try:
    for n in ftp.nlst('/mnt/usb0'):
        print("   ", n)
except Exception as e:
    print("   list error:", e)

print("\n--- DISARM: delete", MODE, "---")
try:
    ftp.delete(MODE)
    print("   deleted")
except Exception as e:
    print("   already gone / error:", e)

print("\n--- /mnt/usb0 after ---")
try:
    names = ftp.nlst('/mnt/usb0')
    for n in names:
        print("   ", n)
    print("   selfdec.mode still present?" , any(n.endswith('selfdec.mode') for n in names))
except Exception as e:
    print("   list error:", e)

print("\n--- payload copies present on console ---")
for d in ['/data/GoldHEN/payloads', '/data/payloads']:
    try:
        hits = [n for n in ftp.nlst(d) if 'selfdec' in n]
        print("   %-24s %s" % (d, hits if hits else "none"))
    except Exception as e:
        print("   %-24s error %s" % (d, e))

print("\n--- /data/GoldHEN/config.ini (autorun check) ---")
try:
    lines = []
    ftp.retrlines('RETR /data/GoldHEN/config.ini', lines.append)
    for L in lines:
        print("   ", L)
except Exception as e:
    print("   error:", e)

ftp.quit()
print("\nDONE - disarmed." if False else "\nDONE.")
