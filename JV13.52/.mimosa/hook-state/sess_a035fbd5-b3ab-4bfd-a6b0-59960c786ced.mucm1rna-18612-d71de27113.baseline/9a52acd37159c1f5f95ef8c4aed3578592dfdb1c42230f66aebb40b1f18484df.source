from ftplib import FTP
import hashlib, io

LOCAL = r'C:\Users\Kinan\Downloads\JV13.52\pup-decrypt-1352.bin'
want = hashlib.sha256(open(LOCAL, 'rb').read()).hexdigest().upper()

ftp = FTP()
ftp.connect('172.20.10.3', 2121, timeout=25)
ftp.login('anonymous', 'anonymous')

for path in ['/data/GoldHEN/payloads/pup-decrypt-1352.bin',
             '/data/payloads/pup-decrypt-1352.bin',
             '/mnt/usb0/pup-decrypt-1352.bin']:
    buf = io.BytesIO()
    ftp.retrbinary('RETR ' + path, buf.write)
    got = hashlib.sha256(buf.getvalue()).hexdigest().upper()
    print("%-46s %7d B  %s" % (path, len(buf.getvalue()), "OK - identical" if got == want else "MISMATCH " + got))

# confirm no stale copies remain anywhere
print("\nremaining 'ps4-pup-decrypt.bin' copies (should be none):")
for d in ['/data/GoldHEN/payloads', '/data/payloads', '/mnt/usb0']:
    names = ftp.nlst(d)
    hits = [n for n in names if n.endswith('ps4-pup-decrypt.bin')]
    print("  %-24s %s" % (d, hits if hits else "none"))

print("\nUSB state:")
for n in ftp.nlst('/mnt/usb0'):
    print("  ", n)
ftp.quit()
