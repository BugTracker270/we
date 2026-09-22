"""Stage the payload and write kmem.cfg for the full PT_LOAD 1 dump."""
import io, os, sys
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121
LOCAL = r'C:\Users\Kinan\Downloads\JV13.52\kmemdump\kmemdump.bin'
DEST = ['/mnt/usb0/kmemdump.bin',
        '/data/GoldHEN/payloads/kmemdump.bin',
        '/data/payloads/kmemdump.bin']

# exact PT_LOAD 1 of 1352k.elf: [0x1520000, 0x2834af0), 4 KiB chunks, kbase-relative
CFG = b"start=0x1520000\nend=0x2834af0\nchunk=0x1000\nabs=0\n"

size = os.path.getsize(LOCAL)
print(f"local payload: {size:,} B")
print(f"cfg:\n{CFG.decode()}")

ftp = FTP()
ftp.connect(HOST, PORT, timeout=30)
print("welcome:", ftp.getwelcome())
ftp.login('anonymous', 'anonymous')

for d in DEST:
    with open(LOCAL, 'rb') as f:
        ftp.storbinary(f'STOR {d}', f)
    print(f"  {'OK  ' if ftp.size(d) == size else 'SIZE'} {d}")

ftp.storbinary('STOR /mnt/usb0/kmem.cfg', io.BytesIO(CFG))
print("  cfg size:", ftp.size('/mnt/usb0/kmem.cfg'))

# clear last run's artifacts so anything new is unambiguous
for name in ['/mnt/usb0/kmem_img.bin', '/mnt/usb0/kmem_img.txt',
             '/mnt/usb0/kmem_status.txt']:
    try:
        ftp.delete(name); print("  deleted", name)
    except Exception as e:
        print(f"  {name}: {e}")

print("\n--- /mnt/usb0 ---")
lines = []
ftp.retrlines('LIST /mnt/usb0', lines.append)
for L in lines:
    p = L.split(None, 8)
    print(f"  {p[4]:>12}  {p[8]}" if len(p) >= 9 else "  " + L)

ftp.quit()

total = 0x2834af0 - 0x1520000
print(f"\nwindow {total:,} B = {total // 0x1000} reads of 4 KiB")
