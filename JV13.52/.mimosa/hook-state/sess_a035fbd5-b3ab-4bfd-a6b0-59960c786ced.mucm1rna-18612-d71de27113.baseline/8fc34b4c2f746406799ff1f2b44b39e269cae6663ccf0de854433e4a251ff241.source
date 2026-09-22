"""Is there an FTP-reachable path where the console hands back DECRYPTED SELFs?

With 80010008.self they are not. But the console runs SELFs from /system/* every
boot, so its filesystem may decrypt some on read. If any reachable path returns a
plaintext ELF for a SELF, the whole payload build is unnecessary.
Cheap to test: FTP 2121 only, read-only, nothing written.
"""
import io
from ftplib import FTP

HOST, PORT = '172.20.10.3', 2121
DIRS = ['/system/common/lib', '/system/sys', '/system/priv/lib',
        '/system_ex/common_ex/lib', '/system/vsh']
SELF_MAGIC = b'\x4f\x15\x3d\x1d'
ELF_MAGIC = b'\x7fELF'

ftp = FTP()
ftp.connect(HOST, PORT, timeout=60)
print("welcome:", ftp.getwelcome())
ftp.login('anonymous', 'anonymous')

for d in DIRS:
    print(f"\n=== {d} ===")
    try:
        names = ftp.nlst(d)
    except Exception as e:
        print("   list failed:", e)
        continue

    interesting = [n for n in names
                   if n.lower().endswith(('.sprx', '.self', '.bin'))]
    print(f"   {len(names)} entries, {len(interesting)} .sprx/.self/.bin")

    counts = {'ELF': 0, 'SELF': 0, 'other': 0}
    shown = 0
    for n in interesting[:40]:
        try:
            buf = io.BytesIO()
            ftp.retrbinary(f'RETR {n}', buf.write)
            head = buf.getvalue()[:0x20]
        except Exception as e:
            print(f"   {n.split('/')[-1]:<40} read failed: {e}")
            continue
        if head[:4] == ELF_MAGIC:
            kind = 'ELF'
        elif head[:4] == SELF_MAGIC:
            kind = 'SELF'
        else:
            kind = 'other'
        counts[kind] += 1
        if shown < 8:
            print(f"   {n.split('/')[-1]:<44} {kind:<5} {head[:16].hex(' ')}")
            shown += 1
    print(f"   -> ELF:{counts['ELF']}  SELF:{counts['SELF']}  other:{counts['other']}")

ftp.quit()
print("\nIf any SELF comes back as ELF, the filesystem decrypts on read.")
