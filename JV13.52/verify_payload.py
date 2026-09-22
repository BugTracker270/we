import os, hashlib

NEW = r'C:\Users\Kinan\Downloads\JV13.52\build\ps4-pup-decrypt\src.bin'
OLD = r'C:\Users\Kinan\Downloads\JV13.52\ps4-pup-decrypt.bin'

def load(p):
    with open(p, 'rb') as f:
        return f.read()

n, o = load(NEW), load(OLD)
print("NEW:", os.path.basename(NEW), len(n), "bytes  sha256", hashlib.sha256(n).hexdigest())
print("OLD:", os.path.basename(OLD), len(o), "bytes  sha256", hashlib.sha256(o).hexdigest())
print("NEW first16:", n[:16].hex(' '))
print("OLD first16:", o[:16].hex(' '))
print()

checks = [
    'Unsupported firmware',
    'Running PS4 PUP Decrypter',
    'Finished PS4 PUP Decrypter',
    'PUP Decrypter: start',
    'pup_update0 fd=',
    'ABORT: pup_update0 not accessible',
    'uid=%d sandbox=%d jb=%d',
    '/mnt/usb0/safe.PS4UPDATE.PUP',
    '/dev/pup_update0',
]
print("%-42s %-10s %s" % ("string", "NEW", "OLD"))
for s in checks:
    print("%-42s %-10s %s" % (s, "PRESENT" if s.encode() in n else "absent",
                             "PRESENT" if s.encode() in o else "absent"))
print()
# kpayload/jailbreak symbols must be gone from the new build
for sym in [b'build_kpayload', b'kpayload_jailbreak', b'kexec', b'jailbreak']:
    print("%-24s NEW=%s  OLD=%s" % (sym.decode(),
          sym in n, sym in o))
