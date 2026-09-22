"""Are any local .sprx/.self files PLAINTEXT ELF or still SELF?

If plaintext ELF: the console does hand back decrypted SELFs somehow, and that
route is worth chasing for 80010008 rather than building a payload.
"""
import os, glob

SELF = b'\x4f\x15\x3d\x1d'
ELF = b'\x7fELF'


def kind(h):
    if h[:4] == ELF:
        return 'ELF (PLAINTEXT)'
    if h[:4] == SELF:
        return 'SELF (encrypted)'
    return 'other'


print("=== local .sprx / .self in the working dir ===")
for pat in ('*.sprx', '*.self', '*.prx', '*.sbin'):
    for f in glob.glob(pat):
        d = open(f, 'rb').read(0x40)
        print(f"  {f:<28} {os.path.getsize(f):>10,}  {kind(d):<18} {d[:16].hex(' ')}")

print("\n=== every .sprx under Downloads ===")
n = 0
for root, dirs, files in os.walk(r'C:\Users\Kinan\Downloads'):
    dirs[:] = [x for x in dirs if x not in ('.git', 'node_modules')]
    for fn in files:
        if fn.endswith('.sprx'):
            fp = os.path.join(root, fn)
            try:
                h = open(fp, 'rb').read(4)
            except Exception:
                continue
            print(f"  {kind(h + b'    ')[:16]:<18} {fp}")
            n += 1
            if n > 40:
                print("  ... truncated")
                raise SystemExit
print(f"  total {n}")
