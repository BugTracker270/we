"""Search the 8 MB arena dump at 0xffffc18716000000 for the AuthMgr key banks."""
import hashlib, re, struct, time

DUMP = r'C:\Users\Kinan\Downloads\JV13.52\v12_kmem_img.bin'
BASE = 0xffffc18716000000

KEY_T = {
    "keybank 0x00": "7cf7a6ecbd0eae8ee0ff4a703ee8f21acfc733344e45ba6ee293ff443edb336e",
    "keybank 0x01": "693d2637a3c69993388a3b869ada0b0f175bd9cb04d5b1b7d4408484a8865e17",
    "keybank 0x02": "29ae7d829d778dd37b435e679bc367034674e1924fc55c811d9a64a0577d7452",
    "sigbank 0x00": "d96c2d1981af473fd51d0b0b30169b2e75205540414e6a147ac3e25f8921e97a",
    "sigbank 0x01": "c05badfff635bfe8f900f1cc18d8029cf5894062227bb8c89698c6e047b5cc3d",
    "sigbank 0x02": "cfdd6bd305adef79ebbebb82dd252a93c4d3f2df5d09210d7de3f6fcf60927e5",
}

d = open(DUMP, 'rb').read()
print(f"arena dump {len(d):,} B covering 0x{BASE:x}..0x{BASE+len(d):x}")

print("\n=== 1. exact key-bank / sig-bank signatures ===")
t0 = time.time()
hits = []
sha = hashlib.sha256
for i in range(len(d) - 15):
    t = KEY_T.get(sha(d[i:i + 16]).hexdigest())
    if t:
        hits.append((i, t))
print(f"  {len(hits)} hits in {time.time()-t0:.1f}s")
for off, t in hits:
    print(f"    !! {t} at 0x{BASE+off:x}")

print("\n=== 2. bank terminator shape ===")
pat = re.compile(rb'....\x00\x01\x00\x00....\x08\x00\x00\x00....\x00\x01\x00\x00', re.S)
th = [m.start() for m in pat.finditer(d)]
print(f"  {len(th)} matches")
for h in th[:20]:
    print(f"    at 0x{BASE+h:x}")

print("\n=== 3. ELF headers ===")
n = 0
for m in re.finditer(rb'\x7fELF', d):
    n += 1
    if n <= 10:
        print(f"    at 0x{BASE+m.start():x}")
print(f"  total {n}")

print("\n=== 4. SELF magic 4f 15 3d 1d ===")
n = 0
for m in re.finditer(rb'\x4f\x15\x3d\x1d', d):
    n += 1
    if n <= 10:
        print(f"    at 0x{BASE+m.start():x}")
print(f"  total {n}")

print("\n=== 5. secure-module name strings ===")
for m in re.finditer(rb'8001[0-9A-Fa-f]{4}', d):
    print(f"    0x{BASE+m.start():x}  {m.group().decode()}")

print("\n=== 6. printable strings >= 10 chars (first 60) ===")
c = 0
for m in re.finditer(rb'[\x20-\x7e]{10,}', d):
    c += 1
    if c <= 60:
        print(f"    0x{BASE+m.start():x}  {m.group().decode()[:100]}")
print(f"  total {c}")
