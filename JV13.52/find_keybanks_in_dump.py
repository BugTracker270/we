"""Search the 19.1 MB kernel .data/.bss dump for the 80010008 key banks.

Two independent tests:
  1. Al-Azif's exact key-bank / signature-bank SHA-256 signatures (definitive).
  2. The structural bank terminator pattern (broader net, no hash needed).
Plus module-name strings, to see what the SBL has loaded.
"""
import hashlib, re, struct, time, collections

DUMP = r'C:\Users\Kinan\Downloads\JV13.52\v11_kmem_img.bin'
KOFF = 0x1520000

KEY_T = {
    "keybank 0x00": "7cf7a6ecbd0eae8ee0ff4a703ee8f21acfc733344e45ba6ee293ff443edb336e",
    "keybank 0x01": "693d2637a3c69993388a3b869ada0b0f175bd9cb04d5b1b7d4408484a8865e17",
    "keybank 0x02": "29ae7d829d778dd37b435e679bc367034674e1924fc55c811d9a64a0577d7452",
    "sigbank 0x00": "d96c2d1981af473fd51d0b0b30169b2e75205540414e6a147ac3e25f8921e97a",
    "sigbank 0x01": "c05badfff635bfe8f900f1cc18d8029cf5894062227bb8c89698c6e047b5cc3d",
    "sigbank 0x02": "cfdd6bd305adef79ebbebb82dd252a93c4d3f2df5d09210d7de3f6fcf60927e5",
}

d = open(DUMP, 'rb').read()
print(f"dump {len(d):,} B covering koff 0x{KOFF:x}..0x{KOFF+len(d):x}")

print("\n=== 1. exact key-bank signatures ===")
t0 = time.time()
hits = []
sha = hashlib.sha256
for i in range(len(d) - 15):
    t = KEY_T.get(sha(d[i:i + 16]).hexdigest())
    if t:
        hits.append((i, t))
print(f"  {len(hits)} hits (brute-forced {len(d):,} windows in {time.time()-t0:.1f}s)")
for off, t in hits:
    print(f"    !! {t}  at file 0x{off:x}  koff 0x{KOFF+off:x}")

print("\n=== 2. bank terminator shape ===")
pat = re.compile(rb'....\x00\x01\x00\x00....\x08\x00\x00\x00....\x00\x01\x00\x00', re.S)
th = [m.start() for m in pat.finditer(d)]
print(f"  {len(th)} matches")
for h in th[:25]:
    print(f"    file 0x{h:x}  koff 0x{KOFF+h:x}")

print("\n=== 3. secure-module names present ===")
for m in re.finditer(rb'8001000[0-9A-F]', d):
    print(f"    koff 0x{KOFF+m.start():x}  {m.group().decode()}")

print("\n=== 4. interesting strings ===")
for m in re.finditer(rb'[\x20-\x7e]{8,}', d):
    s = m.group().decode()
    if any(k in s for k in ('8001000', 'authmgr', 'AuthMgr', 'sbl', 'Sbl',
                            'SBL', '.self', 'SELF', 'keybank', 'key_bank',
                            'eap', 'EAP', 'kernel', 'Kernel')):
        print(f"    koff 0x{KOFF+m.start():x}  {s[:100]}")

print("\n=== 5. kernel .text function-pointer census (targets of qwords) ===")
KBASE = 0xffffffff85680000          # from this run's kmem_img.txt
TEXT_END = KBASE + 0xcfe758
c = collections.Counter()
for off in range(0, len(d) - 8, 8):
    v = struct.unpack_from('<Q', d, off)[0]
    if KBASE <= v < TEXT_END:
        c[(v - KBASE) & ~0xf] += 1
print(f"  distinct .text targets: {len(c)}")
for koff, n in c.most_common(15):
    print(f"    0x{koff:x}  x{n}")
