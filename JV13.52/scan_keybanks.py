"""Offline scan for Al-Azif's 80010008 SELF key-bank / signature-bank signatures.

80010008.py identifies key banks by the SHA-256 of each bank's FIRST 0x10 bytes.
Those three hashes are constants of the key material, so if the plaintext AuthMgr
(or anything else carrying the SELF keys) is already sitting in a file we hold,
we can find it with no console involvement at all.

Pure read. Nothing here touches the console.
"""
import hashlib, os, sys, time

KEY_T = {
    "keybank 0x00": "7cf7a6ecbd0eae8ee0ff4a703ee8f21acfc733344e45ba6ee293ff443edb336e",
    "keybank 0x01": "693d2637a3c69993388a3b869ada0b0f175bd9cb04d5b1b7d4408484a8865e17",
    "keybank 0x02": "29ae7d829d778dd37b435e679bc367034674e1924fc55c811d9a64a0577d7452",
    "sigbank 0x00": "d96c2d1981af473fd51d0b0b30169b2e75205540414e6a147ac3e25f8921e97a",
    "sigbank 0x01": "c05badfff635bfe8f900f1cc18d8029cf5894062227bb8c89698c6e047b5cc3d",
    "sigbank 0x02": "cfdd6bd305adef79ebbebb82dd252a93c4d3f2df5d09210d7de3f6fcf60927e5",
}
# the bank body always terminates with this shape at the start of the next slot
TERM = bytes.fromhex("0000010008000000")

CANDIDATES = [
    r'C:\Users\Kinan\Downloads\czdji0\1352k.elf',
    r'C:\Users\Kinan\Downloads\czdji0\1350.elf',
    r'C:\Users\Kinan\Downloads\czdji0\1302.elf',
    r'C:\Users\Kinan\Downloads\czdji0\kernel1304.elf',
    r'C:\Users\Kinan\Downloads\czdji0\1150k.elf',
    r'C:\Users\Kinan\Downloads\JV13.52\dec\unpacked1\secure_modules.bin',
    r'C:\Users\Kinan\Downloads\JV13.52\dec\unpacked1\eap_fs_image.img',
    r'C:\Users\Kinan\Downloads\JV13.52\dec\unpacked1\system_fs_image.img',
    r'C:\Users\Kinan\Downloads\JV13.52\dec\unpacked1\torus2_firmware.bin',
    r'C:\Users\Kinan\Downloads\JV13.52\dec\unpacked1\wlan_firmware.bin',
    r'C:\Users\Kinan\Downloads\JV13.52\dec\PS4UPDATE1.PUP.dec',
    r'C:\Users\Kinan\Downloads\JV13.52\libkernel.sprx',
    r'C:\Users\Kinan\Downloads\JV13.52\libc.sprx',
    r'C:\Users\Kinan\Downloads\bd-j-usr-main (1)\bd-j-usr-main\1352-hunt\dumps\libkernel_sys_13.52.bin',
]

MAX = 200 * 1024 * 1024
REPORT = r'C:\Users\Kinan\Downloads\JV13.52\keybank_scan.txt'


def scan(path):
    if not os.path.exists(path):
        return f"MISSING"
    sz = os.path.getsize(path)
    if sz < 64:
        return f"too small ({sz} B)"
    if sz > MAX:
        return f"SKIPPED (too large: {sz:,} B)"
    t0 = time.time()
    with open(path, 'rb') as f:
        d = f.read()
    hits = []
    n = len(d) - 15
    sha = hashlib.sha256
    for i in range(n):
        h = sha(d[i:i + 16]).hexdigest()
        t = KEY_T.get(h)
        if t:
            hits.append((i, t))
    # second, cheaper structural probe: bank terminator shape
    terms = []
    p = 0
    while True:
        p = d.find(TERM, p)
        if p < 0:
            break
        terms.append(p)
        p += 1
    dt = time.time() - t0
    msg = f"{sz:>12,} B  scanned in {dt:5.1f}s  exact-keybank-hits={len(hits)}  terminator-hits={len(terms)}"
    if hits:
        msg += "\n" + "\n".join(f"        !! {t} at offset 0x{off:X}" for off, t in hits)
    return msg


lines = []
lines.append("=== offline key-bank scan ===")
for p in CANDIDATES:
    r = scan(p)
    line = f"{os.path.basename(p):<34} {r}"
    print(line, flush=True)
    lines.append(line)

open(REPORT, 'w', encoding='utf-8').write("\n".join(lines) + "\n")
print("\nsaved:", REPORT)
