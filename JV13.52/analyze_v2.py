"""Analyse the v2 probe log + identify what the handle window's pointers point at."""
import re

LOG = r'C:\Users\Kinan\Downloads\JV13.52\console_log_probe.txt'
txt = open(LOG, 'rb').read().decode('utf-8', errors='replace')

print("=== raw F lines (repr, so nothing is hidden) ===")
for L in txt.splitlines():
    if 'F ' in L and 'NOTIFICATION' in L:
        tail = L.split('NOTIFICATION]:', 1)[-1]
        print("   ", repr(tail))

print("\n=== H lines ===")
for L in txt.splitlines():
    if 'H0 ' in L or 'H20 ' in L or 'H40 ' in L or 'H60 ' in L:
        print("   ", L.split('NOTIFICATION]:', 1)[-1])

# ---------------------------------------------------------------- static image
P = r"C:\Users\Kinan\Downloads\czdji0\1352k.elf"
data = open(P, "rb").read()
BASE = 0xffffffff82200000
LIVE = 0xffffffff9f8d4000

print("\n=== what the window's kernel pointers point at (koff, then bytes) ===")
ptrs = [0xffffffffa03c1e79, 0xffffffffa03c1e84, 0xffffffffa03c18f0]
for p in ptrs:
    ko_live = p - LIVE
    print(f"\n  ptr {p:#x}  -> live koff {ko_live:#x}")
    o = ko_live
    if 0 <= o < len(data):
        chunk = data[o:o+48]
        print("     bytes:", chunk.hex())
        print("     repr :", repr(chunk))
    else:
        print("     outside file")

print("\n=== ctx[0] buffer decode (SELF header?) ===")
import struct
qw = [0x120101001d3d154f, 0x03d003d000000101, 0x00000000006755d0, 0x0000000000220008]
raw = b"".join(struct.pack("<Q", q) for q in qw)
hdr = struct.unpack_from("<IBBBB I HH Q HH I", raw, 0)
print(f"  magic       0x{hdr[0]:08X}   (SELF_MAGIC=0x1D3D154F)")
print(f"  version     {hdr[1]}")
print(f"  mode        {hdr[2]}")
print(f"  endianness  {hdr[3]}")
print(f"  attr        0x{hdr[4]:02x}")
print(f"  key_type    0x{hdr[5]:08X}")
print(f"  header_size 0x{hdr[6]:04x}")
print(f"  meta_size   0x{hdr[7]:04x}")
print(f"  file_size   {hdr[8]:#x}  ({hdr[8]} bytes)")
print(f"  num_entries {hdr[9]}")
print(f"  flags       0x{hdr[10]:04x}")
