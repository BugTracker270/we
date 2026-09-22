"""Print the first 8 bytes at each derived function offset in 1352k.elf.
These are what the v2 probe must read back on hardware."""
P = r"C:\Users\Kinan\Downloads\czdji0\1352k.elf"
data = open(P, "rb").read()

# .text segment: file offset == koff  (PH[2]: off=0, vaddr=0xffffffff82200000)
FNS = [
    ("mailbox", 0x00630230),
    ("smreq  ", 0x0063fff0),
    ("authhdr", 0x00642c90),
    ("load   ", 0x006434d0),
    ("fin    ", 0x00643370),
    ("isload ", 0x00642880),
]
print("expected first 8 bytes (from 1352k.elf):")
for n, ko in FNS:
    b = data[ko:ko + 8]
    print(f"  F {n} {b.hex()}")

print("\nexpected 0x80-byte window at koff 0x0269C0A0 (file offset 0x01b265e8+... ):")
ko = 0x0269C0A0
# this koff is past file-backed .data (0x01b265e8) -> .bss, not in the image
print(f"  koff {ko:#x} > file-backed end 0x01b265e8 -> .bss, no static value")
print("  (this is why the handle read as 0/unknown; the window dump is the way to see it)")
