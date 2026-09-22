"""Exact runtime-mapped ranges of the 13.52 kernel, from its own program headers.

kmemdump walked [kbase+0x1520000, ...) in 128 KiB chunks and the console died.
This tells us which addresses are actually mapped, i.e. the first chunk that
could have faulted.
"""
import struct, os

PATH = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KBASE = 0xffffffff82200000
CHUNK = 0x20000

d = open(PATH, 'rb').read()
assert d[:4] == b'\x7fELF', 'not an ELF'

e_phoff, = struct.unpack_from('<Q', d, 0x20)
e_phentsize, e_phnum = struct.unpack_from('<HH', d, 0x36)
e_entry, = struct.unpack_from('<Q', d, 0x18)

print(f"file       {os.path.getsize(PATH):,} B")
print(f"entry      0x{e_entry:x}   (relative to kbase: 0x{e_entry - KBASE:x})")
print(f"phoff 0x{e_phoff:x}  phentsize {e_phentsize}  phnum {e_phnum}")
print()
print(f"{'type':<12}{'off':>12}{'vaddr':>18}{'koff':>12}{'filesz':>12}{'memsz':>12}{'flags':>7}")
loads = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
        struct.unpack_from('<IIQQQQQQ', d, o)
    if p_type != 1:            # PT_LOAD only
        continue
    koff = p_vaddr - KBASE
    loads.append((koff, p_offset, p_vaddr, p_filesz, p_memsz, p_flags))
    nm = {5: 'R-X', 6: 'RW-', 7: 'RWX', 4: 'R--'}.get(p_flags, hex(p_flags))
    print(f"PT_LOAD     {p_offset:>12x}{p_vaddr:>18x}{koff:>12x}"
          f"{p_filesz:>12x}{p_memsz:>12x}{nm:>7}")

loads.sort()
print()
prev_end = None
for koff, p_offset, vaddr, filesz, memsz, flags in loads:
    end = koff + memsz
    tag = ""
    if prev_end is not None and koff > prev_end:
        tag = f"   <-- GAP of 0x{koff - prev_end:x} bytes before this, NOT mapped"
    print(f"mapped koff 0x{koff:08x} .. 0x{end:08x}  (0x{memsz:x} bytes){tag}")
    prev_end = end

print()
print("=== kmemdump chunk-by-chunk, first 0x%x bytes ===" % (CHUNK * 8))
start = 0x1520000
for i in range(64):
    a = start + i * CHUNK
    b = a + CHUNK
    inside = any(koff <= a and b <= koff + memsz for koff, _, _, _, memsz, _ in loads)
    print(f"  chunk {i:>3}  0x{a:08x}..0x{b:08x}  {'OK' if inside else '*** OUTSIDE EVERY PT_LOAD ***'}")
    if not inside:
        break
