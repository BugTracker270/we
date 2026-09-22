#!/usr/bin/env python3
"""Show a payload .bin's PT_LOAD segments: filesz vs memsz.

A large gap between filesz and memsz is .bss. Run 4's build (27388 B) worked and
had NO big static buffer. Runs 5 and 6 both added an 8 KB `static char`
and both crash with no output at all. If a homebrew launcher sizes its module
allocation from p_filesz, or has a fixed budget, an 8 KB .bss bump is exactly
the kind of change that breaks loading before a single line of the module runs.
"""
import struct, sys

p = sys.argv[1] if len(sys.argv) > 1 else \
    r'C:\Users\Kinan\Downloads\JV13.52\selfdec2\selfdec2.bin'
d = open(p, 'rb').read()
print(f"{p}\n  file size {len(d)} ({len(d):#x})")

if d[:4] != b'\x7fELF':
    print("  not an ELF")
    sys.exit(1)

e_phoff = struct.unpack_from('<Q', d, 0x20)[0]
e_phentsize = struct.unpack_from('<H', d, 0x36)[0]
e_phnum = struct.unpack_from('<H', d, 0x38)[0]
print(f"  e_phoff={e_phoff:#x} e_phentsize={e_phentsize:#x} e_phnum={e_phnum}\n")

tot_f = tot_m = 0
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from('<II', d, o)
    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
        struct.unpack_from('<QQQQQQ', d, o + 8)
    kind = {1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 6: 'PHDR'}.get(
        p_type, str(p_type))
    print(f"  [{i}] type={kind:8s} flags={p_flags:#x} off={p_offset:#x} "
          f"vaddr={p_vaddr:#x} filesz={p_filesz:#x} memsz={p_memsz:#x} "
          f"gap={p_memsz - p_filesz:#x}")
    if p_type == 1:
        tot_f += p_filesz
        tot_m += p_memsz

print(f"\n  total LOAD filesz={tot_f:#x}  memsz={tot_m:#x}  "
      f"bss={tot_m - tot_f:#x} ({(tot_m - tot_f)} bytes)")
