"""Extract raw bytes for a kernel VA from 1352k.elf using its own program headers.

objdump refused the file ("file format not recognized"), so instead of relying on
its ELF reader we resolve VA->file offset ourselves and disassemble the slice as
flat x86-64.
"""
import struct, sys

PATH = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KBASE = 0xffffffff82200000
OUT = r'C:\Users\Kinan\Downloads\JV13.52\func_slice.bin'

d = open(PATH, 'rb').read()
e_machine, = struct.unpack_from('<H', d, 0x12)
print(f"e_ident class={d[4]} data={d[5]} version={d[6]}")
print(f"e_machine=0x{e_machine:x}  e_type=0x{struct.unpack_from('<H', d, 0x10)[0]:x}")

e_phoff, = struct.unpack_from('<Q', d, 0x20)
e_phentsize, e_phnum = struct.unpack_from('<HH', d, 0x36)

loads = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
        struct.unpack_from('<IIQQQQQQ', d, o)
    if p_type == 1:
        loads.append((p_vaddr, p_offset, p_filesz, p_memsz))
        print(f"  LOAD vaddr=0x{p_vaddr:x} p_offset=0x{p_offset:x} "
              f"filesz=0x{p_filesz:x} memsz=0x{p_memsz:x}")

def foff(va):
    for vaddr, poff, fsz, msz in loads:
        if vaddr <= va < vaddr + fsz:
            return poff + (va - vaddr)
    return None

# sceSblAuthMgrSmRequest @ koff 0x63FFF0
START = KBASE + 0x63FFC0
END = KBASE + 0x640280
fo = foff(START)
print(f"\nVA 0x{START:x} -> file offset 0x{fo:x}")
raw = d[fo:fo + (END - START)]
open(OUT, 'wb').write(raw)
print(f"wrote {len(raw)} bytes to {OUT}")
