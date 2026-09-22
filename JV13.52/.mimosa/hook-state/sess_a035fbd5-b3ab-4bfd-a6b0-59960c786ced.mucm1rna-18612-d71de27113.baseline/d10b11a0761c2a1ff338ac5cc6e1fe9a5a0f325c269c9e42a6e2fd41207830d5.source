#!/usr/bin/env python3
"""Extract everything the kernel SELFs expose in the clear, and check whether
every keyset-1.4 module on hand names the same key bank.
"""
import glob
import os
import re
import struct

A = r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\80010002.self'
B = r'C:\Users\Kinan\Downloads\JV13.52\dec\80010002_kernel_14.00.self'


def elf_hdr(d, base):
    e = d[base:base + 0x40]
    if e[:4] != b'\x7fELF':
        return None
    ei_class, ei_data = e[4], e[5]
    e_type, e_machine, e_version = struct.unpack_from('<HHI', e, 0x10)
    e_entry, e_phoff, e_shoff = struct.unpack_from('<QQQ', e, 0x18)
    e_flags, e_ehsize, e_phentsize, e_phnum = struct.unpack_from('<IHHH', e, 0x30)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', e, 0x3A)
    return dict(cls=ei_class, data=ei_data, type=e_type, machine=e_machine,
                entry=e_entry, phoff=e_phoff, shoff=e_shoff, flags=e_flags,
                ehsize=e_ehsize, phentsize=e_phentsize, phnum=e_phnum,
                shentsize=e_shentsize, shnum=e_shnum, shstrndx=e_shstrndx)


def phdrs(d, base, h):
    out = []
    for i in range(h['phnum']):
        off = base + h['phoff'] + i * h['phentsize']
        p_type, p_flags = struct.unpack_from('<II', d, off)
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
            struct.unpack_from('<QQQQQQ', d, off + 8)
        out.append(dict(type=p_type, flags=p_flags, offset=p_offset,
                        vaddr=p_vaddr, paddr=p_paddr, filesz=p_filesz,
                        memsz=p_memsz, align=p_align))
    return out


print('=' * 74)
print('SELF header fields (plaintext, no key needed)')
print('=' * 74)
for nm, f in (('13.52', A), ('14.00', B)):
    d = open(f, 'rb').read(0x400)
    magic, verb, mode, endian, attr = struct.unpack_from('<IBBBB', d, 0)
    key_type, = struct.unpack_from('<I', d, 0x08)
    hdr, meta = struct.unpack_from('<HH', d, 0x0C)
    fsz, = struct.unpack_from('<Q', d, 0x10)
    nent, flags = struct.unpack_from('<HH', d, 0x18)
    print(f'\n[{nm}] {os.path.basename(f)}')
    print(f'  magic            {magic:#010x}   key_type/keyset {key_type:#06x}  '
          f'(0x0c01 = keyset 1.4)')
    print(f'  version {verb:#x}  mode {mode:#x}  endian {endian}  attr {attr:#x}')
    print(f'  header_size {hdr:#x}  metadata_size {meta:#x}  '
          f'body starts {hdr + meta:#x}')
    print(f'  file_size {fsz}  num_entries {nent}  flags {flags:#x}')
    print(f'  (u64 @0x30) {struct.unpack_from("<Q", d, 0x30)[0]}   '
          f'(u64 @0x38) {struct.unpack_from("<Q", d, 0x38)[0]}')

    eh = elf_hdr(d, 0x40)
    print(f'  embedded ELF @0x40:')
    m = {0x3e: 'x86-64', 0x03: 'i386', 0x28: 'ARM', 0xb7: 'AArch64'}.get(
        eh['machine'], hex(eh['machine']))
    t = {2: 'ET_EXEC', 3: 'ET_DYN'}.get(eh['type'], hex(eh['type']))
    print(f'    class {eh["cls"]} (2=ELF64)  data {eh["data"]} (1=LSB)  '
          f'type {t}  machine {m}')
    print(f'    e_entry     {eh["entry"]:#x}')
    print(f'    e_phoff     {eh["phoff"]:#x}   e_phentsize {eh["phentsize"]:#x}  '
          f'e_phnum {eh["phnum"]}')
    print(f'    e_shoff     {eh["shoff"]:#x}   e_shnum {eh["shnum"]}')
    for i, p in enumerate(phdrs(d, 0x40, eh)):
        fl = ''.join(c for b, c in ((4, 'R'), (2, 'W'), (1, 'X')) if p['flags'] & b)
        print(f'    phdr[{i}] type {p["type"]:#x} flags {p["flags"]:#x} ({fl}) '
              f'off {p["offset"]:#x} vaddr {p["vaddr"]:#x} '
              f'filesz {p["filesz"]:#x} memsz {p["memsz"]:#x} align {p["align"]:#x}')

print()
print('=' * 74)
print('Strings in the plaintext metadata region (0x100 - 0x2c0)')
print('=' * 74)
for nm, f in (('13.52', A), ('14.00', B)):
    d = open(f, 'rb').read(0x2c0)
    found = re.findall(rb'[ -~]{5,}', d[0x100:0x2c0])
    print(f'[{nm}] {[s.decode() for s in found]}')

print()
print('=' * 74)
print('key_type across every keyset-1.4 module on hand')
print('=' * 74)
for f in sorted(glob.glob(r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\*.self')):
    d = open(f, 'rb').read(0x20)
    kt, = struct.unpack_from('<I', d, 0x08)
    nent, = struct.unpack_from('<H', d, 0x18)
    print(f'  {os.path.basename(f):<22} key_type {kt:#06x}  entries {nent}')
d = open(B, 'rb').read(0x20)
kt, = struct.unpack_from('<I', d, 0x08)
print(f'  {"80010002_kernel_14.00":<22} key_type {kt:#06x}  entries 1')
