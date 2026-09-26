#!/usr/bin/env python3
"""SUCCESSOR SESSION 2026-09-22 — offset-mapping tests (HANDOFF §12.8 #2).

Establishes the mapping between:
  (a) the raw13g chain's RVAs  (measured from the reference kernel_1352k.elf,
      rebased base 0xffffffff82200000, per ps4_offsets.js fw_status)
  (b) our flat live image kmemfull.bin  (kbase-relative offsets, 0x0..0x1b265e8)
  (c) v11_kmem_img.bin  (live dump of 0x1520000..0x2834af0, earlier boot)

Candidate hypotheses, all testable with byte evidence:
  H1  naive:      ours = rva
  H2  +0x800000:  ours = rva + 0x800000   (ORBISYS anchor: ref 0xd20000 -> ours 0x1520000)
  H3  +0x680000:  ours = rva + 0x680000   (SELF PT_LOAD p_vaddr; refuted for 13.50 vals
                                           by test_base_convention.py, retest for 13.52 vals)
  H4  ref file = ours[0x800000:0x1b265e8] exactly (ref size 0x13265e8 == ours-0x800000):
      then chain RVAs (vaddr-based) need the ref phdrs; but we can at least test whether
      ours[0x800000:] looks like the ref ELF container (ELF magic at 0x800000).
"""
import struct, sys, hashlib

D = open('kmemfull.bin', 'rb').read()
V11 = open('../v11_kmem_img.bin', 'rb').read()
V11_BASE = 0x1520000          # kbase-relative start of the v11 dump
OURS_END = len(D)             # 0x1b265e8
print(f'kmemfull.bin   {len(D):#x} bytes')
print(f'v11_kmem_img   {len(V11):#x} bytes  covers {V11_BASE:#x}..{V11_BASE+len(V11):#x}')
print(f'v11 covers ours end {OURS_END:#x}?  {V11_BASE+len(V11) > OURS_END}')
print(f'v11 covers 0x2400000 (kdump5 tier1 36MB)?  {V11_BASE+len(V11) > 0x2400000}')

def hdr(off, name):
    if off + 0x40 > len(D):
        print(f'{name}: beyond dump'); return
    b = D[off:off+0x40]
    magic = b[:4] == b'\x7fELF'
    print(f'{name} @ {off:#x}: magic={magic}  first16={b[:16].hex(" ")}')
    if magic:
        ecls, edata, ever, eosabi = b[4], b[5], b[6], b[7]
        e_type, e_machine = struct.unpack_from('<HH', b, 0x10)
        e_entry, e_phoff, e_shoff = struct.unpack_from('<QQQ', b, 0x18)
        e_phnum = struct.unpack_from('<H', b, 0x38)[0]
        print(f'    class={ecls} osabi={eosabi} type={e_type:#x} machine={e_machine:#x}')
        print(f'    entry={e_entry:#x} phoff={e_phoff:#x} phnum={e_phnum} shoff={e_shoff:#x}')

print('\n=== ELF headers in our image ===')
hdr(0x0,      'ours 0x0     (image header)')
hdr(0x680000, 'ours 0x680000(SELF PT_LOAD vaddr)')
hdr(0x800000, 'ours 0x800000(H4 ref container start)')

print('\n=== bytes at candidate gadget offsets (13.52 k_jmp_rsi = 0x4d6d0) ===')
def peek(off, n=8, src=D, base=0, label=''):
    if 0 <= off-base < len(src)-(n-1):
        print(f'  {label or "ours"} {off:#010x}: {src[off-base:off-base+n].hex(" ")}')
    else:
        print(f'  {label or "ours"} {off:#010x}: <out of range>')
for hyp_name, sh in (('H1 naive', 0x0), ('H2 +0x800000', 0x800000), ('H3 +0x680000', 0x680000)):
    print(f'-- {hyp_name} --')
    peek(0x4d6d0 + sh)                      # 13.52 jmp_rsi
    peek(0x47b31 + sh)                      # 13.50/13.00 jmp_rsi (different kernel, expect NO)
    peek(0xe6c60 + sh, n=16)                # 13.52 kl_lock  (data object expected)
    peek(0x1102b70 + sh, n=48)              # 13.52 sysent base (stride 0x30 table)
    peek(0x785228 + sh, n=16)               # 13.52 evf_cv
    peek(0x3fa8e0 + sh, n=16)               # 13.52 sysctl_handle_int (.text fn)
    peek(0x1c1e00 + sh, n=16)               # 13.52 idt_rsvd
    peek(0x1a5c0c0 + sh, n=16)              # 13.52 prison0

print('\n=== v11 coverage of the out-of-range chain offsets (naive & shifted) ===')
for name, rva in (('k_rootvnode', 0x2136e90), ('k_arg1_maxfiles', 0x22cc474),
                  ('k_arg1_maxprocperuid', 0x22cc478), ('k_arg1_maxfilesperproc', 0x22cc47c),
                  ('patch site 0x1b77a3', 0x1b77a3)):
    for hyp_name, sh in (('H1', 0x0), ('H2', 0x800000), ('H3', 0x680000)):
        kbr = rva + sh
        peek(kbr, 16, V11, V11_BASE, f'v11 {name} {hyp_name}')

print('\n=== v11 vs kmemfull overlap consistency (same firmware check) ===')
# v11[i] == kmemfull[0x1520000 + i] for the file-backed overlap 0x1520000..0x1b265e8
ov = OURS_END - V11_BASE
a = D[V11_BASE:OURS_END]
b = V11[:ov]
ident = sum(1 for i in range(0, ov, 4096) if a[i:i+4096] == b[i:i+4096])
tot = (ov + 4095)//4096
print(f'overlap {V11_BASE:#x}..{OURS_END:#x} ({ov:#x} B): {ident}/{tot} 4KiB blocks identical '
      f'({100.0*ident/tot:.1f}%)  <- expect ~100% if same FW (file-backed .data)')
bad = [i for i in range(0, ov, 4096) if a[i:i+4096] != b[i:i+4096]][:8]
print('first differing blocks (kbase-relative):', [hex(V11_BASE+i) for i in bad])

print('\n=== ORBISYS anchor re-verify ===')
print('ours  0x1520000:', D[0x1520000:0x1520010])
print('v11   0x1520000:', V11[0:16])
print('v11   0x1b265e8 (ours end):', V11[OURS_END-V11_BASE:OURS_END-V11_BASE+16].hex(' '))
print('v11   0x2400000 (tier1 end):', V11[0x2400000-V11_BASE:0x2400000-V11_BASE+16].hex(' '))
