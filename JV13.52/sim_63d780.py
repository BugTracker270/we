#!/usr/bin/env python3
"""Replay sub_63D780 (koff 0x63D780) over the real SELF bytes.

   63D784  mov  r8,  qword ptr [rdi + 0x38]      ; r8 = ctx->header
   63D792  movzx r9d, word ptr [r8 + 0x18]       ; n
   63D797  movzx ecx, word ptr [r8 + 0xc]        ; hs
   63D79F  shl  r9, 5                            ; r9 = n*0x20
   63D7A6  sub  ecx, eax                         ; ecx = hs - n*0x20
   63D7A8  movzx eax, word ptr [r8 + r9 + 0x58]  ; cnt
   63D7AE  add  ecx, -0x20
   63D7B1  imul edi, eax, 0x38
   63D7B9  add  edi, 0x4f
   63D7BC  and  edi, 0xfffffff0
   63D7BF  sub  rcx, rdi
   63D7C2  add  rdx, rcx          (rdx = 0xfffffffc0)
   63D7C5  shr  rdx, 4
   63D7C9  cmp  edx, 3            -> jb fail(-2)
   63D7CE  lea  rcx, [r8 + r9 + 0x20]
   63D7D3  mov  dl, byte ptr [rdi + rcx + 0x40]
   63D7D7  and  dl, 3
   63D7DA  cmp  dl, 3             -> jne fail(-2)
   63D7DF  lea  rax, [rdi + rcx + 0x50]   ; *out
"""
import sys

SELF = sys.argv[1] if len(sys.argv) > 1 else \
    r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\80010008.self'
d = open(SELF, 'rb').read()
print(f"{SELF}  {len(d)} B\n")


def u16(o):
    return int.from_bytes(d[o:o + 2], 'little')


def u32(o):
    return int.from_bytes(d[o:o + 4], 'little')


def u64(o):
    return int.from_bytes(d[o:o + 8], 'little')


print("header fields")
print(f"  magic        @0x00 = {u32(0):#010x}  (SELF_MAGIC {0x1d3d154f:#010x})")
print(f"  key_type     @0x08 = {u32(0x08):#x}")
print(f"  header_size  @0x0C = {u16(0x0c):#x}")
print(f"  meta_size    @0x0E = {u16(0x0e):#x}")
print(f"  file_size    @0x10 = {u64(0x10):#x}  (actual {len(d):#x})")
print(f"  num_entries  @0x18 = {u16(0x18)}")
print(f"  flags        @0x1A = {u16(0x1a):#x}")
print()

n = u16(0x18)
hs = u16(0x0c)
r9 = (n * 0x20) & 0xffffffff
print(f"n  = {n}")
print(f"hs = {hs:#x}")
print(f"r9 = n*0x20 = {r9:#x}")

cnt_off = r9 + 0x58
cnt = u16(cnt_off)
print(f"cnt = u16[hdr + {cnt_off:#x}] = {cnt}  (raw bytes {d[cnt_off:cnt_off+2].hex()})")
print()

ecx = (hs - r9) & 0xffffffff
print(f"ecx = hs - r9            = {ecx:#x}")
ecx = (ecx - 0x20) & 0xffffffff
print(f"ecx = ecx - 0x20         = {ecx:#x}")
edi = (cnt * 0x38) & 0xffffffff
print(f"edi = cnt*0x38           = {edi:#x}")
edi = (edi + 0x4f) & 0xffffffff
print(f"edi = edi + 0x4f         = {edi:#x}")
edi = edi & 0xfffffff0
print(f"edi = edi & ~0xf         = {edi:#x}")
ecx = (ecx - edi) & 0xffffffff
print(f"ecx = ecx - edi          = {ecx:#x}")
rdx = (0xfffffffc0 + ecx) & 0xffffffffffffffff
print(f"rdx = 0xfffffffc0 + ecx  = {rdx:#x}")
edx = (rdx >> 4) & 0xffffffff
print(f"edx = rdx >> 4           = {edx:#x}")
print()
if edx < 3:
    print(f"*** FAIL: edx={edx} < 3  ->  return 0xfffffffe   <-- REJECTED HERE ***")
    sys.exit(0)
print(f"  check 1 (edx >= 3): PASS")

rcx = r9 + 0x20
byte_off = edi + rcx + 0x40
b = d[byte_off]
print(f"  byte[hdr + {byte_off:#x}] = {b:#04x}   (& 3 = {b & 3})")
if (b & 3) != 3:
    print(f"*** FAIL: (byte & 3) = {b & 3} != 3  ->  return 0xfffffffe   <-- REJECTED HERE ***")
    sys.exit(0)
print(f"  check 2 ((byte & 3) == 3): PASS")
print(f"\n  *out = hdr + {edi + rcx + 0x50:#x}")
print("\nRESULT: sub_63D780 would SUCCEED on this header.")
