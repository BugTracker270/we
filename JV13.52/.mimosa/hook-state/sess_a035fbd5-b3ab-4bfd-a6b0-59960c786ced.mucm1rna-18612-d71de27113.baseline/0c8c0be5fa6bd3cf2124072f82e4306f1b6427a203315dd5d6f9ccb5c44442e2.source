#!/usr/bin/env python3
"""Print every field of the four live self_context_t slots from the kernel dump,
by offset, so the layout verifyHeader actually uses can be read off directly
instead of eyeballed.

self_context_t stride = 0x60, base koff 0x0269C140, dump base koff 0x1520000.
"""
import struct

DUMP = r'C:\Users\Kinan\Downloads\JV13.52\v11_kmem_img.bin'
DBASE = 0x1520000
CTX0 = 0x269C140
STRIDE = 0x60

d = open(DUMP, 'rb').read()


def rd(ko, n):
    return d[ko - DBASE: ko - DBASE + n]


print('gradient of the buf-base globals (verify_header uses *(0x269C0B8)):')
for k in (0x269C0B0, 0x269C0B8, 0x269C0C0):
    print(f'  koff {k:#x} = {struct.unpack("<Q", rd(k, 8))[0]:#018x}')

print('\nverifyHeader derives:  packet+0x08 = *(0x269C0B8) + ctx->0x30 * 0x1000')
bufb = struct.unpack('<Q', rd(0x269C0B8, 8))[0]
print(f'  *(0x269C0B8) = {bufb:#x}')

for i in range(4):
    ko = CTX0 + i * STRIDE
    b = rd(ko, STRIDE)
    print(f'\n--- self_contexts[{i}]  koff {ko:#x} ---')
    for off in range(0, STRIDE, 8):
        q = struct.unpack_from('<Q', b, off)[0]
        u32 = struct.unpack_from('<I', b, off)[0]
        print(f'  +{off:#04x}  {q:#018x}   (u32: {u32:#010x})')
    f_off30 = struct.unpack_from('<I', b, 0x30)[0]
    bus = bufb + f_off30 * 0x1000
    print(f'  => ctx->0x30 as u32 = {f_off30:#x}  ->  packet+0x08 would be {bus:#x}')
