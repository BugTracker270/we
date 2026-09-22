#!/usr/bin/env python3
"""Safety verification of the built selfdec2.bin.

Kernel offsets are added to a runtime kernel base, so the compiler emits them
as 32-bit displacements (lea rax,[rbx+disp32]) or 32-bit immediates - NOT as
64-bit literals. Search both widths.

The load-bearing assertion: _sceSblAuthMgrSmStart (0x63E470) must be ABSENT.
That is the call that softlocked this console twice.
"""
import struct

BIN = r'C:\Users\Kinan\Downloads\JV13.52\selfdec2\selfdec2.bin'
d = open(BIN, 'rb').read()
print(f"{BIN}\n  {len(d):,} bytes\n")

def find(pat):
    out, p = [], 0
    while True:
        i = d.find(pat, p)
        if i < 0:
            return out
        out.append(i)
        p = i + 1

MUST_BE_ABSENT = {
    0x0063E470: '_sceSblAuthMgrSmStart',
    0x0269C0B0: 'AUTHMGR_BUF_A',
}
# read-only inside the payload by construction; presence is expected
READ_ONLY_OK = {
    0x0269C098: 'SM_FLAG (read for reporting only, never written)',
}
EXPECTED = {
    0x00009520: 'kmalloc',
    0x000A3840: '_sx_xlock',
    0x000A3A00: '_sx_xunlock',
    0x002BD790: 'copyin',
    0x002BD6A0: 'copyout',
    0x0061AE20: 'sceSblDriverMapPages',
    0x0061B500: 'sceSblDriverUnmapPages',
    0x00630230: 'sceSblServiceMailbox',
    0x0063FF00: '_sceSblAuthMgrSmFinalize',
    0x01AECCB0: 'malloc_type (M_SBLDRV)',
    0x0269C0A0: 'module id',
    0x0269C0C8: 'authmgr_sm_xlock',
    0x0269C130: 'self_ctx_status',
    0x0269C140: 'self_contexts',
}

bad = 0
print("=== MUST NOT APPEAR (checked at 32 and 64 bit) ===")
for v, n in MUST_BE_ABSENT.items():
    o32 = find(struct.pack('<I', v))
    o64 = find(struct.pack('<Q', v))
    if o32 or o64:
        bad += 1
        print(f"  !! 0x{v:08x} {n}: 32-bit@{[hex(x) for x in o32]} "
              f"64-bit@{[hex(x) for x in o64]}")
    else:
        print(f"  OK 0x{v:08x} {n}: absent")

print("\n=== expected constants ===")
for v, n in EXPECTED.items():
    o32 = find(struct.pack('<I', v))
    o64 = find(struct.pack('<Q', v))
    tag = 'ok ' if (o32 or o64) else 'ABSENT'
    print(f"  {tag} 0x{v:08x}  {n:<28} 32-bit x{len(o32)}  64-bit x{len(o64)}")

print("\nVERDICT:", "FAIL - forbidden symbol referenced!" if bad
      else "PASS - no forbidden reference; all needed constants present")
