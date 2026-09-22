#!/usr/bin/env python3
"""Confirm run 6's build really dropped the risky paths."""
import struct

p = r'C:\Users\Kinan\Downloads\JV13.52\selfdec2\selfdec2.bin'
d = open(p, 'rb').read()
print('size', len(d), '\n')

CHECKS = [
    # the crash source: sub_645110 must be GONE from the binary entirely
    ('KO_KEY_LOOKUP     0x00645110', 0x00645110, 'absent'),
    # read only as a VALUE for the report, never followed
    ('KO_KEY_LIST       0x0269C300', 0x0269C300, 'present'),
    ('KO_SM_VERIFY_HDR  0x006401F0', 0x006401F0, 'present'),
    ('KO_BUF_B          0x0269C0B8', 0x0269C0B8, 'present'),
    ('KO_CTX_BUFBASE    0x0269C2C0', 0x0269C2C0, 'present'),
    ('SUB_63D780 probe  0x0063D780', 0x0063D780, 'ABSENT'),
    ('SmStart           0x0063E470', 0x0063E470, 'ABSENT'),
]
ok = True
for name, v, want in CHECKS:
    n = d.count(struct.pack('<I', v))
    got = 'present' if n else 'absent'
    good = (got.lower() == want.lower())
    ok &= good
    print(f"  {'OK ' if good else 'BAD'} {name:32s} count={n}  want={want}")

for s in (b'smcall', b'keyhead'):
    n = d.count(s)
    print(f"  {'OK ' if n else 'BAD'} string {s.decode():32s} count={n}")
    ok &= (n > 0)

print('\nAUDIT:', 'PASS' if ok else 'FAIL')
