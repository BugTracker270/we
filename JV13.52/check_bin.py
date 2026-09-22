#!/usr/bin/env python3
"""Confirm the built payload carries the new constants and still avoids SmStart."""
import struct

p = r'C:\Users\Kinan\Downloads\JV13.52\selfdec2\selfdec2.bin'
d = open(p, 'rb').read()
print('size', len(d))
for n, v in [('KO_SM_VERIFY_HDR  0x006401F0', 0x006401F0),
             ('KO_CTX_DIGEST_PTR 0x0063D780', 0x0063D780),
             ('KO_BUF_B         0x0269C0B8', 0x0269C0B8),
             ('KO_CTX_BUFBASE   0x0269C2C0', 0x0269C2C0),
             ('KO_SM_FLAG       0x0269C098', 0x0269C098),
             ('KO_MODULE_ID     0x0269C0A0', 0x0269C0A0),
             ('KO_KEY_LIST      0x0269C300', 0x0269C300),
             ('KO_KEY_LOOKUP    0x00645110', 0x00645110),
             ('MAILBOX          0x00630230', 0x00630230),
             ('FINALIZE         0x0063FF00', 0x0063FF00),
             ('[MUST BE ABSENT] SmStart 0x0063E470', 0x0063E470)]:
    print(f'  {n:34s} count={d.count(struct.pack("<I", v))}')
