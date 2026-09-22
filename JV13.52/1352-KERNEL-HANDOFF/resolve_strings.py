#!/usr/bin/env python3
"""Resolve the string pointers that sceSblAuthMgrIsLoadable references, so the
disassembly reads as source-level logic instead of magic addresses.

Addresses are read straight off the objdump output:
  0x642891  lea 0x211a608(%rip),%r15  -> 0x275cea0   (stack canary)
  0x6428cd  lea 0x4ab48b(%rip),%rdi   -> 0xaedd5f
  0x6428d4  lea 0x4ab4b1(%rip),%rsi   -> 0xaedd8c
  0x6428f3  lea 0x4ab4a2(%rip),%rdx   -> 0xaedd9c
  0x642937  lea 0x4ab050(%rip),%rdi   -> 0xaed98e
  0x64293e  lea 0x4ab031(%rip),%rsi   -> 0xaed976
"""
IMG = r'C:\Users\Kinan\Downloads\JV13.52\kmemfull.bin'
d = open(IMG, 'rb').read()

TARGETS = [
    (0x275CEA0, 'r15 global (stack canary / guard)'),
    (0x0AEDD5F, 'rdi @0x6428cd  (log: file path?)'),
    (0x0AEDD8C, 'rsi @0x6428d4  (log: func name?)'),
    (0x0AEDD9C, 'rdx @0x6428f3  (mutex name)'),
    (0x0AED98E, 'rdi @0x642937  (error log: file path)'),
    (0x0AED976, 'rsi @0x64293e  (error log: func name)'),
    (0x0AECDA9, 'authmgr self_file.c build path'),
    (0x0AECE6A, 'authmgr pltauth_sm.c build path'),
    (0x0AED040, '80010008 module id'),
    (0x0AE61FA, 'SblDrvHdlrSx'),
    (0x0808B2A, 'sceSblAuthMgrIsLoadable(%s)=%x error'),
    (0x0802829, 'authmgrwait'),
    (0x08029A1, 'detach_authmgr'),
]

print(f'{"vaddr":>10}  {"bytes":<28} string')
print('-' * 100)
for off, note in TARGETS:
    end = d.find(b'\x00', off)
    raw = d[off:end] if end > 0 else b''
    txt = raw.decode('utf-8', 'replace')
    print(f'{off:#010x}  {raw[:12].hex(" "):<28} {txt[:80]!r}')
    print(f'{"":>10}  -> {note}')

print()
print('--- context around the authmgr build paths (0xaecd80..0xaed100) ---')
seg = d[0xAECD80:0xAED100]
for part in seg.split(b'\x00'):
    if len(part) >= 8 and all(32 <= c < 127 for c in part):
        print('   ', part.decode())
