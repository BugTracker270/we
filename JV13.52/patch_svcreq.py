#!/usr/bin/env python3
"""Default svcreq to 0 so the mailbox call proceeds.

Evidence for reversing my earlier caution:
  * fn_640630 is the real AuthMgr SM request core; it reaches
    sceSblServiceMailbox and takes the id from [0x269C0A0]
  * sceSblAuthMgrAuthHeader -> 0x63D100 -> fn_640630 (x2), so the LIVE
    header-verification path uses the mailbox
  * this console boots and runs games, i.e. SELF verification works, so the
    id the kernel passes there - the same 0 - must be functional
So 0 is the default SM service, not "unpopulated", and the guard was
over-cautious. svcreq stays available for cfg override if this is wrong.
"""
import sys

SRC = r'C:\Users\Kinan\Downloads\JV13.52\selfdec2\source\main.c'
OLD = "    c->svcreq  = 1;"
NEW = "    c->svcreq  = 0;   /* 0: allow the mailbox call (see patch_svcreq.py) */"

src = open(SRC, encoding='utf-8').read()
if OLD not in src:
    for line in src.splitlines():
        if 'svcreq' in line and 'c->' in line:
            print("candidate:", repr(line))
    print("FAIL: default svcreq line not found verbatim")
    sys.exit(2)
if src.count(OLD) != 1:
    print(f"FAIL: appears {src.count(OLD)} times")
    sys.exit(2)

src = src.replace(OLD, NEW)
open(SRC, 'w', encoding='utf-8', newline='').write(src)

chk = open(SRC, encoding='utf-8').read()
assert OLD not in chk and NEW in chk
print("PASS: svcreq default is now 0")
