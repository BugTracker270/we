#!/usr/bin/env python3
"""Enable VERIFY_HEADER (step 7) and claim the AuthMgr context first.

Step 6 proved the transport: _sceSblAuthMgrSmFinalize returned 0 through
sceSblServiceMailbox with module id 0. Next is VERIFY_HEADER (cmd 1), which
returns the auth/service id that LOAD_SELF_SEGMENT then needs.

The orbital reference claims the context (self_ctx_status[i] = 1) AFTER
finalize and BEFORE verifying, so do the same.
"""
import sys

SRC = r'C:\Users\Kinan\Downloads\JV13.52\selfdec2\source\main.c'
src = open(SRC, encoding='utf-8').read()
before = src

# 1. run steps 1..7 instead of 1..6
for old, new in (("    c->maxstep = 6;", "    c->maxstep = 7;"),
                 ("c->maxstep = 6;",     "c->maxstep = 7;")):
    if old in src:
        src = src.replace(old, new, 1)
        print(f"PASS maxstep -> 7  (matched {old!r})")
        break
else:
    print("FAIL: maxstep default not found")
    sys.exit(2)

# 2. claim the context immediately before calling finalize
anchor = "        r = (uint64_t)finalize((void *)(kb + KO_SELF_CONTEXTS"
if anchor not in src:
    print("FAIL: finalize call anchor not found verbatim")
    for line in src.splitlines():
        if 'finalize(' in line:
            print("  candidate:", repr(line))
    sys.exit(2)
src = src.replace(
    anchor,
    "        st[cid] = 1;   /* claim it, as the reference does pre-verify */\n"
    + anchor, 1)
print("PASS ctx claim inserted before finalize")

if src == before:
    print("FAIL: nothing changed")
    sys.exit(2)

open(SRC, 'w', encoding='utf-8', newline='').write(src)
chk = open(SRC, encoding='utf-8').read()
assert 'c->maxstep = 7' in chk and 'st[cid] = 1;' in chk
print("written OK")
