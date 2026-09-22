#!/usr/bin/env python3
"""Send the REAL ctx_id (context+0x1C), not the array index.

VERIFY_HEADER returned rc=0 at the mailbox level but the SM's reply carried
0xffffffea (EINVAL). Cause: the packet's context_id field carried the array
index, while the SM identifies contexts by the ctx_id stored at context+0x1C -
and on this console that is a permutation, not the identity:

    ctx[0].ctx_id = 1   ctx[1].ctx_id = 2
    ctx[2].ctx_id = 0   ctx[3].ctx_id = 3

Proof it is this field and not the packet layout: the kernel's own
_sceSblAuthMgrSmFinalize takes its context id from [ctx+0x1C] (verified in its
disassembly), and that call - step 6 - returned 0. Only my hand-built step 7
packet, which used the index, came back EINVAL.

The orbital reference sends the index because it assumes
sceSblAuthMgrSmStart has run and written ctx[idx].ctx_id = idx. We never call
SmStart (it is the function that softlocked the console), so that identity
mapping was never established here.
"""
import sys

SRC = r'C:\Users\Kinan\Downloads\JV13.52\selfdec2\source\main.c'
OLD = """        q[2] = (a->hdr_len & 0xffffffffULL)          /* 0x10 header_size   */
             | ((a->ctx & 0xffffffffULL) << 32);     /* 0x1C context_id    */"""
NEW = """        /* context_id must be the ctx_id STORED in the context (ctx+0x1C),
           which is what the kernel's own _sceSblAuthMgrSmFinalize sends -
           verified in its disassembly. The array index is NOT the ctx_id on
           this console (the mapping is a permutation), and sending the index
           is what produced EINVAL here. */
        a->svc_id = id;
        {
            uint32_t real_ctx = *(volatile uint32_t *)
                (kb + KO_SELF_CONTEXTS + a->ctx * CTX_STRIDE + 0x1C);
            o->rd[9] = real_ctx;
            q[2] = (a->hdr_len & 0xffffffffULL)      /* 0x10 header_size   */
                 | ((uint64_t)real_ctx << 32);       /* 0x1C context_id    */
        }"""

src = open(SRC, encoding='utf-8').read()
if OLD not in src:
    print("FAIL: q[2] assignment not found verbatim")
    sys.exit(2)
if src.count(OLD) != 1:
    print(f"FAIL: appears {src.count(OLD)} times")
    sys.exit(2)

src = src.replace(OLD, NEW)
open(SRC, 'w', encoding='utf-8', newline='').write(src)

chk = open(SRC, encoding='utf-8').read()
assert 'real_ctx' in chk and OLD not in chk
print("PASS: step 7 now sends the stored ctx_id from context+0x1C")
