#!/usr/bin/env python3
"""Disassemble the SM contact point candidates with the CORRECT base.

trace_transport.py disassembled at image-relative addresses, so capstone
computed call targets against base 0 and printed them base-subtracted. This
version disassembles at KB+koff so every printed target is a true koff.

Targets, all reachable from sceSblAuthMgrAuthHeader and its callees:
    0x640630   called by 0x63D100 (the function that also calls SmStart)
    0x63D100   calls SmStart + 0x640630
    0x641F80   called by 0x641E70
    0x63E470   _sceSblAuthMgrSmStart - what its guard actually tests
"""
import struct, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ELF = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KB = 0xffffffff82200000
d = open(ELF, 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

KNOWN = {
    0x00009520: 'kmalloc', 0x000096E0: 'kfree',
    0x000A3840: '_sx_xlock', 0x000A3A00: '_sx_xunlock',
    0x002BD4E0: 'bzero', 0x002BD5A0: 'memcpy',
    0x002BD790: 'copyin', 0x002BD6A0: 'copyout',
    0x002E0510: 'log_error', 0x006C8550: 'kprintf?',
    0x0061AE20: 'sceSblDriverMapPages',
    0x00630230: 'sceSblServiceMailbox',
    0x0063E470: '_sceSblAuthMgrSmStart',
    0x0063FF00: '_sceSblAuthMgrSmFinalize',
    0x0063FFF0: 'sceSblAuthMgrSmRequest',
    0x00640AA0: '_sceSblAuthMgrSmLoadSelfBlock',
}
GLOBALS = {
    0x0269C098: 'SM_FLAG', 0x0269C09C: '(+4)',
    0x0269C0A0: 'MODULE_ID', 0x0269C0A8: 'B?0x0A8',
    0x0269C0B0: 'BUF_A', 0x0269C0B8: 'BUF_B', 0x0269C0C0: 'BUF_C',
    0x0269C0C8: 'SM_XLOCK', 0x0269C130: 'CTX_STATUS', 0x0269C140: 'SELF_CONTEXTS',
    0x0269C2C0: 'CTX_BUFBASE',
}


def dis(lo, hi):
    out, off = [], lo
    while off < hi:
        got = False
        for ins in md.disasm(d[off:hi], KB + off):
            out.append(ins)
            off += ins.size
            got = True
        if not got:
            off += 1
    return out


def report(lo, hi, title):
    print(f"=== {title}  0x{lo:06x}..0x{hi:06x} ===")
    ins = dis(lo, hi)
    calls, globs = collections.Counter(), []
    for i in ins:
        if i.mnemonic == 'call' and i.op_str.startswith('0x'):
            calls[int(i.op_str, 16) - KB] += 1
        for op in i.operands:
            if op.type == 3 and op.mem.base == 41:
                t = i.address + i.size + op.mem.disp - KB
                if t in GLOBALS:
                    globs.append((i.mnemonic, i.op_str, t))
    for c, n in calls.most_common():
        tag = KNOWN.get(c, '')
        flag = '   <== MAILBOX' if c == 0x630230 else ''
        print(f"    call x{n}  0x{c:08x}  {tag}{flag}")
    if globs:
        print("    --- named global accesses ---")
        for m, o, t in globs:
            print(f"      {m} {o}   ; {GLOBALS[t]} (0x{t:x})")
    if not calls and not globs:
        print("    (none)")
    print()


report(0x640630, 0x640AA0, 'fn_640630')
report(0x63D100, 0x63D7F0, 'fn_63D100')
report(0x63E470, 0x63E700, 'fn_63E470 SmStart guard region')
