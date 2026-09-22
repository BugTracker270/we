#!/usr/bin/env python3
"""Find the transport the LIVE AuthMgr path uses to reach the secure module.

Fact: on 13.52 sceSblAuthMgrAuthHeader does NOT call sceSblServiceMailbox
(0x630230). Its call list contains 0x642b10 (twice), which sits immediately
before sceSblAuthMgrIsLoadable (0x642880). So disassemble [0x642b10, 0x642880)
and every other callee, and report what THEY call - we are looking for the
first hop that lands on the mailbox (0x630230) or on a mailbox-like wrapper.

Also reports any global whose value is loaded and passed as arg1, since that
would be the real module id.
"""
import struct, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ELF = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KB = 0xffffffff82200000
d = open(ELF, 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

MAILBOX = 0x630230
KNOWN = {
    0x00009520: 'kmalloc', 0x000096E0: 'kfree',
    0x000A3840: '_sx_xlock', 0x000A3A00: '_sx_xunlock',
    0x002BD4E0: 'bzero', 0x002BD520: 'bzero2',
    0x002BD5A0: 'memcpy', 0x002BD790: 'copyin', 0x002BD6A0: 'copyout',
    0x002E0510: 'log_error', 0x006C8550: 'kprintf?',
    0x00378A80: 'vlog?', 0x00378D30: 'vlog2?', 0x003794F0: 'vlog3?',
    0x00379560: 'vlog4?', 0x00394AD0: 'vlog5?',
    0x0061AE20: 'sceSblDriverMapPages',
    0x0061B500: 'sceSblDriverUnmapPages',
    0x00630230: 'sceSblServiceMailbox',
    0x0063FF00: '_sceSblAuthMgrSmFinalize',
    0x0063FFF0: 'sceSblAuthMgrSmRequest',
    0x0063D7F0: '_sceSblAuthMgrCheckSelfHeader',
    0x0063D100: 'fn_63d100', 0x00641E70: 'fn_641e70',
    0x00642B10: 'fn_642b10', 0x006432C0: 'fn_6432c0',
    0x00642880: 'sceSblAuthMgrIsLoadable',
    0x00642C90: 'sceSblAuthMgrAuthHeader',
    0x00643370: 'sceSblAuthMgrFinalize',
    0x006434D0: 'sceSblAuthMgrLoad',
    0x00655F20: 'fn_655f20', 0x00655F50: 'fn_655f50',
}


def dis(lo, hi):
    """Capstone with resync so data blobs cannot halt us."""
    out = []
    off = lo
    while off < hi:
        got = False
        for ins in md.disasm(d[off:hi], off):
            out.append(ins)
            off += ins.size
            got = True
        if not got:
            off += 1
    return out


TARGETS = [0x642B10, 0x63D100, 0x641E70, 0x6432C0]
for t in TARGETS:
    ins = dis(t, t + 0x120)
    calls = []
    datas = []
    for i in ins:
        if i.mnemonic == 'call' and i.op_str.startswith('0x'):
            calls.append(int(i.op_str, 16) - KB)
        if 'rip' in i.op_str and i.mnemonic in ('mov', 'lea'):
            pass
    print(f"=== {KNOWN.get(t, hex(t))}  0x{t:x} ===")
    seen = collections.Counter(calls)
    for c, n in seen.most_common():
        tag = KNOWN.get(c, '')
        flag = '   <== MAILBOX' if c == MAILBOX else ''
        print(f"    x{n}  0x{c:08x}  {tag}{flag}")
    if not seen:
        print("    (no calls in the first 0x120 bytes)")
    print()
