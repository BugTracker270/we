#!/usr/bin/env python3
"""Focused derivation: disassemble the already-confirmed AuthMgr functions and
extract, per function, every call target plus every RIP-relative operand.
That reveals kmalloc / kfree / MapPages / UnmapPages / M_AUTHMGR by usage.
"""
import struct, sys, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ELF   = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KBASE = 0xffffffff82200000
d = open(ELF, 'rb').read()
e_phoff, = struct.unpack_from('<Q', d, 0x20)
e_phentsize, e_phnum = struct.unpack_from('<HH', d, 0x36)
SEGS = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t, fl, po, va, pa, fsz, msz, al = struct.unpack_from('<IIQQQQQQ', d, o)
    if t == 1:
        SEGS.append((va - KBASE, po, fsz, msz, fl))
SEGS.sort()
TEXT_BASE, TEXT_FOFF, TEXT_FSZ = SEGS[0][0], SEGS[0][1], SEGS[0][2]
TEXT_END = TEXT_BASE + TEXT_FSZ

def koff2foff(k):
    for ko, po, fsz, msz, fl in SEGS:
        if ko <= k < ko + fsz:
            return po + (k - ko)
def rd(k, n):
    o = koff2foff(k)
    return None if o is None else d[o:o + n]

KNOWN = {
 0x000A3840: '_sx_xlock',            0x000A3A00: '_sx_xunlock',
 0x00009520: 'kmalloc??',
 0x00630230: 'sceSblServiceMailbox',
 0x0063FF00: '_sceSblAuthMgrSmFinalize',
 0x0063FFF0: 'sceSblAuthMgrSmRequest',
 0x0063E470: '_sceSblAuthMgrSmStart',
 0x0063D180: '_sceSblAuthMgrLoadSelfBlock',
 0x0063D7F0: '_sceSblAuthMgrCheckSelfHeader',
 0x00640AA0: '_sceSblAuthMgrSmLoadSelfBlock',
 0x00642880: 'sceSblAuthMgrIsLoadable',
 0x00642C90: 'sceSblAuthMgrAuthHeader',
 0x00643370: 'sceSblAuthMgrFinalize',
 0x006434D0: 'sceSblAuthMgrLoadSegment/Block',
 0x002BD6A0: 'copyout',
 0x002BD4E0: 'memcpy?',
 0x00378D30: 'log/panic-ish',
 0x0002D670: '??',
}

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def scan(name, kstart, kend):
    buf = rd(kstart, kend - kstart)
    if not buf:
        print(f"\n### {name} 0x{ksystem:08x}: no bytes"); return
    print(f"\n{'='*78}\n### {name}  koff 0x{kstart:08x} .. 0x{kend:08x}  ({kend-kstart} B)\n{'='*78}")
    calls = []
    for ins in md.disasm(buf, KBASE + kstart):
        k = ins.address - KBASE
        line = f"  0x{k:08x}  {ins.bytes.hex():<22} {ins.mnemonic:<9}{ins.op_str}"
        extra = ''
        if ins.mnemonic == 'call' and ins.op_str.startswith('0x'):
            t = int(ins.op_str, 16) - KBASE
            calls.append(t)
            extra = f"   -> koff 0x{t:08x}" + (f"  [{KNOWN[t]}]" if t in KNOWN else "")
        # rip-relative memory operand
        if '[rip' in ins.op_str:
            for op in ins.operands:
                if op.type == 3 and op.mem.base == 41:
                    tgt = ins.address + ins.size + op.mem.disp - KBASE
                    extra += f"   ;; data koff 0x{tgt:08x}"
        if extra:
            print(line + extra)
        else:
            print(line)
    c = collections.Counter(calls)
    print(f"  --- calls in {name} ---")
    for t, n in c.most_common():
        print(f"      0x{t:08x} x{n}  {'[' + KNOWN[t] + ']' if t in KNOWN else ''}")

TARGETS = [
 ('_sceSblAuthMgrSmFinalize', 0x0063FF00, 0x0063FF00 + 0x0F0),
 ('sceSblAuthMgrSmRequest',   0x0063FFF0, 0x0063FFF0 + 0x150),
 ('sceSblAuthMgrIsLoadable',  0x00642880, 0x00642880 + 0x410),
 ('sceSblAuthMgrAuthHeader',  0x00642C90, 0x00642C90 + 0x6E0),
 ('sceSblAuthMgrFinalize',    0x00643370, 0x00643370 + 0x160),
 ('sceSblAuthMgrLoad?',       0x006434D0, 0x006434D0 + 0x400),
 ('_sceSblAuthMgrCheckSelfHeader', 0x0063D7F0, 0x0063D7F0 + 0x300),
]
for nm, a, b in TARGETS:
    scan(nm, a, b)
