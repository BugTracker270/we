#!/usr/bin/env python3
"""Dump the kernel's OWN verify-header packet builder.

sceSblAuthMgrAuthHeader 0x642C90 is the function the kernel calls to validate a
SELF header. Whatever 0x80-byte request it hands the SM is by definition the
layout the SM accepts. Print every instruction plus the stack-slot stores so the
packet fields can be read off directly instead of guessed.

Also walks the find_sm_commands.py style search for the wrapper that carries
function-id 1 (AUTHMGR_CMD_VERIFY_HEADER).
"""
import struct
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
    0x0061AE20: 'sceSblDriverMapPages',
    0x0061B500: 'sceSblDriverUnmapPages',
    0x00630230: 'sceSblServiceMailbox',
    0x0063E470: '_sceSblAuthMgrSmStart',
    0x0063FF00: '_sceSblAuthMgrSmFinalize',
    0x0063FFF0: 'sceSblAuthMgrSmRequest',
    0x00640AA0: '_sceSblAuthMgrSmLoadSelfBlock',
    0x00642C90: 'sceSblAuthMgrAuthHeader',
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


def show(lo, hi, title):
    print(f"===== {title}  0x{lo:06x}..0x{hi:06x} =====")
    for i in dis(lo, hi):
        ko = i.address - KB
        note = ''
        if i.mnemonic == 'call' and i.op_str.startswith('0x'):
            t = int(i.op_str, 16) - KB
            note = '   ; ' + KNOWN.get(t, f'sub_{t:06x}')
        elif i.mnemonic == 'mov' and 'imm' not in i.op_str:
            for op in i.operands:
                if op.type == 3 and op.mem.base == 41:      # %rip
                    t = i.address + i.size + op.mem.disp - KB
                    note = f'   ; G 0x{t:x}'
        print(f"  {ko:06x}  {i.mnemonic:8s} {i.op_str}{note}")
    print()


show(0x642C90, 0x642F80, 'sceSblAuthMgrAuthHeader')
