#!/usr/bin/env python3
"""Recursive-descent disassembler for the decrypted 13.52 kernel.

Why: capstone LINEAR sweep desyncs on this image (it walks into data), and
objdump/readelf are not installed.  Recursive descent follows real control flow
and re-syncs at every ret / padding byte, so it is accurate.

Also disassembly-independent RIP-relative references are NOT needed here: every
RIP target is resolved and printed as a koff, with the EEKC/SBL globals named.

Usage:
    recd.py START_KOFF [END_KOFF]
"""
import struct, sys, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET
from capstone.x86 import X86_REG_RIP

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


def koff2foff(k):
    for ko, po, fsz, msz, fl in SEGS:
        if ko <= k < ko + fsz:
            return po + (k - ko)
    return None


def foff2koff(o):
    for ko, po, fsz, msz, fl in SEGS:
        if po <= o < po + fsz:
            return ko + (o - po)
    return None


def rd(k, n):
    o = koff2foff(k)
    return b'' if o is None else d[o:o + n]


TEXT_BASE, TEXT_FOFF, TEXT_FSZ, _, _ = SEGS[0]
TEXT_END = TEXT_BASE + TEXT_FSZ

GLOB = {
    0x269C098: 'SM_STARTED', 0x269C09C: 'SM_..9C', 0x269C0A0: 'MODULE_ID',
    0x269C0A8: 'G0A8', 0x269C0B0: 'BUF_A', 0x269C0B8: 'BUF_B', 0x269C0C0: 'BUF_C',
    0x269C0C8: 'SM_XLOCK', 0x269C130: 'CTX_STATUS', 0x269C140: 'SELF_CTX',
    0x269C2C0: 'CTX_BUFBASE', 0x269C2E0: 'EEKC_LOCK', 0x269C300: 'EEKC_ROOT',
    0x269C308: 'E308', 0x269C310: 'E310', 0x269C318: 'E318', 0x269C320: 'E320',
    0x269C330: 'E330', 0x269C350: 'E350', 0x269C360: 'E360', 0x269C380: 'E380',
    0x2845168: 'SBL_BUF', 0x2845170: 'SBL_META',
}
FUNCS = {
    0x630230: 'sceSblServiceMailbox', 0x63D100: 'SmStart+verify',
    0x63D780: 'sub_63D780(digest_resolver)', 0x63FF00: 'SmFinalize',
    0x6401F0: 'SmVerifyHeader', 0x645110: 'EEKC_lookup_645110',
    0xA3840: 'sx_xlock', 0xA3A00: 'sx_xunlock', 0x2BD790: 'copyin',
    0x2BD6A0: 'copyout', 0x9520: 'kmalloc', 0x96E0: 'kfree',
    0xAEF0D3: 'eekc_mgr.c',
}
STRINGS = {0xAEE0D3: 'eekc_mgr.c string', 0xAEEF0D: '?', }

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

START = int(sys.argv[1], 16)
END = int(sys.argv[2], 16) if len(sys.argv) > 2 else START + 0x400

seen = set()
code = {}          # koff -> (text, note)
todo = [START]
while todo:
    a = todo.pop()
    if a in seen or not (TEXT_BASE <= a < TEXT_END):
        continue
    while True:
        seen.add(a)
        b = rd(a, 16)
        ins = None
        for i in md.disasm(b, KBASE + a, count=1):
            ins = i
        if ins is None:
            break
        note = ''
        for op in ins.operands:
            if op.type == 3 and op.mem.base == X86_REG_RIP:
                t = a + ins.size + op.mem.disp
                note += f'   ; [koff {t:#x}'
                note += f' = {GLOB[t]}' if t in GLOB else ''
                note += ']'
        tgt = None
        if ins.mnemonic == 'call' and ins.op_str.startswith('0x'):
            tgt = int(ins.op_str, 16) - KBASE
            note += f'   ; -> {FUNCS.get(tgt, hex(tgt))}'
        code[a] = (f'{ins.mnemonic:8s} {ins.op_str}{note}', a)
        nxt = a + ins.size
        grp = ins.groups
        if ins.mnemonic == 'jmp' and ins.op_str.startswith('0x'):
            t = int(ins.op_str, 16) - KBASE
            if TEXT_BASE <= t < TEXT_END:
                todo.append(t)
            break
        if ins.mnemonic.startswith('j') and ins.op_str.startswith('0x'):
            t = int(ins.op_str, 16) - KBASE
            if TEXT_BASE <= t < TEXT_END:
                todo.append(t)
            a = nxt
            if not (START <= a < END + 0x2000):
                break
            continue
        if CS_GRP_RET in grp or ins.mnemonic in ('hlt', 'int3', 'ud2', 'iret'):
            break
        a = nxt
        if not (START <= a < END + 0x2000):
            break

print(f'--- recursive descent from koff {START:#x} (printed while < {END:#x}) ---')
for a in sorted(code):
    if a < END:
        print(f'  {a:06x}  {code[a][0]}')
print(f'[i] {len(code)} instructions decoded; '
      f'max koff reached 0x{max(code):x}' if code else '[i] nothing')
