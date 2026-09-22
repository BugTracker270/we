#!/usr/bin/env python3
"""Recursive-descent disassemble EVERY function in a koff range.

Seeds from every `55 48 89 e5` (push rbp; mov rbp,rsp) that is preceded by
padding / ret / int3, i.e. a real function entry, then runs true recursive
descent per function so no data is ever decoded as code.

Usage: recd_all.py LO_KOFF HI_KOFF
"""
import re, struct, sys

SRC = open(r'C:\Users\Kinan\Downloads\JV13.52\recd.py').read()
# reuse recd.py's ELF plumbing by exec'ing the top part up to the md = Cs(...) line
head = SRC.split("md = Cs(")[0]
exec(compile(head, 'recd_head', 'exec'))

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_RET
from capstone.x86 import X86_REG_RIP

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

LO = int(sys.argv[1], 16)
HI = int(sys.argv[2], 16)

# ---- find function entries -------------------------------------------------
seeds = []
p = LO
while p < HI - 4:
    if rd(p, 4) == b'\x55\x48\x89\xe5':
        prev = rd(p - 1, 1)
        if prev in (b'\x90', b'\xc3', b'\xcc', b'\x5d', b''):
            seeds.append(p)
            p += 3
            continue
    p += 1
print(f'[i] {len(seeds)} function entries in [0x{LO:x},0x{HI:x})')

seen = {}
for s in sorted(seeds):
    todo = [s]
    local = set()
    while todo:
        a = todo.pop()
        if a in local or not (TEXT_BASE <= a < TEXT_END):
            continue
        while True:
            local.add(a)
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
            if ins.mnemonic == 'call' and ins.op_str.startswith('0x'):
                t = int(ins.op_str, 16) - KBASE
                note += f'   ; -> {FUNCS.get(t, hex(t))}'
            seen.setdefault(a, (s, f'{ins.mnemonic:8s} {ins.op_str}{note}'))
            nxt = a + ins.size
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
                if not (s <= a < HI + 0x8000):
                    break
                continue
            if CS_GRP_RET in ins.groups or ins.mnemonic in ('hlt', 'int3', 'ud2'):
                break
            a = nxt
            if not (s <= a < HI + 0x8000):
                break

cur = None
for a in sorted(seen):
    fn, txt = seen[a]
    if fn != cur:
        cur = fn
        print(f'\n===== fn 0x{fn:06x} =====')
    print(f'  {a:06x}  {txt}')
