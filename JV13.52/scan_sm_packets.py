#!/usr/bin/env python3
"""Enumerate every AuthMgr SM command wrapper in the SBL region.

_sceSblAuthMgrSmFinalize (0x63FF00) shows the shape:
    lea r15, [rbp-0xB0]                  ; packet base
    mov qword ptr [rbp-0xB0], 5          ; packet[0x00] = command id
    mov eax, dword ptr [rbx+0x1C]
    mov dword ptr [rbp-0xA8], eax        ; packet[0x08] = ctx_id
    mov rsi, r15 / mov rdx, r15
    call sceSblServiceMailbox

Identify the packet base by light register dataflow on the lea that feeds
rsi/rdx at the mailbox call, then print the true field layout.
"""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ELF = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
KB = 0xffffffff82200000
d = open(ELF, 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

LO, HI = 0x63C000, 0x645000
MAILBOX = 0x630230
RBP, RSP, RIP = 36, 44, 41

insns = []
off = LO
while off < HI:
    g = False
    for i in md.disasm(d[off:HI], KB + off):
        insns.append(i)
        off += i.size
        g = True
    if not g:
        off += 1

funcs, cur = [], []
for i in insns:
    if i.mnemonic == 'push' and i.op_str == 'rbp':
        prev = cur[-1] if cur else None
        if not (prev and prev.mnemonic == 'mov' and prev.op_str == 'rbp, rsp'):
            if cur:
                funcs.append(cur)
            cur = [i]
            continue
    cur.append(i)
if cur:
    funcs.append(cur)

print(f"{len(funcs)} functions in 0x{LO:x}..0x{HI:x}\n")


def bases_for(f):
    """Return the set of [rbp-disp] slots used as rsi/rdx at the mailbox call."""
    slot = {}          # reg -> rbp disp (positive number)
    for i in f:
        if i.mnemonic == 'call' and i.op_str.startswith('0x'):
            if int(i.op_str, 16) - KB == MAILBOX:
                got = set()
                for rn in ('rsi', 'rdx'):
                    if rn in slot:
                        got.add(slot[rn])
                if got:
                    return got
        if len(i.operands) != 2:
            continue
        dst, src = i.operands
        if dst.type != 1 or not dst.reg:
            continue
        dn = i.reg_name(dst.reg)
        if i.mnemonic == 'lea' and src.type == 3 and src.mem.base == RBP:
            slot[dn] = src.mem.disp
        elif i.mnemonic == 'mov' and src.type == 1 and src.reg:
            sn = i.reg_name(src.reg)
            if sn in slot:
                slot[dn] = slot[sn]
        elif i.mnemonic == 'mov' and src.type == 3 and src.mem.base == RBP:
            slot.pop(dn, None)
    return set()


for f in funcs:
    found = bases_for(f)
    if not found:
        continue
    base = f[0].address - KB
    calls = sorted(set(int(i.op_str, 16) - KB for i in f
                       if i.mnemonic == 'call' and i.op_str.startswith('0x')))
    for pbase in sorted(found, key=abs):
        body = [i for i in f if i.mnemonic == 'mov'
                and len(i.operands) == 2 and i.operands[0].type == 3
                and i.operands[0].mem.base == RBP
                and i.operands[0].mem.disp == pbase]
        cmd = None
        for i in body:
            s = i.operands[1]
            if s.type == 2 and i.operands[0].size == 8:
                cmd = s.imm
                break
        print(f"--- fn 0x{base:06x}  packet @[rbp-{-pbase:#x}]  cmd={cmd if cmd is None else hex(cmd)}"
              f"  calls={[hex(c) for c in calls if c != MAILBOX]}")
        seen = set()
        for i in body:
            rel = i.operands[0].mem.disp - pbase
            sz = i.operands[0].size * 8
            if (rel, sz) in seen:
                continue
            seen.add((rel, sz))
            s = i.operands[1]
            if s.type == 2:
                v = f'imm {s.imm:#x}'
            elif s.type == 1 and s.reg:
                v = f'<-> {i.reg_name(s.reg)}'
            elif s.type == 3:
                v = f'[{i.reg_name(s.mem.base)}+{s.mem.disp:#x}]'
            else:
                v = '?'
            print(f"        +0x{rel:02x}  u{sz:<3} {v}")
        print()
