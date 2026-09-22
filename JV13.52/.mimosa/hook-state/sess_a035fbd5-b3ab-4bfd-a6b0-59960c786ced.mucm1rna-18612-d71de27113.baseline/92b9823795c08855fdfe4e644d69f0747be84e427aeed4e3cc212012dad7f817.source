"""Verify the v3 probe output against the static image, then infer argument
registers for each AuthMgr entry point from its prologue."""
import re
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_MEM

LOG = r'C:\Users\Kinan\Downloads\JV13.52\console_log_probe.txt'
ELF = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
data = open(ELF, 'rb').read()

KOS = [0x00630230, 0x0063fff0, 0x00642c90, 0x006434d0, 0x00643370, 0x00642880]
NAMES = ['mailbox', 'smreq', 'authhdr', 'load', 'fin', 'isload']

# ---------------------------------------------------------------- 1. verify
txt = open(LOG, 'rb').read().decode('utf-8', errors='replace')
got = {}
for L in txt.splitlines():
    m = re.search(r'NOTIFICATION\]: F(\d) ([0-9a-f]+)', L)
    if m:
        got[int(m.group(1))] = m.group(2)

print("=== v3 function-address verification (24 bytes each) ===")
allok = True
for i, ko in enumerate(KOS):
    exp = data[ko:ko + 24].hex()
    g = got.get(i)
    ok = (g == exp)
    allok &= ok
    print(f"  F{i} {NAMES[i]:8} {'MATCH' if ok else 'MISMATCH'}")
    if not ok:
        print(f"       expected {exp}")
        print(f"       got      {g}")
print(f"\n  ==> {'ALL SIX HARDWARE-CONFIRMED' if allok else 'there are mismatches'}")

# ---------------------------------------------------------------- 2. signatures
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def canon(name):
    m = {
        'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
        'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
        'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx',
        'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx',
        'r8d': 'r8', 'r8w': 'r8', 'r8b': 'r8',
        'r9d': 'r9', 'r9w': 'r9', 'r9b': 'r9',
    }
    return m.get(name, name)

WRITE0 = {'mov', 'lea', 'xor', 'sub', 'add', 'and', 'or', 'shl', 'shr', 'sar',
          'pop', 'movzx', 'movsx', 'movsxd', 'inc', 'dec', 'neg', 'not', 'imul',
          'movabs', 'andn'}

ARGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

print("\n=== inferred argument registers (read before being written) ===")
for i, ko in enumerate(KOS):
    written = set()
    argseen = {}
    lines = []
    for ins in md.disasm(data[ko:ko + 0x60], 0xffffffff82200000 + ko):
        ops = ins.operands
        # reads
        for k, op in enumerate(ops):
            is_dst = (k == 0 and ins.mnemonic in WRITE0)
            if op.type == X86_OP_REG:
                r = canon(md.reg_name(op.reg))
                if not is_dst:
                    if r in ARGS and r not in written and r not in argseen:
                        argseen[r] = ins.address
            elif op.type == X86_OP_MEM:
                for rr in (op.mem.base, op.mem.index):
                    if rr:
                        r = canon(md.reg_name(rr))
                        if r in ARGS and r not in written and r not in argseen:
                            argseen[r] = ins.address
        # writes
        if ops and ins.mnemonic in WRITE0 and ops[0].type == X86_OP_REG:
            written.add(canon(md.reg_name(ops[0].reg)))
        lines.append(f"      {ins.mnemonic} {ins.op_str}")
        if ins.mnemonic == 'ret':
            break

    order = [a for a in ARGS if a in argseen]
    print(f"\n  F{i} {NAMES[i]}: args seen [{', '.join(order)}]")
    for a in order:
        print(f"        {a} first used at {argseen[a]:#x} (koff {argseen[a]-0xffffffff82200000:#x})")
    if not order:
        print("        (no argument registers read - takes no args?)")
