#!/usr/bin/env python3
"""Pin the remainder: sceSblDriverUnmapPages, kmalloc vs malloc, kfree, M_AUTHMGR."""
import struct, re
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
TB0 = SEGS[0][0]
tb = d[SEGS[0][1]:SEGS[0][1] + SEGS[0][2]]
def rd(k, n):
    o = k - TB0
    return tb[o:o + n] if 0 <= o < len(tb) else None
def koff2foff(k):
    for ko, po, fsz, msz, fl in SEGS:
        if ko <= k < ko + fsz:
            return po + (k - ko)
def foff2koff(o):
    for ko, po, fsz, msz, fl in SEGS:
        if po <= o < po + fsz:
            return ko + (o - po)
def disp_target(ins, opidx=0):
    for op in ins.operands:
        if op.type == 3 and op.mem.base == 41:
            return ins.address + ins.size + op.mem.disp - KBASE
    return None

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def show(kstart, kend, label, maxins=400, want='all'):
    print(f"\n{'='*78}\n### {label}  0x{kstart:08x}..0x{kend:08x}\n{'='*78}")
    buf = rd(kstart, kend - kstart)
    if not buf: print("  <no bytes>"); return
    n = 0
    for ins in md.disasm(buf, KBASE + kstart):
        k = ins.address - KBASE
        ex = ''
        if ins.mnemonic == 'call' and ins.op_str.startswith('0x'):
            ex = f"   -> koff 0x{int(ins.op_str,16)-KBASE:08x}"
        if '[rip' in ins.op_str:
            try:
                ex += f"   ;; data 0x{disp_target(ins):08x}"
            except Exception:
                pass
        if want == 'all' or 'koff' in ex or 'data 0x' in ex:
            print(f"  0x{k:08x}  {ins.bytes.hex():<24} {ins.mnemonic:<8}{ins.op_str}{ex}")
        n += 1
        if n >= maxins: break

# --- 1. free_map_mem: has the UnmapPages error log at 0x627c8c
show(0x00627C00, 0x00627D40, 'free_map_mem (UnmapPages error log @0x627c8c)')

# --- 2. MapPages entry: confirm the 6-arg shape
show(0x0061AE20, 0x0061AFC0, 'sceSblDriverMapPages 0x61ae20 (confirm)', 90)

# --- 3. UnmapPages candidate 0x61c4c0
show(0x0061C4C0, 0x0061C540, 'sceSblDriverUnmapPages candidate 0x61c4c0', 40)

# --- 4. malloc/kmalloc relationship
show(0x00009520, 0x00009580, 'candidate A: 0x9520 head', 30)
show(0x000096E0, 0x00009740, 'candidate B: 0x96e0 head', 30)

# --- 5. AuthMgr AuthHeader: its own kmalloc call reveals M_AUTHMGR
show(0x00642C90, 0x00642F00, 'sceSblAuthMgrAuthHeader 0x642c90', 300, want='calls')
