#!/usr/bin/env python3
"""Pin the true function ENTRY for the two SBL-driver symbols, using the call
graph (E8 targets) + prologue match, then disassemble to confirm."""
import struct, collections
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
tb = d[TEXT_FOFF:TEXT_FOFF + TEXT_FSZ]

def rd(k, n):
    o = k - TEXT_BASE
    return tb[o:o + n] if 0 <= o < len(tb) else None

# call graph
CALLT = set()
for i in range(len(tb) - 5):
    if tb[i] == 0xE8:
        rel, = struct.unpack_from('<i', tb, i + 1)
        t = TEXT_BASE + i + 5 + rel
        if TEXT_BASE <= t < TEXT_END:
            CALLT.add(t)
print(f"[i] {len(CALLT):,} call targets = candidate function entries")

def entry_for(site):
    """largest call-target <= site that starts with push rbp;mov rbp,rsp"""
    best = None
    for t in CALLT:
        if t <= site and site - t < 0x2000:
            b = rd(t, 4)
            if b and b == b'\x55\x48\x89\xe5':
                if best is None or t > best:
                    best = t
    return best

SITES = {
 'sceSblDriverMapPages   (log "sceSblDriverMapPages %d")': 0x0061BF0D,
 'sceSblDriverUnmapPages (log "ERROR: ...UnmapPages %d")': 0x0061C4D6,
 'caller of MapPages     (0x627a08)':                      0x00627A08,
 'caller of MapPages     (0x635c18)':                      0x00635C18,
 'sceSblServiceMailbox   (known)':                         0x00630230,
}
for lab, site in SITES.items():
    e = entry_for(site)
    print(f"\n{lab}\n   site 0x{site:08x}   -> entry {('0x%08x' % e) if e else '?'}"
          f"   head={rd(e, 16).hex(' ') if e else ''}")

md = Cs(CS_ARCH_X86, CS_MODE_64)
def dis(kstart, kend, label, maxins=999):
    buf = rd(kstart, kend - kstart)
    print(f"\n{'='*76}\n### {label}   0x{kstart:08x} .. 0x{kend:08x}\n{'='*76}")
    if not buf:
        print("   <no bytes>"); return
    n = 0
    for ins in md.disasm(buf, KBASE + kstart):
        k = ins.address - KBASE
        ex = ''
        if ins.mnemonic == 'call' and ins.op_str.startswith('0x'):
            t = int(ins.op_str, 16) - KBASE
            ex = f"   -> koff 0x{t:08x}"
        print(f"  0x{k:08x}  {ins.bytes.hex():<22} {ins.mnemonic:<8}{ins.op_str}{ex}")
        n += 1
        if n >= maxins: break

for lab, site in SITES.items():
    if 'known' in lab or 'caller' in lab:
        continue
    e = entry_for(site)
    if e:
        dis(e, site + 0x40, lab)

# also: the 0x62Exxx region is the SBL driver "send" area; show the wrapper
dis(0x6300E0, 0x630230, 'sceSblServiceSpawn? (called by SmStart with "80010008")', 80)
