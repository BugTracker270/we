#!/usr/bin/env python3
"""Derive the 5 missing 13.52 koffs:
     sceSblDriverMapPages, sceSblDriverUnmapPages, kmalloc, kfree, M_AUTHMGR

Method, in order:
  A. Calibrate the image against libPS4's own known-good 13.52 constants
     (K1352_*) and the 5.05 table (K505_*) so we know koff==file-offset is right.
  B. Build the call graph from E8 rel32 sites (deterministic byte scan, no
     linear disassembly -> immune to the desync noted in earlier notes).
  C. kmalloc: the kernel calls kmalloc(size, M_AUTHMGR, 0x102) all over the
     AuthMgr. "mov edx,0x102" (BA 02 01 00 00) shortly before "call rel32"
     pins the target; the nearby "lea rsi,[rip+X]" pins M_AUTHMGR.
  D. MapPages/UnmapPages: disassemble the AuthMgr functions and the
     0x62Exxx chunk-table cluster, list every call target.
"""
import struct, re, os, sys, collections

ELF   = r'C:\Users\Kinan\Downloads\czdji0\1352k.elf'
SDK   = r'C:\Users\Kinan\Downloads\JV13.52\sdk\fw_defines.h'
KBASE = 0xffffffff82200000

d = open(ELF, 'rb').read()
print(f"[i] {ELF}  {len(d):,} bytes")

# ------------------------------------------------------------------ ELF layout
assert d[:4] == b'\x7fELF'
e_phoff, = struct.unpack_from('<Q', d, 0x20)
e_phentsize, e_phnum = struct.unpack_from('<HH', d, 0x36)
SEGS = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags, p_off, p_va, p_pa, p_fsz, p_msz, p_al = struct.unpack_from('<IIQQQQQQ', d, o)
    if p_type == 1:
        SEGS.append((p_va - KBASE, p_off, p_fsz, p_msz, p_flags))
SEGS.sort()
TEXT_BASE, TEXT_OFF, TEXT_FSZ, TEXT_MSZ, _ = SEGS[0]
TEXT_END = TEXT_BASE + TEXT_FSZ
for koff, poff, fsz, msz, fl in SEGS:
    print(f"[i] PT_LOAD koff 0x{koff:08x} foff 0x{poff:08x} filesz 0x{fsz:x} memsz 0x{msz:x} flags {fl}")

def koff2foff(k):
    for koff, poff, fsz, msz, fl in SEGS:
        if koff <= k < koff + fsz:
            return poff + (k - koff)
    return None

def foff2koff(o):
    for koff, poff, fsz, msz, fl in SEGS:
        if poff <= o < poff + fsz:
            return koff + (o - poff)
    return None

def rd(k, n):
    o = koff2foff(k)
    if o is None: return None
    return d[o:o + n]

# ------------------------------------------------------- A. SDK calibration
print("\n=== A. calibration against libPS4 known-good tables ===")
txt = open(SDK, encoding='utf-8', errors='replace').read()
def table(prefix):
    out = {}
    for m in re.finditer(r'#define\s+' + prefix + r'_([A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+)', txt):
        out[m.group(1)] = int(m.group(2), 16)
    return out
t505, t1352 = table('K505'), table('K1352')
common = sorted(set(t505) & set(t1352))
print(f"[i] {len(t505)} K505 symbols, {len(t1352)} K1352 symbols, {len(common)} common")
print(f"{'symbol':<28}{'5.05':>12}{'13.52':>12}{'delta':>10}")
rows = []
for s in common:
    delta = t1352[s] - t505[s]
    rows.append((t1352[s], s, t505[s], delta))
for v1352, s, v505, delta in sorted(rows):
    flag = '' if 0 else ''
    print(f"{s:<28}{v505:>12x}{v1352:>12x}{delta:>+10x}{flag}")

# prologue sanity: does the byte at each known 13.52 fn offset look like code?
print("\n[i] prologue sanity (first 8 bytes at each known K1352 fn offset)")
for v1352, s, v505, delta in sorted(rows):
    b = rd(v1352, 8)
    hexs = b.hex(' ') if b else '<not in a file-backed segment>'
    print(f"  {s:<28} 0x{v1352:08x}  {hexs}")

# --------------------------------------------------- B. call graph (E8 rel32)
print("\n=== B. call graph ===")
tb = rd(TEXT_BASE, TEXT_FSZ)
calls = collections.defaultdict(list)           # target koff -> [site koffs]
nsites = 0
for i in range(len(tb) - 5):
    if tb[i] == 0xE8:
        rel, = struct.unpack_from('<i', tb, i + 1)
        tgt = TEXT_BASE + i + 5 + rel
        if TEXT_BASE <= tgt < TEXT_END:
            calls[tgt].append(TEXT_BASE + i)
            nsites += 1
print(f"[i] {nsites:,} candidate call sites -> {len(calls):,} distinct targets")
prologue_ok = lambda k: (rd(k, 1) or b'\x00')[0] in (0x55, 0x53, 0x56, 0x57, 0x41, 0x48, 0x4C, 0xF3, 0x31, 0x83, 0x8B, 0x89, 0xB8, 0xC3)
clean = {k: v for k, v in calls.items() if prologue_ok(k)}
print(f"[i] {len(clean):,} targets start with a plausible prologue byte")

print("\n[i] top-40 most-called targets (kmalloc/kfree/sx_lock etc. live here)")
for k, v in sorted(clean.items(), key=lambda kv: -len(kv[1]))[:40]:
    print(f"  0x{k:08x}  callers={len(v):>5}   head={rd(k,12).hex(' ')}")

# ------------------------------------------------- C. kmalloc via 0x102 flag
print("\n=== C. kmalloc hunt: 'mov edx,0x102' (BA 02 01 00 00) near a call ===")
PAT = bytes.fromhex('ba02010000')
hits = []
pos = tb.find(PAT)
while pos != -1:
    # look up to 0x40 bytes forward and 0x30 back for an E8 call
    fwd = None
    for j in range(pos + 5, min(pos + 5 + 0x40, len(tb) - 5)):
        if tb[j] == 0xE8:
            rel, = struct.unpack_from('<i', tb, j + 1)
            tgt = TEXT_BASE + j + 5 + rel
            if TEXT_BASE <= tgt < TEXT_END:
                fwd = (tgt, TEXT_BASE + j)
                break
    hits.append((TEXT_BASE + pos, fwd))
    pos = tb.find(PAT, pos + 1)
hist = collections.Counter()
for site, fwd in hits:
    if fwd: hist[fwd[0]] += 1
print(f"[i] {len(hits)} sites load edx=0x102; {sum(hist.values())} have a resolvable call after")
print("[i] candidate kmalloc targets (target, #sites):")
for tgt, n in hist.most_common(12):
    print(f"  0x{tgt:08x}  x{n}   head={rd(tgt,16).hex(' ')}")

print("\n[i] per-site detail for the top candidate (M_AUTHMGR = lea rsi,[rip+X] nearby)")
for tgt, n in hist.most_common(3):
    print(f"  --- candidate kmalloc 0x{tgt:08x} ---")
    shown = 0
    for site, fwd in hits:
        if not fwd or fwd[0] != tgt: continue
        # scan backwards for 'lea rsi,[rip+rel]' (48 8d 35) to identify M_AUTHMGR
        ma = None
        for j in range(site - 1, max(site - 0x30, 0), -1):
            if tb[j:j+3] == b'\x48\x8d\x35':
                rel, = struct.unpack_from('<i', tb, j + 3)
                ma = TEXT_BASE + j + 7 + rel
                break
        print(f"    site 0x{site:08x}  call@0x{fwd[1]:08x}  M_AUTHMGR?={hex(ma) if ma else '-'}")
        shown += 1
        if shown >= 6: break

# --------------------------------------- D. disassemble the AuthMgr cluster
print("\n=== D. disassembly of the AuthMgr / chunk-table cluster ===")
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
    print("[!] capstone missing"); sys.exit(1)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

def dis(kstart, kend, label):
    print(f"\n--- {label}: 0x{kstart:08x} .. 0x{kend:08x} ---")
    buf = rd(kstart, kend - kstart)
    if buf is None:
        print("   <outside file-backed segments>"); return
    for ins in md.disasm(buf, KBASE + kstart):
        mark = ''
        if ins.mnemonic == 'call':
            t = ins.op_str
            if t.startswith('0x'):
                tk = int(t, 16) - KBASE
                mark = f'    ; koff 0x{tk:08x}' + (f'  [callers={len(calls.get(tk,[]))}]' if tk in calls else '')
        print(f"  0x{ins.address - KBASE:08x}  {ins.bytes.hex():<20} {ins.mnemonic:<8}{ins.op_str}{mark}")

# the two candidate thin wrappers right before sceSblServiceMailbox (0x630230)
dis(0x62DFC0, 0x62E020, 'just before map_chunk_table guess')
dis(0x62E020, 0x62E120, 'map_chunk_table guess')
dis(0x630230, 0x6302C0, 'sceSblServiceMailbox (confirmed)')

# the AuthMgr public API we already have
dis(0x642880, 0x642900, 'sceSblAuthMgrIsLoadable (0x642880)')
dis(0x642C90, 0x642E60, 'sceSblAuthMgrAuthHeader (0x642C90)')
dis(0x642C90, 0x642C90, 'noop')
dis(0x63FF00, 0x63FFF0, '_sceSblAuthMgrSmFinalize (0x63FF00)')
dis(0x63FFF0, 0x640140, 'sceSblAuthMgrSmRequest (0x63FFF0)')
