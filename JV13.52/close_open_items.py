#!/usr/bin/env python3
"""Stage-7 : close the open items.
 (1) name strings for pmap/dmap/pml4/mailbox symbols
 (2) context of the two 'sdt' rodata holders -> authmgr_handle
 (3) properly aligned disassembly of the SblDrvSendSx function
"""
import struct, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

P = r"C:\Users\Kinan\Downloads\czdji0\1352k.elf"
data = open(P, "rb").read()
BASE = 0xffffffff82200000
segs = []
for i in range(6):
    t, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", data, 0x40 + i*56)
    segs.append((t, off, va, fsz, msz))
def v2o(v):
    for t, off, va, fsz, msz in segs:
        if t == 1 and va <= v < va + fsz: return off + (v - va)
    return None
def o2v(o):
    for t, off, va, fsz, msz in segs:
        if t == 1 and off <= o < off + fsz: return va + (o - off)
    return None

ALLSTR = [(m.start(), m.group()) for m in re.finditer(rb"[ -~]{4,}", data)]

def find(sub, limit=25):
    print(f"\n--- strings containing {sub!r} ---")
    n = 0
    for off, s in ALLSTR:
        if sub in s:
            v = o2v(off)
            if v:
                print(f"   {v:#018x}  koff {v-BASE:#010x}  {s[:95].decode(errors='replace')}")
                n += 1
                if n >= limit: break
    if n == 0: print("   (none)")

print("========== (1) symbol name strings ==========")
for pat in (b"dmpml4i", b"pml4pml4i", b"dmpdpi", b"invlgn", b"invlpg",
            b"Mailbox", b"MapPages", b"ModuleId", b"pmap_pinit", b"dmap"):
    find(pat)

print("\n========== (2) 'sdt' rodata holders ==========")
for holder in (0xffffffff82ea1c80, 0xffffffff83c79f90):
    print(f"\n-- holder {holder:#018x} --")
    o = v2o(holder)
    if o is None:
        print("   (in .bss, not file-backed)"); continue
    # what strings are nearby
    reg = data[max(0,o-0x80):o+0x100]
    for s in re.findall(rb"[ -~]{4,}", reg)[:12]:
        print("   str:", s.decode(errors="replace")[:90])
    print("   qwords:")
    for k in range(0, 0x40, 8):
        q = struct.unpack_from("<Q", data, o+k)[0]
        note = ""
        t = o2v(o+k)
        if 0xffffffff82200000 <= q < 0xffffffff82efe758: note = "(.text)"
        elif 0xffffffff83720000 <= q < 0xffffffff84a34af0: note = "(.data/.bss)"
        print(f"     +{k:#04x} {t:#018x}: {q:#018x} {note}")

print("\n========== (3) SblDrvSendSx function ==========")
md = Cs(CS_ARCH_X86, CS_MODE_64)
# find real function start: scan back for push rbp / mov rbp,rsp
o = v2o(0xffffffff8281bca2)
start_off = None
for back in range(0, 0x200):
    oo = o - back
    if data[oo:oo+4] == b"\x55\x48\x89\xe5":
        start_off = oo; break
if start_off is None:
    start_off = o - 0x100
sv = o2v(start_off)
print(f"function start -> {sv:#018x}")
for ins in md.disasm(data[start_off:start_off+0x140], sv):
    mark = "  <-- CALL" if ins.mnemonic == "call" else ""
    print(f"  {ins.address:#018x}  {ins.mnemonic} {ins.op_str}{mark}")
