#!/usr/bin/env python3
"""Stage-2 : (a) confirm 1352k.elf is really 13.52 using the SDK's own K1352/K1350 tables
             (b) locate the SBL-mailbox anchors and derive the documented offsets."""
import struct

P = r"C:\Users\Kinan\Downloads\czdji0\1352k.elf"
data = open(P, "rb").read()
BASE = 0xffffffff82200000

# --- program headers -> mapping
e_phoff, e_phentsize, e_phnum = 0x40, 56, 6
segs = []
for i in range(e_phnum):
    t, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", data, e_phoff + i*56)
    segs.append((t, off, va, fsz, msz))

def v2o(v):
    for t, off, va, fsz, msz in segs:
        if t == 1 and va <= v < va + fsz:
            return off + (v - va)
    return None
def o2v(o):
    for t, off, va, fsz, msz in segs:
        if t == 1 and off <= o < off + fsz:
            return va + (o - off)
    return None

TEXT_START, TEXT_END = BASE, BASE + 0xcfe758

# ---------- (a) collect all direct-call targets inside .text ----------
calls = set()
i = 0
tstart_off, tend_off = v2o(TEXT_START), v2o(TEXT_END - 1)
while i < tend_off - 5:
    if data[i] == 0xE8:
        rel = struct.unpack_from("<i", data, i + 1)[0]
        tgt = o2v(i) + 5 + rel
        if tgt is not None and TEXT_START <= tgt < TEXT_END:
            calls.add(tgt)
    i += 1
print(f"[a] direct-call targets found in .text: {len(calls)}")

K1352 = {
 "XFAST_SYSCALL":0x000001C0,"PRISON_0":0x0111FA18,"ROOTVNODE":0x02136E90,
 "COPYOUT":0x002BD6A0,"MMAP_SELF_1":0x003B35F0,"MMAP_SELF_2":0x003B3610,
 "MMAP_SELF_3":0x001FC561,"DISABLE_ASLR":0x00478504,"REG_MGR_SET_INT":0x004E8CC0,
 "SET_TIME":0x00635220,"CLEAR_TIME_DIFFERENCE":0x00634700,"TARGET_ID":0x021CC60D,
 "ICC_NVS_WRITE":0x000A5A10,"NPDRM_OPEN":0x0064DF00,"NPDRM_CLOSE":0x0064DF20,
 "NPDRM_IOCTL":0x0064DF77,"NO_BD_PATCH":0x001D5EA3}
K1350 = {
 "XFAST_SYSCALL":0x000001C0,"PRISON_0":0x0111FA18,"ROOTVNODE":0x02136E90,
 "COPYOUT":0x002BD600,"MMAP_SELF_1":0x003B31F0,"MMAP_SELF_2":0x003B3210,
 "MMAP_SELF_3":0x001FC4C1,"DISABLE_ASLR":0x00478104,"REG_MGR_SET_INT":0x004E88C0,
 "SET_TIME":0x00634E20,"CLEAR_TIME_DIFFERENCE":0x00634300,"TARGET_ID":0x021CC60D,
 "ICC_NVS_WRITE":0x000A5A10,"NPDRM_OPEN":0x0064DB00,"NPDRM_CLOSE":0x0064DB20,
 "NPDRM_IOCTL":0x0064DB77,"NO_BD_PATCH":0x001D5E03}
K1400 = {"COPYOUT":0x002BD950,"MMAP_SELF_1":0x003B38A0,"MMAP_SELF_2":0x003B38C0,
 "MMAP_SELF_3":0x001FC801,"DISABLE_ASLR":0x004787B4,"REG_MGR_SET_INT":0x004E8F70,
 "SET_TIME":0x006354E0,"CLEAR_TIME_DIFFERENCE":0x006349C0,"NPDRM_OPEN":0x0064E1C0,
 "NPDRM_CLOSE":0x0064E1E0,"NPDRM_IOCTL":0x0064E237,"NO_BD_PATCH":0x001D6143}

for label, tbl in (("K1352", K1352), ("K1350", K1350), ("K1400", K1400)):
    n = 0; tot = 0; det = []
    for k, off in tbl.items():
        a = BASE + off
        if not (TEXT_START <= a < TEXT_END):
            continue          # data-side constant, prologue test N/A
        tot += 1
        ok = a in calls
        n += ok
        det.append(f"{k}={'YES' if ok else 'no '}")
    print(f"[a] {label}: {n}/{tot} of its .text entries are real call targets")
    print("     " + "  ".join(det))

# ---------- (b) absolute pointers to the anchors ----------
ANCH = {"sdt":0xffffffff82a036b1,
        "SblDrvSendSx":0xffffffff82ce6207,
        "req mtx":0xffffffff82ceaca8,
        "req msg cv":0xffffffff82ceac9d}
print("\n[b] absolute 8-byte pointers to each anchor string:")
holders = {}
for name, va in ANCH.items():
    pat = struct.pack("<Q", va)
    found = []
    s = 0
    while True:
        j = data.find(pat, s)
        if j < 0: break
        found.append(j)
        s = j + 1
    holders[name] = found
    print(f"  {name!r:14} @ {va:#018x} -> {len(found)} holder(s): "
          f"{[hex(o2v(x)) for x in found]}")

# ---------- (c) delta candidates ----------
D = {"authmgr_handle":("sdt",0x30),
     "sbl_mb_mtx":("SblDrvSendSx",-0x20),
     "mailbox_flags":("req mtx",-0x8),
     "mailbox_meta":("req msg cv",-0x18)}
print("\n[c] delta candidates  (offset = fw-relative offset from kernel base)")
for out,(src,d) in D.items():
    for h in holders[src]:
        a = o2v(h) + d
        off = a - BASE
        print(f"  {out:14} = {a:#018x}  (koff {off:#010x})   via {src} holder @ {hex(o2v(h))}")

# ---------- (d) dump around the mailbox struct ----------
print("\n[d] 0x60 bytes around 'req msg cv' / 'req mtx' string pair:")
hub = v2o(0xffffffff82ceac90)
if hub:
    for r in range(hub, hub + 0x30, 8):
        q = struct.unpack_from("<Q", data, r)[0]
        print(f"   off {r:#010x} vaddr {o2v(r):#018x} : {q:#018x}")
