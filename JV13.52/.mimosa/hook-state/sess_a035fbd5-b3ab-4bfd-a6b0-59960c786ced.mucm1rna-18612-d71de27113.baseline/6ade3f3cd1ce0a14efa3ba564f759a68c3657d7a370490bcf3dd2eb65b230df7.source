"""GO/NO-GO check 3: can the PS5 decrypter's porting anchors be found in the
19 MB kernel .data/.bss dump we already have?

The PS5-SELF-Decrypter README gives an anchor-string method for locating all the
offsets it needs, explicitly so it can be ported "even without kernel .text dump":

  offset_authmgr_handle   +0x30 from pointer to "sdt"        (also "usually 0x4")
  offset_sbl_mb_mtx       -0x20 from pointer to "SblDrvSendSx"
  offset_mailbox_base     +0x8  from offset_sbl_mb_mtx
  offset_sbl_sxlock       +0x8  from offset_mailbox_base
  offset_mailbox_flags    -0x8  from pointer to "req mtx"
  offset_mailbox_meta     -0x18 from pointer to "req msg cv"
  offset_dmpml4i          -0x8  from pointer to "invlgn"
  offset_dmpdpi           +0x4  from offset_dmpml4i
  offset_pml4pml4i        -0x1C from pointer to "pmap"

If these anchors are present in our dump, porting is a lookup job instead of a
guessing job. "pointer to X" means a qword in kernel memory that holds the
address of the string X.
"""
import struct, re

DUMP = r'C:\Users\Kinan\Downloads\JV13.52\v11_kmem_img.bin'
KOFF = 0x1520000
KBASE = 0xffffffff85680000          # this run's kbase
d = open(DUMP, 'rb').read()

ANCHORS = {
    "sdt":              0x30,
    "SblDrvSendSx":    -0x20,
    "req mtx":         -0x8,
    "req msg cv":      -0x18,
    "invlgn":          -0x8,
    "pmap":            -0x1C,
}

print(f"dump {len(d):,} B, koff 0x{KOFF:x}..0x{KOFF+len(d):x}\n")

# 1. where do the anchor STRINGS live?
str_va = {}
for s in ANCHORS:
    b = s.encode()
    hits = [m.start() for m in re.finditer(re.escape(b), d)]
    print(f'string {s!r}: {len(hits)} occurrence(s)')
    for h in hits[:4]:
        va = KBASE + KOFF + h
        print(f"    string at koff 0x{KOFF+h:x}  VA 0x{va:x}")
        str_va.setdefault(s, []).append(va)

# 2. is there a POINTER TO that string anywhere (8-byte aligned)?
print("\n--- pointers to anchor strings (8-byte aligned qwords) ---")
ptr_of = {}
for s, vas in str_va.items():
    for va in vas:
        pv = struct.pack('<Q', va)
        found = []
        for m in re.finditer(re.escape(pv), d):
            if m.start() % 8 == 0:
                found.append(m.start())
        if found:
            print(f"  pointer to {s!r} (0x{va:x}): {len(found)} site(s)")
            for fo in found[:4]:
                pko = KOFF + fo
                base = pko + ANCHORS[s]
                ptr_of[s] = base
                print(f"    pointer at koff 0x{pko:x}  -> derived koff 0x{base:x}"
                      f"  VA 0x{KBASE+base:x}")
        else:
            print(f"  pointer to {s!r} (0x{va:x}): none found")

print("\n--- cross-check against the derived AUTHMGR offsets ---")
for label, ko in [("AUTHMGR_HANDLE (derived)", 0x0269C0A0),
                  ("SM_FLAG (derived)", 0x0269C098),
                  ("CTX_TABLE (derived)", 0x0269C140)]:
    print(f"  {label:<26} 0x{ko:x}   VA 0x{KBASE+ko:x}")
if 'sdt' in ptr_of:
    print(f"  authmgr_handle via 'sdt'+0x30 = 0x{ptr_of['sdt']:x}   "
          f"(derived 0x269c0a0)  delta=0x{ptr_of['sdt'] - 0x269C0A0:x}")
