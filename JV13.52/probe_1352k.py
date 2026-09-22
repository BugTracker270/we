#!/usr/bin/env python3
"""Probe czdji0/1352k.elf : confirm it is a kernel ELF, then hunt the 6 string anchors
used by PS5-SELF-Decrypter's offset-porting recipe."""
import struct, os, sys

P = r"C:\Users\Kinan\Downloads\czdji0\1352k.elf"
data = open(P, "rb").read()
print("file      :", P)
print("size      :", len(data))
print("magic     :", data[:4])
if data[:4] != b"\x7fELF":
    print("NOT AN ELF - abort"); sys.exit(1)

cls, endian = data[4], data[5]
print("class     :", cls, "(2=64bit)", " endian:", endian, "(1=LE)")
(hdr) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, \
    e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = hdr
print(f"e_type    : {e_type:#x}   e_machine: {e_machine:#x} (0x3e=x86-64)")
print(f"e_entry   : {e_entry:#x}")
print(f"e_phoff   : {e_phoff:#x}  e_phnum={e_phnum}  e_phentsize={e_phentsize}")
print(f"e_shoff   : {e_shoff:#x}  e_shnum={e_shnum}")

# ---- program headers: build vaddr <-> file-offset mapping
segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
        struct.unpack_from("<IIQQQQQQ", data, off)
    segs.append(dict(i=i, type=p_type, flags=p_flags, off=p_offset,
                     vaddr=p_vaddr, filesz=p_filesz, memsz=p_memsz))
    print(f"  PH[{i}] type={p_type:#x} flags={p_flags:#x} off={p_offset:#010x} "
          f"vaddr={p_vaddr:#018x} filesz={p_filesz:#010x} memsz={p_memsz:#010x}")

def v2o(v):
    for s in segs:
        if s["type"] == 1 and s["vaddr"] <= v < s["vaddr"] + s["filesz"]:
            return s["off"] + (v - s["vaddr"])
    return None
def o2v(o):
    for s in segs:
        if s["type"] == 1 and s["off"] <= o < s["off"] + s["filesz"]:
            return s["vaddr"] + (o - s["off"])
    return None

LOAD_BASES = [s["vaddr"] for s in segs if s["type"] == 1]
print("\nload vaddrs:", [hex(b) for b in LOAD_BASES])
if LOAD_BASES:
    base = min(LOAD_BASES)
    print(f"lowest load vaddr (=kernel base candidate): {base:#018x}")

# ---- anchor strings
ANCHORS = [b"sdt", b"SblDrvSendSx", b"req mtx", b"req msg cv", b"invlgn", b"pmap"]
print("\n=== anchor string occurrences (file, and mapped vaddr) ===")
hits = {}
for a in ANCHORS:
    found = []
    start = 0
    while True:
        j = data.find(a, start)
        if j < 0:
            break
        # require NUL-terminated-ish context to cut noise for short strings
        after = data[j+len(a):j+len(a)+1]
        before = data[j-1:j] if j else b""
        found.append((j, o2v(j), before, after))
        start = j + 1
    hits[a] = found
    term = [f for f in found if f[3] == b"\x00"]
    print(f"\n  {a!r}: {len(found)} raw hit(s), {len(term)} NUL-terminated")
    for (j, v, before, after) in term[:40]:
        print(f"     fileoff={j:#010x}  vaddr={'None' if v is None else hex(v)}"
              f"  prev={before!r}")
print("\ndone.")
