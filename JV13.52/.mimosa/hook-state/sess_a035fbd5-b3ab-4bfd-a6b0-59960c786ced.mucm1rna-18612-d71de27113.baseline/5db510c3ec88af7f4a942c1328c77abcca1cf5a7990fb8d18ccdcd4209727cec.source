#!/usr/bin/env python3
"""What can actually be extracted from the encrypted kernel SELFs?

Two questions to answer with data, not theory:
  Q1  What plaintext structure does a SELF expose without keys?
  Q2  Do the 13.52 and 14.00 kernels share plaintext-derived material
      (segment digests, whole unchanged regions)? If yes, we learn real
      facts about 14.00 with zero keys.
"""
import collections
import hashlib
import struct

A = r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\80010002.self'          # 13.52 kernel
B = r'C:\Users\Kinan\Downloads\JV13.52\dec\80010002_kernel_14.00.self'  # 14.00 kernel

a = open(A, 'rb').read()
b = open(B, 'rb').read()

print('=' * 72)
print('Q1. PLAINTEXT STRUCTURE EXPOSED WITHOUT KEYS')
print('=' * 72)
print(f'13.52  size {len(a):>10}  sha1 {hashlib.sha1(a).hexdigest()[:16]}')
print(f'14.00  size {len(b):>10}  sha1 {hashlib.sha1(b).hexdigest()[:16]}')
print(f'size delta      {len(b) - len(a):>10}')

for nm, d in (('13.52', a), ('14.00', b)):
    magic, verb, mode, endian, attr = struct.unpack_from('<IBBBB', d, 0)
    key_type, = struct.unpack_from('<I', d, 0x08)
    hdr, meta = struct.unpack_from('<HH', d, 0x0C)
    fsz, = struct.unpack_from('<Q', d, 0x10)
    nent, flags = struct.unpack_from('<HH', d, 0x18)
    print(f'\n[{nm}] magic={magic:#010x} key_type={key_type:#x} hdr_size={hdr:#x} '
          f'meta_size={meta:#x} file_size={fsz} num_entries={nent} flags={flags:#x}')

print('\nheader bytes 0x00-0x80, side by side (13.52 | 14.00 | differ?):')
for i in range(0, 0x80, 16):
    ra, rb = a[i:i+16], b[i:i+16]
    mark = ''.join('^' if ra[j] != rb[j] else '.' for j in range(16))
    print(f'  {i:#04x}  {ra.hex(" ")}  |  {rb.hex(" ")}   {mark}')

n = 0x2000
diffs = [i for i in range(min(len(a), len(b), n)) if a[i] != b[i]]
print(f'\nbytes differing in first {n:#x}: {len(diffs)}')
print(f'  offsets: {[hex(x) for x in diffs[:64]]}')

# --- look for a SHA-256 digest table in the plaintext header region ---
print('\nscanning first 0x1000 for runs of 32-byte high-entropy values (digest table):')
cand = []
for i in range(0, 0x1000 - 32, 32):
    blk = a[i:i+32]
    if len(set(blk)) > 20 and b[i:i+32] == blk:
        cand.append(i)
print(f'  32-byte blocks identical in both files: {len(cand)} at {[hex(x) for x in cand[:24]]}')
same32 = sum(1 for i in range(0, 0x2000, 32) if a[i:i+32] == b[i:i+32])
print(f'  of {(0x2000)//32} aligned 32B blocks in first 0x2000, identical: {same32}')

print()
print('=' * 72)
print('Q2. DO THE TWO KERNELS SHARE ANY LARGE IDENTICAL (ENCRYPTED) REGION?')
print('    Same key + same block position + same plaintext => same ciphertext.')
print('    So identical ciphertext runs imply unchanged plaintext.')
print('=' * 72)

STEP, SAMPLE = 0x8000, 96
probes = range(0, len(a) - SAMPLE, STEP)
found = []
for pos in probes:
    s = a[pos:pos + SAMPLE]
    if len(set(s)) < 8:          # skip degenerate filler runs
        continue
    j = b.find(s)
    if j != -1:
        found.append((pos, j, j - pos))
print(f'probes taken from 13.52: {len(list(probes))}   found verbatim in 14.00: {len(found)}')
if found:
    hist = collections.Counter(d for _, _, d in found)
    print('  delta histogram (pos_14.00 - pos_13.52):')
    for d, c in hist.most_common(10):
        print(f'    delta {d:>+8}  count {c}')
    print('  sample hits:')
    for pos, j, d in found[:12]:
        print(f'    13.52 {pos:#010x} -> 14.00 {j:#010x}  (delta {d:+})')
else:
    print('  none - no 96-byte region of the 13.52 encrypted body appears in 14.00')

# free-floating longest common substring, bounded, as a sanity check
def lcs_len(x, y, cap=4096):
    best = bi = 0
    prev = [0] * (len(y) + 1)
    for i in range(1, min(len(x), 300000) + 1):
        cur = [0] * (len(y) + 1)
        for j in range(1, min(len(y), 300000) + 1):
            if x[i-1] == y[j-1]:
                cur[j] = prev[j-1] + 1
                if cur[j] > best:
                    best, bi = cur[j], i - cur[j]
        prev = cur
    return best, bi

print('\n(longest-common-substring scan skipped: O(n*m) over 10 MB is not worth the wait;')
print(' the sample probe above is the meaningful test.)')
