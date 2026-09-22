"""Check two 13.52 globals the reference needs, using the v10 window already on disk.

On 5.05 the layout is:
    sceSblAuthMgrModuleId  0x02768310
    authmgr_sm_xlock       0x027680D0
    self_ctx_status        0x02768140   (uint32_t[4] = 0x10 bytes)
    self_contexts          0x02768150   (self_context_t, stride 0x60)

self_ctx_status sits exactly 0x10 before self_contexts. We hardware-confirmed
self_contexts at koff 0x269C140 with stride 0x60, so self_ctx_status should be
at 0x269C130. Check that, and re-read the module-id global.
"""
import struct

DUMP = r'C:\Users\Kinan\Downloads\JV13.52\v10_kmem_img.bin'
WIN = 0x02680000
d = open(DUMP, 'rb').read()

K = lambda ko: ko - WIN


def u32(ko):
    return struct.unpack_from('<I', d, K(ko))[0]


def u64(ko):
    return struct.unpack_from('<Q', d, K(ko))[0]


print("=== self_ctx_status candidate @ 0x269C130 (expect 4 statuses: 3 = free) ===")
print(f"  u32[4] = {[u32(0x0269C130 + 4*i) for i in range(4)]}")
print("  5.05 semantics: 3 = free context, 1/2 = in use")

print("\n=== self_contexts @ 0x269C140 (stride 0x60), fields per self_context_t ===")
FIELDS = [('format', 0x00, 'I'), ('elf_auth_type', 0x04, 'I'),
          ('total_header_size', 0x08, 'I'), ('unk_0C', 0x0C, 'I'),
          ('segment', 0x10, 'Q'), ('unk_18', 0x18, 'I'),
          ('ctx_id', 0x1C, 'I'), ('svc_id', 0x20, 'Q'),
          ('unk_28', 0x28, 'Q'), ('buf_id', 0x30, 'I'),
          ('unk_34', 0x34, 'I'), ('header', 0x38, 'Q')]
for i in range(4):
    base = 0x0269C140 + i * 0x60
    vals = []
    for name, off, fmt in FIELDS:
        v = struct.unpack_from('<' + fmt, d, K(base + off))[0]
        if v:
            vals.append(f"{name}=0x{v:x}")
    print(f"  ctx[{i}] @0x{base:x}: " + "  ".join(vals))

print("\n=== sceSblAuthMgrModuleId @ 0x269C0A0 ===")
print(f"  as u64 = 0x{u64(0x0269C0A0):x}")
print(f"  as u32 = 0x{u32(0x0269C0A0):x}")
print("  (the kernel loads this VALUE and passes it to sceSblServiceMailbox)")

print("\n=== 0x88 staging buffers (pointers at 0x269C0B0 / 0x269C0C0) ===")
for name, ko in [('BUF_A ptr @0x269C0B0', 0x0269C0B0),
                 ('BUF_B ptr @0x269C0C0', 0x0269C0C0)]:
    print(f"  {name} = 0x{u64(ko):x}")
