import struct

A = r'C:\Users\Kinan\Downloads\JV13.52\dec\1352\80010002.self'
B = r'C:\Users\Kinan\Downloads\JV13.52\dec\80010002_kernel_14.00.self'
da = open(A, 'rb').read(0x110)
db = open(B, 'rb').read(0x110)

print('offset   13.52                    14.00')
for i in range(0xB0, 0x100, 8):
    ha = ' '.join('%02x' % c for c in da[i:i + 8])
    hb = ' '.join('%02x' % c for c in db[i:i + 8])
    print(f'{i:#05x}   {ha}      {hb}')

print()
for i in range(0xB8, 0x100, 8):
    va = struct.unpack_from('<Q', da, i)[0]
    vb = struct.unpack_from('<Q', db, i)[0]
    print(f'u64 @{i:#05x}:  {va:#018x}   {vb:#018x}')

print()
print('reading high 32 bits as BCD firmware (0x1352 -> 13.52, 0x1400 -> 14.00):')
for nm, d in (('13.52', da), ('14.00', db)):
    for off in (0xD0, 0xD8):
        v = struct.unpack_from('<Q', d, off)[0]
        hi = (v >> 32) & 0xFFFFFFFF
        print(f'  {nm} @{off:#05x}: hi32 = {hi:#010x}  -> {hi >> 12 & 0xF}{(hi >> 8) & 0xF}.'
              f'{(hi >> 4) & 0xF}{hi & 0xF}')

print()
print('bytes 0xE0..0x100 (candidate ELF digest), 13.52:')
print('  ' + da[0xE0:0x100].hex())
print('bytes 0xE0..0x100, 14.00:')
print('  ' + db[0xE0:0x100].hex())
print('bytes 0xD8..0xF8, 13.52:')
print('  ' + da[0xD8:0xF8].hex())
print('bytes 0xD8..0xF8, 14.00:')
print('  ' + db[0xD8:0xF8].hex())
