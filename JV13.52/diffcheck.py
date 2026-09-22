data = open(r'C:\Users\Kinan\Downloads\czdji0\1352k.elf', 'rb').read()
names = ['mailbox', 'smreq', 'authhdr', 'load', 'fin', 'isload']
kos = [0x00630230, 0x0063fff0, 0x00642c90, 0x006434d0, 0x00643370, 0x00642880]

print("how many bytes before all six are distinguishable:")
for n in (8, 12, 16, 20, 24, 32, 40, 48, 64):
    pre = [data[k:k + n] for k in kos]
    print(f"  {n:3} bytes -> {len(set(pre))} distinct of 6")

print("\n32-byte prefixes:")
for i, k in enumerate(kos):
    print(f"  F{i} {data[k:k+32].hex()}   {names[i]}")
