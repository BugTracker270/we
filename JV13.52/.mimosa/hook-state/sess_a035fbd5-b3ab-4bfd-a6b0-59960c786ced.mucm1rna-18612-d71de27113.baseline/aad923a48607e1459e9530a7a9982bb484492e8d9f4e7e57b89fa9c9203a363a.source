data = open(r'C:\Users\Kinan\Downloads\czdji0\1352k.elf', 'rb').read()
names = ["mailbox", "smreq", "authhdr", "load", "fin", "isload"]
kos = [0x00630230, 0x0063fff0, 0x00642c90, 0x006434d0, 0x00643370, 0x00642880]
print("expected 16-byte prefixes from 1352k.elf:")
for i, ko in enumerate(kos):
    print(f"  F{i} {data[ko:ko+16].hex()}   ({names[i]})")
