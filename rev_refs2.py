import struct, json
from collections import defaultdict

d=open("/home/brandon/Documents/EDC17CP09/mpc_full.bin",'rb').read()
CODE_S, CODE_E = 0x020000, 0x180000

# 1) enumerate 32-bit LE words (4-byte aligned) in code that point into data space 0x180000-0x200000
refs=defaultdict(list)
for i in range(CODE_S, CODE_E-3, 4):
    v=struct.unpack_from('<I', d, i)[0]
    if 0x180000 <= v < 0x200000:
        refs[v].append(i)

top=sorted(refs.items(), key=lambda kv: (-len(kv[1]), kv[0]))
print("=== 32-bit abs refs from code -> data space (top 60 by count) ===")
for v,locs in top[:60]:
    print(f"  {v:#010x}  x{len(locs):3d}  first={[hex(x) for x in locs[:6]]}")

# 2) 24-bit imm form: TriCore abs24 = 0xRRRRRR where R=ref; check bytes pattern: word == (target & 0xFFFFFF)
refs24=defaultdict(list)
for i in range(CODE_S, CODE_E-3, 4):
    v=struct.unpack_from('<I', d, i)[0]
    if 0x180000 <= v < 0x1800000 and (v & 0xFFFF8000) == 0:  # top byte 0
        if 0x180000 <= v < 0x190000:  # focus on startup block first
            refs24[v].append(i)
print("\n=== 24-bit form refs into 0x180000-0x190000 (top 40) ===")
for v,locs in sorted(refs24.items(), key=lambda kv:-len(kv[1]))[:40]:
    print(f"  {v:#010x}  x{len(locs):3d}  {[hex(x) for x in locs[:6]]}")

json.dump({hex(k):[hex(x) for x in v] for k,v in refs.items()},
          open("/home/brandon/Documents/EDC17CP09/rev_config_refs.json","w"), indent=1)
print("\nsaved rev_config_refs.json with", len(refs), "unique targets")
