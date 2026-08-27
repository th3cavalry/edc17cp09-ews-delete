import struct, re, json

d=open("/home/brandon/Documents/EDC17CP09/mpc_full.bin",'rb').read()
CODE_S, CODE_E = 0x020000, 0x180000

def find_all(pat, lo, hi, cap=200):
    out=[]; start=lo
    while len(out)<cap:
        i=d.find(pat,start,hi)
        if i<0: break
        out.append(i); start=i+1
    return out

# 1) absolute-address immediates (24-bit and 32-bit LE) pointing at the EWS/startup data block
addr_hits={}
for target in range(0x180040, 0x180100):
    a24=struct.pack('<I',target)[:3]          # 24-bit LE
    a32=struct.pack('<I',target)              # 32-bit LE
    h24=find_all(a24, CODE_S, CODE_E, 20)
    h32=find_all(a32, CODE_S, CODE_E, 20)
    if h24 or h32:
        addr_hits[hex(target)]={'a24':[hex(x) for x in h24], 'a32':[hex(x) for x in h32]}
print("=== code refs to EWS-data addresses (0x180040-0x1800FF) ===")
for k in sorted(addr_hits): print(' ',k,addr_hits[k])

# 2) the EWS key bytes and variants
key=bytes([0xFB,0x41,0xAC,0x86])
print("\n=== key byte searches (full image) ===")
for name,pat in [('FB41AC86 (LE)',key), ('86AC41FB (BE)',bytes([0x86,0xAC,0x41,0xFB])),
                 ('FB41',key[:2]), ('AC86',key[2:]),
                 ('86AC',bytes([0x86,0xAC])), ('41FB',bytes([0x41,0xFB]))]:
    h=find_all(pat,0,0x200000,30)
    incode=[hex(x) for x in h if CODE_S<=x<CODE_E]
    print(f'  {name}: n={len(h)} code={incode} other={[hex(x) for x in h if not (CODE_S<=x<CODE_E)][:8]}')

# 3) CVN 0x996D8667 variants in code
cvn=struct.pack('<I',0x996D8667)
print("\n=== CVN 996D8667 in code ===")
h=find_all(cvn,CODE_S,CODE_E,30)
print('  LE:', [hex(x) for x in h])
h2=find_all(bytes([0x67,0x86,0x6D,0x99]),CODE_S,CODE_E,30)
print('  BE:', [hex(x) for x in h2])

# 4) the startup header 11 53 55 43 (magic seen at 0x180034) as a code constant
h3=find_all(bytes([0x11,0x53,0x55,0x43]),CODE_S,CODE_E,30)
print("\n=== startup-magic 11535543 in code ===")
print('  ', [hex(x) for x in h3])

# 5) CRC pointers (0x0D35B4, 0x0D7180) — the code must reference these
for lbl,v in [('crcptr1 0x0D35B4',0x0D35B4),('crcptr2 0x0D7180',0x0D7180),
              ('startup 0x180034',0x180034),('EWSkey 0x180074',0x180074)]:
    v24=struct.pack('<I',v)[:3]; v32=struct.pack('<I',v)
    h24=find_all(v24,CODE_S,CODE_E,20); h32=find_all(v32,CODE_S,CODE_E,20)
    print(f'  {lbl}: a24={[hex(x) for x in h24]} a32={[hex(x) for x in h32]}')
