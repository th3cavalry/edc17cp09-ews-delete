import json
s=json.load(open("/home/brandon/Documents/EDC17CP09/rev_sweep.json"))
# branches: list of [src,tgt,kind,op]
# We want instructions that READ [a4]#0x40 and are followed by a branch.
# But sweep json only stored branches. Let me re-scan the image for the auth pattern directly.
import struct
import capstone as cs
d=open("/home/brandon/Documents/EDC17CP09/mpc_full.bin",'rb').read()
md=cs.Cs(cs.CS_ARCH_TRICORE, cs.CS_MODE_LITTLE_ENDIAN)
md.skipdata=True
CODE_S,CODE_E=0x020000,0x180000

# collect a linear list of (addr, mnem, op) for quick local inspection
ins={}
i=CODE_S
while i<CODE_E-3:
    w=struct.unpack_from('<I',d,i)[0]
    r=list(md.disasm(d[i:i+4],i))
    if r:
        ins[i]=(r[0].mnemonic,r[0].op_str)
    i+=4

def ctx(addr, n=6):
    """print instructions addr..addr+n*4 with branch targets resolved-ish"""
    out=[]
    for a in range(addr, addr+n*4, 4):
        m,o=ins.get(a,('?','?'))
        tgt=''
        if m.startswith('j') and '#' in o:
            tgt=int(o.split('#')[-1].split(',')[0].strip(),16)
            tgt=f" -> {tgt:#x}"
        out.append((a,m,o,tgt))
    return out

# Find all 'ld' instructions reading [a4]#0x40 or [a4]#0x3f/0x41 (EWS key region)
hits=[]
for a,(m,o) in ins.items():
    if m.startswith('ld') and ('[a4]#0x40' in o or '[a4]#0x3f' in o or '[a4]#0x41' in o
        or '[a4]#0x42' in o):
        hits.append(a)
print(f"reads of [a4]#0x40-ish: {len(hits)}")
for h in sorted(hits):
    print(f"\n===== read at {h:#x} =====")
    for a,m,o,t in ctx(h, 12):
        flag = "  <<< EWSKEY" if ('[a4]#0x4' in o and m.startswith('ld')) else ""
        print(f"  {a:08x}:  {m:10s} {o}{t}{flag}")
