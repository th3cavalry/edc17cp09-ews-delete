#!/usr/bin/env python3
"""Linear sweep disassembler for EDC17CP09 TC1796 app code.
Word-by-word decode; on invalid word skip 4 bytes (data gap).
Collects: function boundaries (ret), branch/call targets, indexed [an]#off ops,
absolute data refs. Emits JSON + per-function text for the region of interest.
"""
import struct, json, sys
import capstone as cs

IMG="/home/brandon/Documents/EDC17CP09/mpc_full.bin"
d=open(IMG,'rb').read()
CODE_S,CODE_E=0x020000,0x180000
CFG_LO,CFG_HI=0x180000,0x200000
md=cs.Cs(cs.CS_ARCH_TRICORE, cs.CS_MODE_LITTLE_ENDIAN)
md.skipdata=True

# sweep
rets=[]
branches=[]       # (src, dst, kind)
indexed=[]        # (addr, opstr)  [an]#off
absrefs=[]        # (addr, val)
instrcount=0
badcount=0
addrs={}          # addr -> (mnemonic, opstr)

i=CODE_S
end=CODE_E
while i<end-3:
    w=struct.unpack_from('<I',d,i)[0]
    ins=list(md.disasm(d[i:i+4],i))
    if not ins:
        badcount+=1
        i+=4
        continue
    x=ins[0]
    m,o=x.mnemonic,x.op_str
    addrs[x.address]=(m,o)
    instrcount+=1
    if m=='ret':
        rets.append(x.address)
    if m.startswith('j') and m not in ('jbsr',) and x.address not in (None,):
        # extract target after last #
        if '#' in o:
            tgt=int(o.split('#')[-1].split(',')[0].strip(),16)
            branches.append((x.address,tgt,m,o))
    if '][' in o or ('#' in o and ('a1' in o or 'a2' in o or 'a3' in o or 'a4' in o or 'a5' in o or 'a6' in o)):
        indexed.append((x.address,o))
    # absolute data refs: ld/st with #0x1xxxxx
    if m.startswith(('ld','st')):
        for tok in o.split(','):
            t=tok.strip().lstrip('[]#')
            try:
                v=int(t,16)
            except ValueError:
                continue
            if CFG_LO<=v<CFG_HI:
                absrefs.append((x.address,v))
    i+=4

print(f"swept {CODE_E-CODE_S:#x} bytes: {instrcount} instrs, {badcount} invalid words")
print(f"rets: {len(rets)}  branches: {len(branches)}  indexed: {len(indexed)}  absrefs: {len(absrefs)}")

# function boundaries: start = ret+4 (or code start), end=ret
func_starts=sorted(set([(r+4)&~0x3 for r in rets]))
# build function containing 0x8df14
def func_of(a):
    starts=[s for s in func_starts if s<=a]
    return max(starts) if starts else CODE_S

fs=func_of(0x8df14)
# find end: first ret >= fs
fend=min([r for r in rets if r>=fs])
print(f"\nfunction around 0x8df14: {fs:#x} .. {fend:#x} ({(fend-fs)//4} words)")

out=open("/home/brandon/Documents/EDC17CP09/func_8df14.txt","w")
for a in range(fs,fend+4,4):
    m,o=addrs.get(a,('?','?'))
    note=''
    # annotate config-ish
    for tok in o.split(','):
        t=tok.strip().lstrip('[]#')
        try:
            v=int(t,16)
        except ValueError:
            continue
        if CFG_LO<=v<CFG_HI:
            note+=f'  ; ->{v:#x}'
    out.write(f"{a:08x}:  {m:12s} {o}{note}\n")
out.close()
print("wrote func_8df14.txt")

# how is a4 set in this function?
print("\n=== a4/a5/a6 setup + all [an]#off in this function ===")
for a in range(fs,fend+4,4):
    m,o=addrs.get(a,('?',''))
    if ('a4' in o and m.startswith(('mov','ld'))) or ('[a4]' in o) or ('[a5]' in o):
        print(f"{a:08x}:  {m} {o}")

json.dump({"rets":[hex(x) for x in rets],"branches":[[hex(a),hex(t),m,o] for a,t,m,o in branches],
           "absrefs":[[hex(a),hex(v)] for a,v in absrefs]},
          open("/home/brandon/Documents/EDC17CP09/rev_sweep.json","w"))
print("\nsaved rev_sweep.json")
