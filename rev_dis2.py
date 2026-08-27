#!/usr/bin/env python3
"""Improved TriCore disassembler: feed whole buffers so capstone handles
packed 20-bit instructions. Focus on EWS/config functions."""
import struct, sys
import capstone as cs

d=open("/home/brandon/Documents/EDC17CP09/mpc_full.bin",'rb').read()
md=cs.Cs(cs.CS_ARCH_TRICORE, cs.CS_MODE_LITTLE_ENDIAN)
md.detail=True

def dis(region, start, size, label):
    print(f"\n########## {label}  [{start:#x} +{size:#x}] ##########")
    buf=d[start:start+size]
    # Try to disassemble; capstone returns what it can
    ok=0; bad=0
    for i in md.disasm(buf, start):
        line=f"{i.address:08x}:  {i.bytes.hex():<24}  {i.mnemonic:10s} {i.op_str}"
        # annotate config access [an]#off -> 0x180034+off
        op=i.op_str
        if '#' in op:
            for tok in op.split(','):
                t=tok.strip()
                if t.startswith('#') and ']' not in t:
                    try:
                        v=int(t[1:],16)
                    except: continue
                    # if it looks like a config offset
                    if 0x00 <= v <= 0xff:
                        tgt=0x180034+v
                        if 0x180000<=tgt<0x190000:
                            line+=f"   ; cfg {tgt:#x}"
                            break
        print(line)
        ok+=1

# 1) the function that loads the EWS key pair -> 0x113e0c. Find its start via prev ret.
#    Just dump a window around it with whole-buffer decode.
dis(d, 0x113dc0, 0xc0, "EWS key loader ~0x113e0c")
dis(d, 0x8de00, 0x180, "config parse fn 0x8de00-0x8ef80")
