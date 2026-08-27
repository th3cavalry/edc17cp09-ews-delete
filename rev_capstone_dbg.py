import struct
import capstone as cs
d=open("/home/brandon/Documents/EDC17CP09/mpc_full.bin",'rb').read()
md=cs.Cs(cs.CS_ARCH_TRICORE, cs.CS_MODE_LITTLE_ENDIAN)
for off in range(0x8df00,0x8df40,4):
    w=struct.unpack_from('<I',d,off)[0]
    ins=list(md.disasm(d[off:off+4],off))
    if ins:
        i=ins[0]
        print(f"{off:#08x} {w:#010x}: {i.mnemonic} {i.op_str}")
    else:
        print(f"{off:#08x} {w:#010x}: <invalid>")
print("--- batch from 0x8df00 ---")
ins=list(md.disasm(d[0x8df00:0x8df40],0x8df00))
print("batch count:",len(ins))
for i in ins[:10]: print(hex(i.address), i.mnemonic, i.op_str)
