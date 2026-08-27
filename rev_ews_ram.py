import struct, json

d=open("/home/brandon/Documents/EDC17CP09/mpc_full.bin",'rb').read()
sw=json.load(open("/home/brandon/Documents/EDC17CP09/rev_sweep.json"))
CODE_S, CODE_E = 0x020000, 0x180000

# reconstruct function boundaries: entry = call target; region = entry..next entry
entries=set([CODE_S])
for b in sw['branches']:
    src,tgt,kind,op=b[0],b[1],b[2],b[3]
    if 'call' in kind:
        entries.add(tgt)
entries=sorted(e for e in entries if CODE_S<=e<=CODE_E)
def fn_of(addr):
    import bisect
    i=bisect.bisect_right(entries,addr)-1
    s=entries[i]
    e=entries[i+1] if i+1<len(entries) else CODE_E
    return s,e

ews_globals = {
  0xd000319f:"EWS_status_flag (&0x80 checked)",
  0xd00031a0:"EWS_status (set 0x80)",
  0xd0003586:"EWS_counter",
  0xd0003587:"EWS_counter2",
  0xd000356b:"EWS_key_src_lo",
  0xd000356c:"EWS_key_src_hi",
  0xd000090e:"EWS_task_flag",
  0xd0000933:"EWS_state_a",
  0xd0000929:"EWS_state_b",
  0xd0000932:"EWS_state_c",
  0xd0000917:"EWS_state_d",
  0xd0000915:"EWS_state_e",
  0xd000092d:"EWS_state_f",
  0xd000092c:"EWS_state_g",
  0xd0000923:"EWS_state_h",
  0xd000090d:"EWS_state_i",
  0xd0000906:"EWS_state_j",
  0xd0002432:"EWS_index",
  0xd000359e:"EWS_table",
  0xd00035ce:"EWS_keybuf_a",
  0xd00035ae:"EWS_keybuf_b",
  0xd00035be:"EWS_keybuf_c",
}

from collections import defaultdict
fnhits=defaultdict(list)
print("=== code refs to EWS RAM globals ===")
for addr,name in ews_globals.items():
    pat=struct.pack('<I',addr)
    off=CODE_S; hits=[]
    while True:
        i=d.find(pat,off,CODE_E)
        if i<0: break
        hits.append(i); off=i+1
    for h in hits:
        s,e=fn_of(h)
        fnhits[(s,e)].append((h,name))
    if hits:
        print(f"{name:28s} {addr:#x}: {len(hits)} hits")

print("\n=== functions referencing EWS globals (fuel-gate candidates) ===")
rank=sorted(fnhits.items(), key=lambda kv:-len(kv[1]))
for (s,e),lst in rank[:40]:
    names=sorted(set(n for _,n in lst))
    print(f"  fn [{s:#08x}-{e:#08x}] size={e-s:#05x}  refs={len(lst):2d}  {names[:6]}")

json.dump({f"{s:#x}-{e:#x}":[[h,n] for h,n in v] for (s,e),v in fnhits.items()},
          open("/home/brandon/Documents/EDC17CP09/ews_ram_refs.json","w"), indent=1)
