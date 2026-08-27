import struct, re, json

d=open("/home/brandon/Documents/EDC17CP09/mpc_full.bin",'rb').read()
CODE_START, CODE_END = 0x020000, 0x180000

pats=[b'EWS',b'IMMO',b'IMMOB',b'CAS',b'KLINE',b'K-LINE',b'5BAUD',b'5BAUD',b'5 Baud',
      b'0x7E',b'0x7F',b'UDS',b'SED',b'Routine',b'routine','routine'.encode(),b'Immobilizer',
      b'immobilizer',b'seed',b'Seed',b'SEED',b'KEY',b'Key',b'key',b'auth',b'AUTH',b'Auth',
      b'FUEL PUMP',b'fuel pump',b'inhib',b'INHIB',b'start/stop',b'startstop',b'crank',
      b'CRANK',b'NO START',b'no start',b'EWS4',b'EWS_4',b'CCIT',b'CCF',b'DTC',b'0x0113',
      b'13',b'reject',b'REJECT',b'rejected',b'not authorized',b'unauthorized',b'password',
      b'0x3000',b'0x3E',b'0x27',b'0x2E',b'DID',b'did',b'0x0202',b'0x1200',b'0x28',b'0x10',
      b'securityAccess',b'secAccess',b'access',b'0x2701',b'0x2703',b'0x0100',b'0x2701']

found={}
for pat in sorted(set(pats)):
    idxs=[]
    start=0
    while True:
        i=d.find(pat,start)
        if i<0: break
        idxs.append(i); start=i+1
        if len(idxs)>40: break
    if idxs: found[pat.decode('latin1')]=idxs

def region(i):
    if CODE_START<=i<CODE_END: return 'CODE'
    if 0x180000<=i<0x1D0000: return 'CONFIG'
    if 0x1D0000<=i<0x1D9000: return 'TUNING'
    if 0x1D9000<=i<0x1DC000: return 'TUNING2'
    if 0x1DC000<=i<0x1FE000: return 'TUNING3'
    return 'OTHER'

for pat,idxs in found.items():
    reg={}
    for i in idxs: reg[region(i)]=reg.get(region(i),0)+1
    show=[hex(i) for i in idxs[:12]]
    print(f"[{region(idxs[0])}] {pat!r}: n={len(idxs)} {show}  {reg}")

# Now: strings in the CONFIG region (0x180000-0x1D0000) that mention immo-ish
print("\n=== printable strings >= 4 chars in 0x180000-0x190000 ===")
strings=re.findall(rb'[!-~]{4,}', d[0x180000:0x190000])
for s in strings[:80]:
    print('  ', s.decode('latin1'))
