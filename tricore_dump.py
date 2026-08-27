#!/usr/bin/env python3
"""TriCore (TC1796) disassembler for EDC17CP09 firmware with cross-ref comments.

Usage: tricore_dump.py START END [STEP]
Disassembles linearly; annotates immediates/offsets that fall in the
config/data regions, and flags jump/call targets.
"""
import sys, struct
import capstone as cs

IMG = "/home/brandon/Documents/EDC17CP09/mpc_full.bin"

CFG_START, CFG_END = 0x180000, 0x200000   # data space
CODE_S, CODE_E = 0x020000, 0x180000       # app code

def main():
    a = int(sys.argv[1], 0)
    b = int(sys.argv[2], 0)
    step = int(sys.argv[3], 0) if len(sys.argv) > 3 else 4
    d = open(IMG, 'rb').read()
    md = cs.Cs(cs.CS_ARCH_TRICORE, cs.CS_MODE_LITTLE_ENDIAN)
    md.detail = False

    # known config fields for annotation
    fields = {
        0x180034: 'STARTUP_HDR', 0x180040: 'EWS_BLK0', 0x180041: 'EWS_FIELD0',
        0x18004F: 'EWS_FIELD1', 0x180059: 'EWS_FIELD2', 0x18005D: 'EWS_FIELD3',
        0x180064: 'EWS_FIELD4', 0x18006A: 'EWS_FIELD5', 0x18006D: 'EWS_FIELD6',
        0x18006F: 'EWS_FIELD7', 0x180074: 'EWS_KEY', 0x18007B: 'EWS_FIELD8',
        0x180080: 'EWS_FIELD9', 0x180088: 'EWS_FIELD10', 0x180093: 'VIN',
        0x180098: 'VIN_END', 0x180099: 'VIN_START2', 0x1800A2: 'EWS_FIELD11',
        0x1800AB: 'EWS_FIELD12', 0x1800AF: 'EWS_FIELD13', 0x1800BD: 'TP_BLK0',
        0x1800C0: 'TP_BLK_START', 0x1800D0: 'TP_BLK_PTR', 0x1800DF: 'TP_BLK_PTR2',
        0x1800FF: 'CFG_END',
    }

    def note(off, imm):
        """Return annotation if imm points into config region."""
        if imm is None: return ''
        # absolute?
        if CFG_START <= imm < CFG_END:
            near = min(fields.keys(), key=lambda k: abs(k - imm))
            if abs(near - imm) <= 0x40:
                return f'  ; -> {imm:#x} ({fields[near]})'
            return f'  ; -> {imm:#x}'
        # base+offset with base 0x180000: check imm itself small
        if 0 <= imm < 0x1000 and (a + 0) > 0:  # candidate offset
            tgt = 0x180000 + imm
            if CFG_START <= tgt < CFG_END:
                near = min(fields.keys(), key=lambda k: abs(k - tgt))
                if abs(near - tgt) <= 0x40:
                    return f'  ; 0x180000+{imm:#x} = {tgt:#x} ({fields[near]})'
        return ''

    code = d[a:b]
    for i in md.disasm(code, a):
        line = f"{i.address:08x}:  {i.bytes.hex():<28}  {i.mnemonic:12s} {i.op_str}"
        # scan immediates for config refs
        for part in i.op_str.split(','):
            for tok in part.split('+'):
                t = tok.strip().lstrip('#')
                try:
                    v = int(t, 16)
                except ValueError:
                    continue
                n = note(i.address, v)
                if n:
                    line += n
                    break
        print(line)

if __name__ == '__main__':
    main()
