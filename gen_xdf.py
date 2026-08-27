#!/usr/bin/env python3
"""
Generate a TunerPro XDF for a BMW M57 EDC17CP09 (HW 0281017487) from
OpenRemap auto-detected tables + the ECU ident/config block.

Map labels are RECONSTRUCTED from axis shape/spacing and must be
verified against a dyno datalog before any tuning. Addresses, sizes and
endianness (little, 16-bit) come from the scan of the real stock file,
so tables will line up in TunerPro.
"""
import json, struct

BIN = "/home/brandon/Documents/EDC17CP09/mpc_full.bin"
SCAN = "/home/brandon/Documents/EDC17CP09/scan_mpc.json"
OUT = "/home/brandon/Documents/EDC17CP09/EDC17CP09_M57_0281017487.xdf"

d = open(BIN, 'rb').read()
scan = json.load(open(SCAN))
tables = sorted(scan["tables"], key=lambda t: t["offset"])

SW1 = "10375506116137U6A"   # config-block SW number @0x18001A
SW2 = "10375135896137T6A"   # application SW @0x14001A
HW = "0281017487"
PART = "1039S46986"
VIN = "".join(chr(d[0x180099+i]) for i in range(17))

def axis_kind(vals):
    if not vals:
        return ("?", "X*1.0")
    lo, hi = min(vals), max(vals); span = hi - lo
    diffs = [vals[i+1] - vals[i] for i in range(len(vals)-1)]
    step = max(set(diffs), key=diffs.count) if diffs else 0
    if span >= 1500 and lo >= 0 and hi <= 12000:
        return ("RPM", "X*1.0")
    if 90 <= lo and hi <= 400 and span >= 40:
        return ("mbar (MAP)", "X*1.0")
    if lo <= 20 and hi <= 120 and span <= 100 and abs(step) <= 10:
        return ("degC", "X*1.0")
    if lo >= 0 and hi <= 100 and step in (1, 2, 5):
        return ("percent", "X*1.0")
    if span > 500 and hi <= 15000:
        return ("mg/stroke", "X*0.1")
    return ("?", "X*1.0")

def category_for(t):
    o = t['offset']
    xv = [struct.unpack_from('<h', d, t['x_axis_offset']+i*2)[0] for i in range(t['cols'])]
    yv = [struct.unpack_from('<h', d, t['y_axis_offset']+i*2)[0] for i in range(t['rows'])]
    xu = axis_kind(xv)[0]; yu = axis_kind(yv)[0]
    if o < 0x040000:
        return "Fuel / request"
    if xu == "RPM" and yu == "RPM":
        return "Torque / limiters (RPM x RPM)"
    if xu == "RPM" and yu.startswith("mbar"):
        return "Injection (RPM x MAP)"
    if xu.startswith("mbar") and yu == "RPM":
        return "Boost / VNT (MAP x RPM)"
    if yu == "RPM":
        return "Maps (x ? x RPM)"
    return "Other"

CATS = {}
def cat_id(name):
    if name not in CATS:
        CATS[name] = 0x10 + len(CATS)
    return CATS[name]

def esc(s):
    return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

# ---- build table elements ----
body = []
uid = 0x200
for t in tables:
    o = t['offset']; c = t['cols']; r = t['rows']
    xoff = t['x_axis_offset']; yoff = t['y_axis_offset']
    xv = [struct.unpack_from('<h', d, xoff+i*2)[0] for i in range(c)]
    yv = [struct.unpack_from('<h', d, yoff+i*2)[0] for i in range(r)]
    xu, xm = axis_kind(xv); yu, ym = axis_kind(yv)
    cat = category_for(t); cid = cat_id(cat)
    uid += 1
    body.append(f'''  <XDFTABLE uniqueid="0x{uid:04x}" flags="0x30">
    <title>Map 0x{o:08X} ({r} rows x {c} cols) | {cat}</title>
    <description>Auto-detected from scan of HW {HW} stock read. X-axis: {xu} [{min(xv)}..{max(xv)}]; Y-axis: {yu} [{min(yv)}..{max(yv)}]. VERIFY axis meaning against a datalog before tuning.</description>
    <CATEGORYMEM index="0" category="0x{cid:02x}" />
    <XDFAXIS id="x" uniqueid="0x{uid:04x}">
      <EMBEDDEDDATA mmedaddress="0x{xoff:08X}" mmedelementsizebits="16" mmedcolcount="{c}" mmedmajorstridebits="16" />
      <units>{esc(xu)}</units>
      <indexcount>{c}</indexcount>
      <DATEFROM expression="{xm}" />
      <MATH equation="{xm}" />
    </XDFAXIS>
    <XDFAXIS id="y" uniqueid="0x{uid:04x}">
      <EMBEDDEDDATA mmedaddress="0x{yoff:08X}" mmedelementsizebits="16" mmedrowcount="{r}" mmedmajorstridebits="16" />
      <units>{esc(yu)}</units>
      <indexcount>{r}</indexcount>
      <DATEFROM expression="{ym}" />
      <MATH equation="{ym}" />
    </XDFAXIS>
    <XDFAXIS id="z">
      <EMBEDDEDDATA mmedaddress="0x{o:08X}" mmedelementsizebits="16" mmedrowcount="{r}" mmedcolcount="{c}" mmedmajorstridebits="16" />
      <units>raw</units>
      <MATH equation="X*1.0" />
    </XDFAXIS>
  </XDFTABLE>''')

# ---- ident/config constants ----
ident_tables = f'''  <!-- ============ ECU IDENT / CONFIG / EWS / CVN (reference) ============ -->
  <XDFTABLE uniqueid="0x0010" flags="0x10">
    <title>Startup Block Header @0x180000</title>
    <description>Block size + CRC pointer region. EWS/immobilizer auth area begins 0x180034.</description>
    <CATEGORYMEM index="0" category="0x{cat_id('Config / EWS / VIN')}" />
    <XDFAXIS id="z">
      <EMBEDDEDDATA mmedaddress="0x180000" mmedelementsizebits="16" mmedrowcount="1" mmedcolcount="16" />
      <units>raw</units>
      <MATH equation="X*1.0" />
    </XDFAXIS>
  </XDFTABLE>
  <XDFTABLE uniqueid="0x0011" flags="0x10">
    <title>Config SW #1 @0x18001A</title>
    <description>ASCII software identifier: {SW1}</description>
    <CATEGORYMEM index="0" category="0x{cat_id('Config / EWS / VIN')}" />
    <XDFAXIS id="z">
      <EMBEDDEDDATA mmedaddress="0x18001A" mmedelementsizebits="8" mmedrowcount="1" mmedcolcount="16" />
      <units>ascii</units>
      <MATH equation="X*1.0" />
    </XDFAXIS>
  </XDFTABLE>
  <XDFTABLE uniqueid="0x0012" flags="0x10">
    <title>VIN @0x180099</title>
    <description>Vehicle Identification Number (ASCII). Currently: {esc(VIN)}</description>
    <CATEGORYMEM index="0" category="0x{cat_id('Config / EWS / VIN')}" />
    <XDFAXIS id="z">
      <EMBEDDEDDATA mmedaddress="0x180099" mmedelementsizebits="8" mmedrowcount="1" mmedcolcount="17" />
      <units>ascii</units>
      <MATH equation="X*1.0" />
    </XDFAXIS>
  </XDFTABLE>
  <XDFTABLE uniqueid="0x0013" flags="0x10">
    <title>HW / Part @0x00FD00</title>
    <description>Hardware number + BMW part: {esc(HW)} / {esc(PART)}</description>
    <CATEGORYMEM index="0" category="0x{cat_id('Config / EWS / VIN')}" />
    <XDFAXIS id="z">
      <EMBEDDEDDATA mmedaddress="0x00FD00" mmedelementsizebits="8" mmedrowcount="1" mmedcolcount="22" />
      <units>ascii</units>
      <MATH equation="X*1.0" />
    </XDFAXIS>
  </XDFTABLE>
  <XDFTABLE uniqueid="0x0014" flags="0x10">
    <title>CVN Checksum @0x1FE90C</title>
    <description>Calibration Verification Number (CVN) for this software version. Recompute after edits.</description>
    <CATEGORYMEM index="0" category="0x{cat_id('Config / EWS / VIN')}" />
    <XDFAXIS id="z">
      <EMBEDDEDDATA mmedaddress="0x1FE90C" mmedelementsizebits="32" mmedrowcount="1" mmedcolcount="1" />
      <units>raw</units>
      <MATH equation="X*1.0" />
    </XDFAXIS>
  </XDFTABLE>
'''

# ---- categories ----
cat_xml = ""
for name, cid in CATS.items():
    cat_xml += f'    <CATEGORY index="0x{cid:02x}" name="{esc(name)}" />\n'

# ---- assemble ----
full = f'''<?xml version="1.0"?>
<!--
  BMW M57 EDC17CP09 - RECONSTRUCTED TunerPro XDF
  HW: {HW}   Part: {PART}
  SW (config): {SW1}   SW (app): {SW2}
  File: 2,097,152 bytes (0x200000) stock read, all 11 checksums valid.

  TABLE LABELS ARE RECONSTRUCTED FROM AXIS SHAPE/SPACING.
  VERIFY against a dyno datalog before tuning. Addresses, sizes and
  endianness (little-endian, 16-bit) come from a direct scan of this stock file.

  Flash regions & checksums (recompute ALL after any edit):
    0x000000-0x003FFF  Dataset #1    ADD32  @0x34
    0x004000-0x00E803  Customer blk   CRC32  @0x4034, @0x4054
    0x014000-0x017EFF  TuneProtect    CRC32  @0x14034
    0x018000-0x01FEFF  Startup blk    CRC32  @0x18034, @0x18054  (EWS/VIN/CVN)
    0x020000-0x17FF03  App SW         ADD32  @0x20034, @0x20054, @0x20074
-->
<XDFFORMAT version="1.60">
  <XDFHEADER>
    <flags>0x1</flags>
    <deftitle>BMW M57 EDC17CP09 {HW} (stock reconstructed)</deftitle>
    <description>Reconstructed EDC17CP09 M57 definition from OpenRemap scan of a stock 2011 X5 read. Map labels verified by axis shape only - confirm on a dyno before tuning.</description>
    <author>REX (Hermes) - generated from scan of HW {HW}</author>
    <BASEOFFSET offset="0" subtract="0" />
    <DEFAULTS datasizeinbits="16" sigdigits="4" outputtype="1" signed="0" lsbfirst="1" float="0" />
    <REGION type="0xFFFFFFFF" startaddress="0x0" size="0x200000" regionflags="0x0" name="Binary File" desc="2MB EDC17CP09 flash (TC1796)" />
{cat_xml}  </XDFHEADER>
{ident_tables}
''' + "\n".join(body) + """
</XDFFORMAT>
"""

open(OUT, 'w').write(full)
print("WROTE", OUT, len(full), "bytes")
print("tables (XDFTABLE):", len(tables) + 5, "(40 scan tables + 5 ident constants)")
print("categories:", list(CATS.keys()))
print("VIN:", VIN, "| SW:", SW1)
