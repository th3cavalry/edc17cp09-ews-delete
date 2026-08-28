#!/usr/bin/env python3
"""
EDC17CP09 Community Release XDF generator (v1.0).

Iterates through the merged master dataset (master_dataset.json) and emits a
complete classic TunerPro XDF (version 1.60 dialect, as used by the GM/LS XDFs
and compatible with TunerPro v9/v10):

    <XDFFORMAT version="1.60">
      <XDFHEADER> flags/fileversion/deftitle/description/author
                  BASEOFFSET / DEFAULTS / REGION
                  <CATEGORY index name/> per Bosch-taxonomy folder
      <TABLEINFO>
        <XDFTABLE uniqueid flags> per master entry
          <title>/<description>/<CATEGORYMEM>
          <XDFAXIS id="x"/"y"/"z">   <- Xaxis, Yaxis, Zaxis nodes, always all three
            <EMBEDDEDDATA .../>      (real flash address for embedded axes,
                                      negative majorstride for linear index axes)
            <indexcount>/<units>/<min>/<max>/<outputtype>
            <LABEL .../>             (real axis values where stored, else index)
            <MATH equation="X"><VAR id="X"/></MATH>

Auto-categorization (Bosch taxonomy):
  * DFES / DTC maps            -> DTC Masks
  * EWS candidates + WFS scalars-> Immobilizer/Security
  * Driver's Wish 1D ADC curves -> Driver's Wish
  * Emissions / Torque / Rail / Injection kept as their own folders
  * Scalars -> Scalar/Config, everything else -> Engine Maps

Honesty rules (from prior corrections):
  * <Xaxis> points at a real axis offset ONLY for the 60 Driver's Wish ADC
    curves, which physically store [count][axis xN][values xN] in flash
    (verified against mpc_full.bin).
  * All other 1D/2D maps are flat value arrays with NO stored axis: they get a
    linear index axis (EMBEDDEDDATA without mmedaddress, negative
    majorstridebits) - no fabricated offsets.
  * EMBEDDEDDATA.mmedaddress on the Z axis is always the real calib address.

Data source: mpc_full.bin = 2 MB X5 35d flash dump; offsets are absolute
flash addresses (BASEOFFSET 0).
"""
import json
import os
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
MASTER = os.path.join(HERE, "master_dataset.json")
OUT = os.path.join(HERE, "EDC17CP09_Community_Release_v1.xdf")

TITLE = "EDC17CP09 (M57 3.0d, HW 0281017487) - Community Release v1.0"
DESC = (
    "BMW EDC17CP09 M57N2 X5 35d (US) - 2MB flash dump (mpc_full.bin).\n"
    "1,336 calibration objects located by TriCore pointer sweep (Capstone/Ghidra)\n"
    "plus 530d OLS cross-reference. 956 1D curves, 172 scalars, 122 DTC/mask\n"
    "arrays, 86 2D grids. Axis values verified where physically stored in flash.\n"
    "Labels/units are best-effort from Bosch taxonomy - verify before tuning."
)
AUTHOR = "Th3cavalry / Hermes"

# ---------------------------------------------------------------- categories
# Ordered; index used in CATEGORYMEM (decimal) and CATEGORY (hex).
CATEGORIES = [
    "DTC Masks",
    "Immobilizer/Security",
    "Driver's Wish",
    "Emissions",
    "Torque/Limiter",
    "Rail Pressure",
    "Injection",
    "Scalar/Config",
    "Engine Maps",
]
CAT_IDX = {c: i for i, c in enumerate(CATEGORIES)}

# ---------------------------------------------------------------- helpers
def parse_dims(d):
    """'3x1' -> (3,1); '1x1 (2 bytes)' -> (1,1); 'Nx2 mask array' -> None; '3x3'->(3,3)"""
    d = d.strip()
    if d.endswith("(2 bytes)"):
        return (1, 1)
    if d.startswith("N"):
        return None
    if "x" in d:
        a, b = d.split("x")
        try:
            return (int(a), int(b))
        except ValueError:
            return None
    return None

def category_for(e):
    """Bosch-taxonomy auto-categorization."""
    src = e.get("src", "")
    cat = e.get("category", "")
    # EWS / immobilizer candidates (pointer-sweep group) always go to Immob
    if src == "sweep:ews_candidates" or cat == "EWS/Immobilizer":
        return "Immobilizer/Security"
    # Driver's Wish 1D ADC curves (verified [count][axis][values])
    if src == "adc_1d" or src == "sweep:drivers_wish_candidates":
        return "Driver's Wish"
    # DFES / DTC arrays -> DTC Masks
    if cat in ("DTC/Error",):
        return "DTC Masks"
    if cat == "Emissions":
        return "Emissions"
    if cat == "Torque/Limiter":
        return "Torque/Limiter"
    if cat == "RailPressure":
        return "Rail Pressure"
    if cat == "Injection":
        return "Injection"
    if e.get("kind") == "scalar":
        return "Scalar/Config"
    return "Engine Maps"

def name_for(e):
    cat = category_for(e)
    a = e["addr"]
    kind = e["kind"]
    if e.get("name"):
        return e["name"]
    if kind == "curve":
        return f"CURV_{a:04X}_{e['count']}pt"
    if kind == "scalar":
        return f"SCAL_{a:04X}"
    if kind == "mask":
        return f"MASK_{a:04X}"
    if kind == "2d":
        try:
            r, c = e["dims"].split("x")
            return f"MAP2_{a:04X}_{r}x{c}"
        except Exception:
            return f"MAP2_{a:04X}"
    return f"MAP_{a:04X}"

def desc_for(e):
    parts = [
        f"category={category_for(e)}",
        f"kind={e['kind']}",
        f"addr=0x{e['addr']:04X}",
        f"src={e.get('src','?')}",
    ]
    if e.get("nrefs"):
        parts.append(f"code_refs={e['nrefs']}")
    if e.get("code_refs"):
        parts.append("refs=" + ",".join(e["code_refs"][:4]))
    if kind := e["kind"]:
        if kind == "curve":
            if e.get("has_axis"):
                parts.append("layout=[count][axis][values] - axis verified in flash")
            else:
                parts.append("flat N-word curve, linear index axis (no stored axis)")
        elif kind == "2d":
            parts.append("2D grid row-major 16-bit, linear index axes")
        elif kind == "mask":
            parts.append("Nx2 word array (DFES/DTC related), 32 index slots")
        elif kind == "scalar":
            parts.append("single 16-bit scalar")
    if e.get("axis"):
        parts.append(f"axis={e['axis']}")
    return "; ".join(parts)

# ---------------------------------------------------------------- axis XML
def linear_axis(parent, axid, count, units="", labels=None):
    """Linear (index) axis: no stored data. TunerPro idiom = EMBEDDEDDATA
    without mmedaddress and negative majorstridebits."""
    ax = ET.SubElement(parent, "XDFAXIS", id=axid, uniqueid="0x0")
    ET.SubElement(ax, "EMBEDDEDDATA",
                  mmedelementsizebits="16",
                  mmedmajorstridebits="-32",
                  mmedminorstridebits="0")
    u = ET.SubElement(ax, "units"); u.text = units
    ic = ET.SubElement(ax, "indexcount"); ic.text = str(count)
    ot = ET.SubElement(ax, "outputtype"); ot.text = "1"
    mn = ET.SubElement(ax, "min"); mn.text = "0"
    mx = ET.SubElement(ax, "max"); mx.text = str(count)
    for i in range(count):
        v = labels[i] if labels else i
        ET.SubElement(ax, "LABEL", index=str(i), value=str(v))
    m = ET.SubElement(ax, "MATH", equation="X")
    ET.SubElement(m, "VAR", id="X")
    return ax

def embedded_axis(parent, axid, addr, count, units="", labels=None,
                  rowcount=None, colcount=None):
    """Axis whose data is stored at flash offset addr (16-bit words)."""
    ax = ET.SubElement(parent, "XDFAXIS", id=axid, uniqueid=f"0x{addr:04X}")
    attrs = dict(mmedaddress=f"0x{addr:X}",
                 mmedelementsizebits="16",
                 mmedmajorstridebits="16",
                 mmedminorstridebits="0",
                 mmedcolcount=str(count))
    if rowcount:
        attrs["mmedrowcount"] = str(rowcount)
    ET.SubElement(ax, "EMBEDDEDDATA", **attrs)
    u = ET.SubElement(ax, "units"); u.text = units
    ic = ET.SubElement(ax, "indexcount"); ic.text = str(count)
    if labels:
        for i, v in enumerate(labels):
            ET.SubElement(ax, "LABEL", index=str(i), value=str(v))
    m = ET.SubElement(ax, "MATH", equation="X")
    ET.SubElement(m, "VAR", id="X")
    return ax

def z_axis(parent, addr, count, units="", labels=None,
           rowcount=None, colcount=None):
    """Z axis = the data itself, flat 16-bit at flash addr."""
    return embedded_axis(parent, "z", addr, count, units=units, labels=labels,
                         rowcount=rowcount, colcount=colcount)

# ---------------------------------------------------------------- main
def build():
    master = json.load(open(MASTER))
    master.sort(key=lambda e: e["addr"])

    root = ET.Element("XDFFORMAT", version="1.60")
    hdr = ET.SubElement(root, "XDFHEADER")
    f = ET.SubElement(hdr, "flags"); f.text = "0x1"
    fv = ET.SubElement(hdr, "fileversion"); fv.text = "2026-08"
    dt = ET.SubElement(hdr, "deftitle"); dt.text = TITLE
    ds = ET.SubElement(hdr, "description"); ds.text = DESC
    au = ET.SubElement(hdr, "author"); au.text = AUTHOR
    ET.SubElement(hdr, "BASEOFFSET", offset="0", subtract="0")
    ET.SubElement(hdr, "DEFAULTS",
                  datasizeinbits="16", sigdigits="2", outputtype="1",
                  signed="0", lsbfirst="0", float="0")
    ET.SubElement(hdr, "REGION",
                  type="0xFFFFFFFF", startaddress="0x0", size="0x200000",
                  regionflags="0x0", name="Flash 2MB",
                  desc="X5 35d full flash dump (mpc_full.bin)")
    for i, c in enumerate(CATEGORIES):
        ET.SubElement(hdr, "CATEGORY", index=f"0x{i:X}", name=c)

    tinfo = ET.SubElement(root, "TABLEINFO")

    n_by_cat = {}
    for idx, e in enumerate(master, start=1):
        cat = category_for(e)
        n_by_cat[cat] = n_by_cat.get(cat, 0) + 1
        a = e["addr"]
        t = ET.SubElement(tinfo, "XDFTABLE",
                          uniqueid=f"0x{a:06X}", flags="0x0")
        ti = ET.SubElement(t, "title"); ti.text = name_for(e)
        de = ET.SubElement(t, "description"); de.text = desc_for(e)
        ET.SubElement(t, "CATEGORYMEM", index="0", category=str(CAT_IDX[cat]))

        kind = e["kind"]
        if kind == "curve":
            n = e["count"]
            if e.get("has_axis"):
                # [count][axis xN][values xN] physically in flash
                # X axis = stored axis words at a+2
                embedded_axis(t, "x", a + 2, n,
                              units="mV" if e.get("src") == "adc_1d" else "raw",
                              labels=e["axis"])
                linear_axis(t, "y", 1)
                z_axis(t, a + 2 + 2 * n, n)
            else:
                # flat values, linear index
                linear_axis(t, "x", n)
                linear_axis(t, "y", 1)
                z_axis(t, a, n)
        elif kind == "2d":
            dims = parse_dims(e["dims"])
            if dims and dims[0] > 0 and dims[1] > 0:
                r, c = dims
                linear_axis(t, "x", c)
                linear_axis(t, "y", r)
                z_axis(t, a, r * c, rowcount=r, colcount=c)
            else:
                # degenerate dims recorded (e.g. 2x0): treat as flat 1D
                try:
                    r = int(e["dims"].split("x")[0])
                except Exception:
                    r = 8
                r = max(r, 1)
                linear_axis(t, "x", r)
                linear_axis(t, "y", 1)
                z_axis(t, a, r)
        elif kind == "scalar":
            linear_axis(t, "x", 1)
            linear_axis(t, "y", 1)
            z_axis(t, a, 1)
        elif kind == "mask":
            # Nx2 word array; 32 index slots (typical DFES/DTC word arrays)
            n = 32
            linear_axis(t, "x", n)
            linear_axis(t, "y", 1)
            z_axis(t, a, n)
        else:
            linear_axis(t, "x", 1)
            linear_axis(t, "y", 1)
            z_axis(t, a, 1)

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(OUT, encoding="utf-8", xml_declaration=True)

    print(f"wrote {OUT}  ({os.path.getsize(OUT)} bytes)")
    print(f"tables: {len(master)}")
    for c in CATEGORIES:
        print(f"  {c:22s} {n_by_cat.get(c, 0)}")

if __name__ == "__main__":
    build()
