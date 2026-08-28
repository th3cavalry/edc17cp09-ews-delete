#!/usr/bin/env python3
"""
EDC17CP09 Community Release XDF generator (v1.1).

Emits a complete classic TunerPro XDF (v1.60 dialect, validated against a
genuine TunerPro PCM XDF) from the merged master dataset.

Structural rules (v1.1 fixes, all verified against the real GM PCM XDF):
  * mmedcolcount = X-axis length ONLY.  mmedrowcount = Y-axis length ONLY.
    (Real 2D tables in the reference XDF: 10/10 had colcount==x_indexcount
    and rowcount==y_indexcount.)
  * No zero-dimension maps.  A map whose dims are degenerate (either
    dimension is 0 or 1) is a 1D curve and is named/formatted as one
    (CURV_<addr>_<N>pt).  "2x0" was a collection artifact: the nonzero
    dim is the real cell count and the zero dim is dropped.
  * No raw binary / hex dumps to stdout - summary counts only.
  * HW and SW numbers are extracted from the dump itself and baked into
    the filename so users cannot flash against a mismatched ECU.

Honesty rules (from prior corrections):
  * <Xaxis> points at a real axis offset ONLY for the 60 Driver's Wish ADC
    curves, which physically store [count][axis xN][values xN] in flash
    (verified against mpc_full.bin).
  * All other 1D/2D maps are flat value arrays with NO stored axis: they get
    a linear index axis (EMBEDDEDDATA without mmedaddress, negative
    majorstridebits) - no fabricated offsets.
  * EMBEDDEDDATA.mmedaddress on the Z axis is always the real calib address.

Data source: mpc_full.bin = 2 MB X5 35d flash dump; offsets are absolute
flash addresses (BASEOFFSET 0).
"""
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
MASTER = os.path.join(HERE, "master_dataset.json")
BIN = os.path.join(HERE, "mpc_full.bin")

# Fallbacks only used if the patterns are not found in the dump.
HW_FALLBACK = "0281017487"
SW_FALLBACK = "10375506116137U6A"

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

# ---------------------------------------------------------------- version ID
def extract_hw_sw(path):
    """Extract hardware and software numbers from the flash dump.

    HW: 10-digit part number repeated in the tail region (0xfd00/0xfe33).
    SW: 14-digit + 3-letter software ID at 0x1a, replicated in every flash
    bank (0, 0x4000, 0x20000, 0x180000).
    Returns (hw, sw, provenance_note).
    """
    b = open(path, "rb").read()
    hw = None
    hw_hits = [m.start() for m in re.finditer(rb"(?<![0-9])[0-9]{10}(?![0-9])", b)
               if 0xf000 <= m.start() <= 0x10000]
    if hw_hits:
        seg = b[hw_hits[0]:hw_hits[0] + 10]
        hw = seg.decode("ascii", "replace")
    sw = None
    m = re.search(rb"([0-9]{14}[A-Z]{3})_", b[0x10:0x40])
    if m:
        sw = m.group(1).decode("ascii")
    note = []
    if hw:
        note.append("HW %s from flash 0x%X" % (hw, hw_hits[0]))
    else:
        hw = HW_FALLBACK
    if sw:
        n = len(re.findall(re.escape(sw.encode()), b))
        note.append("SW %s from flash 0x1a (x%d bank copies)" % (sw, n))
    else:
        sw = SW_FALLBACK
    return hw, sw, " | ".join(note)

# ---------------------------------------------------------------- helpers
def category_for(e):
    """Bosch-taxonomy auto-categorization."""
    src = e.get("src", "")
    cat = e.get("category", "")
    if src == "sweep:ews_candidates" or cat == "EWS/Immobilizer":
        return "Immobilizer/Security"
    if src == "adc_1d" or src == "sweep:drivers_wish_candidates":
        return "Driver's Wish"
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

def dims_of(e):
    """'3x1' -> (3,1); '8x1' -> (8,1); '(2 bytes)' -> (1,1); else None."""
    d = (e.get("dims") or "").strip()
    if d.endswith("(2 bytes)"):
        return (1, 1)
    if "x" in d:
        a, b = d.split("x")
        try:
            return (int(a), int(b))
        except ValueError:
            return None
    return None

def eff_curve_len(e):
    """Effective 1D cell count for an entry, from dims or count key."""
    d = dims_of(e)
    if d:
        # product of the nonzero dims (a '2x0' has one real dim)
        nz = [v for v in d if v > 0]
        if nz:
            prod = 1
            for v in nz:
                prod *= v
            return prod
    c = e.get("count")
    return int(c) if c else None

# ---------------------------------------------------------------- overlap
def rendered_span(e):
    """(start, end) flash byte span as this generator will actually emit it."""
    a = e["addr"]
    kind = e["kind"]
    if kind == "mask":
        n = 32  # masks render as 32 index slots
    elif kind == "scalar":
        n = 1
    else:
        n = e.get("count") or eff_curve_len(e) or 1
        if kind == "curve" and e.get("has_axis"):
            # [count][axis xN][values xN] physically in flash: values start later
            return a + 2 + 2 * n, a + 2 + 4 * n
    return a, a + 2 * n

def dedupe_contained(master):
    """Skip entries whose full span is contained inside another entry of the
    SAME kind - a strict sub-region of an identically-typed table is a
    duplicate view of the same bytes (sweep artifact: e.g. a 4-word pointer
    landing inside an 8-word table at the same 16-bit alignment).

    Returns (kept_entries, skipped_count, cross_kind_partial_overlaps).
    Cross-kind overlaps (a 2D grid over scalars, etc.) are kept - different
    views of the same bytes can both be real - but counted so the user is
    warned.
    """
    spans = [rendered_span(e) for e in master]
    skip = set()
    for i, e in enumerate(master):
        s, en = spans[i]
        for j, o in enumerate(master):
            if i == j or o["kind"] != e["kind"]:
                continue
            os_, oe = spans[j]
            if os_ <= s and oe >= en and (os_, oe) != (s, en):
                skip.add(i)
                break
    kept = [e for i, e in enumerate(master) if i not in skip]

    # cross-kind partial overlap census (report only, no skipping)
    cross = 0
    for i in range(len(kept)):
        s1, e1 = spans[i]
        for j in range(i + 1, len(kept)):
            s2, e2 = spans[j]
            if kept[i]["kind"] == kept[j]["kind"]:
                continue
            if s2 < e1 and s1 < e2:  # partial or full, different kind
                cross += 1
    return kept, len(skip), cross

def is_genuine_2d(e):
    """True only when BOTH dimensions are >= 2. Anything else is a 1D
    curve in both naming and XDF structure."""
    d = dims_of(e)
    if d is None:
        return False
    return d[0] >= 2 and d[1] >= 2

def name_for(e):
    a = e["addr"]
    kind = e["kind"]
    if e.get("name"):
        return e["name"]
    if kind == "curve":
        return "CURV_%04X_%dpt" % (a, e["count"])
    if kind == "scalar":
        return "SCAL_%04X" % a
    if kind == "mask":
        return "MASK_%04X" % a
    if kind == "2d":
        d = dims_of(e)
        if d is None:
            return "MAP_%04X" % a
        if is_genuine_2d(e):
            return "MAP2_%04X_%dx%d" % (a, d[0], d[1])
        # degenerate (either dim 0 or 1) -> 1D curve name, zero dropped
        return "CURV_%04X_%dpt" % (a, eff_curve_len(e))
    return "MAP_%04X" % a

def desc_for(e):
    parts = [
        "category=%s" % category_for(e),
        "kind=%s" % e["kind"],
        "addr=0x%04X" % e["addr"],
        "src=%s" % e.get("src", "?"),
    ]
    if e.get("nrefs"):
        parts.append("code_refs=%d" % e["nrefs"])
    kind = e["kind"]
    if kind == "curve":
        if e.get("has_axis"):
            parts.append("layout=[count][axis][values] - axis verified in flash")
        else:
            parts.append("flat N-word curve, linear index axis (no stored axis)")
    elif kind == "2d":
        d = dims_of(e)
        if d and is_genuine_2d(e):
            parts.append("2D grid %dx%d row-major 16-bit, linear index axes" % d)
        else:
            parts.append("degenerate dims %r recorded at collection - treated as 1D curve of %d words"
                         % (e.get("dims"), eff_curve_len(e)))
    elif kind == "mask":
        parts.append("Nx2 word array (DFES/DTC related), 32 index slots")
    elif kind == "scalar":
        parts.append("single 16-bit scalar")
    if e.get("axis"):
        parts.append("axis=%s" % e["axis"])
    return "; ".join(parts)

# ---------------------------------------------------------------- axis XML
def linear_axis(parent, axid, count, units=""):
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
        ET.SubElement(ax, "LABEL", index=str(i), value=str(i))
    m = ET.SubElement(ax, "MATH", equation="X")
    ET.SubElement(m, "VAR", id="X")
    return ax

def embedded_axis(parent, axid, addr, count, units="", labels=None):
    """Axis whose data is stored at flash offset addr (16-bit words, 1D).
    colcount = axis length only."""
    ax = ET.SubElement(parent, "XDFAXIS", id=axid, uniqueid="0x%04X" % addr)
    ET.SubElement(ax, "EMBEDDEDDATA",
                  mmedaddress="0x%X" % addr,
                  mmedelementsizebits="16",
                  mmedmajorstridebits="16",
                  mmedminorstridebits="0",
                  mmedcolcount=str(count))
    u = ET.SubElement(ax, "units"); u.text = units
    ic = ET.SubElement(ax, "indexcount"); ic.text = str(count)
    if labels:
        for i, v in enumerate(labels):
            ET.SubElement(ax, "LABEL", index=str(i), value=str(v))
    m = ET.SubElement(ax, "MATH", equation="X")
    ET.SubElement(m, "VAR", id="X")
    return ax

def z_1d(parent, addr, count):
    """1D Z axis: count cells at addr. colcount = count, no rowcount."""
    return embedded_axis(parent, "z", addr, count)

def z_2d(parent, addr, xlen, ylen):
    """2D Z axis: xlen columns x ylen rows at addr.
    mmedcolcount = X-axis length ONLY; mmedrowcount = Y-axis length ONLY."""
    ax = ET.SubElement(parent, "XDFAXIS", id="z", uniqueid="0x%04X" % addr)
    ET.SubElement(ax, "EMBEDDEDDATA",
                  mmedaddress="0x%X" % addr,
                  mmedelementsizebits="16",
                  mmedrowcount=str(ylen),
                  mmedcolcount=str(xlen),
                  mmedmajorstridebits="0",
                  mmedminorstridebits="0")
    ic = ET.SubElement(ax, "indexcount"); ic.text = str(xlen * ylen)
    u = ET.SubElement(ax, "units"); u.text = "raw"
    m = ET.SubElement(ax, "MATH", equation="X")
    ET.SubElement(m, "VAR", id="X")
    return ax

# ---------------------------------------------------------------- main
def build():
    master = json.load(open(MASTER))
    master.sort(key=lambda e: e["addr"])

    # Overlap detection: drop same-kind entries that are strict sub-regions
    # of another entry, warn about cross-kind partial overlaps.
    master, n_skipped, n_cross = dedupe_contained(master)
    if n_skipped or n_cross:
        print("overlap check: %d same-kind contained entries skipped, "
              "%d cross-kind partial overlaps kept (both views may be real)"
              % (n_skipped, n_cross))

    hw, sw, ver_note = extract_hw_sw(BIN)
    out_name = "EDC17CP09_HW%s_SW%s_Community_v1.2.xdf" % (hw, sw)
    out = os.path.join(HERE, out_name)

    # dynamic kind census (never hardcode - the dataset is the source of truth)
    census = {}
    for e in master:
        census[e["kind"]] = census.get(e["kind"], 0) + 1

    title = "EDC17CP09 (M57 3.0d) HW %s / SW %s - Community Release v1.2" % (hw, sw)
    desc = (
        "BMW EDC17CP09 M57N2 X5 35d (US) - 2MB flash dump (mpc_full.bin).\n"
        "ECU hardware number: %s   ECU software number: %s\n"
        "DO NOT use this file on an ECU whose HW/SW numbers differ - "
        "calibration addresses are not stable across compilations.\n"
        "%d calibration objects located by TriCore pointer sweep "
        "(Capstone/Ghidra) plus 530d OLS cross-reference: %d curves, "
        "%d 2D grids, %d scalars, %d mask arrays.\n"
        "Version provenance: %s.\n"
        "Axis values verified where physically stored in flash; labels/units "
        "are best-effort from Bosch taxonomy - verify before tuning."
    ) % (hw, sw, len(master),
         census.get("curve", 0), census.get("2d", 0),
         census.get("scalar", 0), census.get("mask", 0), ver_note)

    root = ET.Element("XDFFORMAT", version="1.60")
    hdr = ET.SubElement(root, "XDFHEADER")
    f = ET.SubElement(hdr, "flags"); f.text = "0x1"
    fv = ET.SubElement(hdr, "fileversion"); fv.text = "2026-08"
    dt = ET.SubElement(hdr, "deftitle"); dt.text = title
    ds = ET.SubElement(hdr, "description"); ds.text = desc
    au = ET.SubElement(hdr, "author"); au.text = AUTHOR
    ET.SubElement(hdr, "BASEOFFSET", offset="0", subtract="0")
    ET.SubElement(hdr, "DEFAULTS",
                  datasizeinbits="16", sigdigits="2", outputtype="1",
                  signed="0", lsbfirst="0", float="0")
    ET.SubElement(hdr, "REGION",
                  type="0xFFFFFFFF", startaddress="0x0", size="0x200000",
                  regionflags="0x0", name="Flash 2MB",
                  desc="X5 35d full flash dump (mpc_full.bin), HW %s SW %s" % (hw, sw))
    for i, c in enumerate(CATEGORIES):
        ET.SubElement(hdr, "CATEGORY", index="0x%X" % i, name=c)

    tinfo = ET.SubElement(root, "TABLEINFO")

    n_by_cat = {}
    n_true_2d = 0
    n_degen_to_1d = 0
    for idx, e in enumerate(master, start=1):
        cat = category_for(e)
        n_by_cat[cat] = n_by_cat.get(cat, 0) + 1
        a = e["addr"]
        t = ET.SubElement(tinfo, "XDFTABLE",
                          uniqueid="0x%06X" % a, flags="0x0")
        ti = ET.SubElement(t, "title"); ti.text = name_for(e)
        de = ET.SubElement(t, "description"); de.text = desc_for(e)
        ET.SubElement(t, "CATEGORYMEM", index="0", category=str(CAT_IDX[cat]))

        kind = e["kind"]
        if kind == "curve":
            n = e["count"]
            if e.get("has_axis"):
                # [count][axis xN][values xN] physically in flash
                embedded_axis(t, "x", a + 2, n,
                              units="mV" if e.get("src") == "adc_1d" else "raw",
                              labels=e["axis"])
                linear_axis(t, "y", 1)
                z_1d(t, a + 2 + 2 * n, n)
            else:
                linear_axis(t, "x", n)
                linear_axis(t, "y", 1)
                z_1d(t, a, n)
        elif kind == "2d":
            d = dims_of(e)
            if d and is_genuine_2d(e):
                rows, cols = d  # dims stored as <rows>x<cols>
                n_true_2d += 1
                linear_axis(t, "x", cols)   # X = columns
                linear_axis(t, "y", rows)   # Y = rows
                z_2d(t, a, xlen=cols, ylen=rows)
            else:
                # degenerate dims (a dim is 0 or 1): 1D curve
                n = eff_curve_len(e)
                if not n or n < 1:
                    n = 1
                n_degen_to_1d += 1
                linear_axis(t, "x", n)
                linear_axis(t, "y", 1)
                z_1d(t, a, n)
        elif kind == "scalar":
            linear_axis(t, "x", 1)
            linear_axis(t, "y", 1)
            z_1d(t, a, 1)
        elif kind == "mask":
            # Nx2 word array; 32 index slots (typical DFES/DTC word arrays)
            linear_axis(t, "x", 32)
            linear_axis(t, "y", 1)
            z_1d(t, a, 32)
        else:
            linear_axis(t, "x", 1)
            linear_axis(t, "y", 1)
            z_1d(t, a, 1)

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(out, encoding="utf-8", xml_declaration=True)

    print("wrote %s (%d bytes)" % (out_name, os.path.getsize(out)))
    print("tables: %d (true 2D: %d, degenerate->1D: %d)"
          % (len(master), n_true_2d, n_degen_to_1d))
    for c in CATEGORIES:
        print("  %-22s %d" % (c, n_by_cat.get(c, 0)))

if __name__ == "__main__":
    build()
