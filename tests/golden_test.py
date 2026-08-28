#!/usr/bin/env python3
"""
Golden test for the EDC17CP09 EWS-delete pipeline.

A "golden test" pins known-good inputs to known-good outputs so any
regression in the tools is caught immediately:

  1. STOCK DUMP INTEGRITY
     mpc_full.bin must match its SHA256 and validate 11/11 checksums.

  2. PATCH REPRODUCTION
     mpc_full.bin --patch_gate_ews.py--> output must be byte-identical to
     the committed X5d_Stock_ImmoOff.bin (SHA256-verified).

  3. CHECKSUM-CORRECTION REPRODUCTION
     X5d_Stock_ImmoOff.bin --medc17_checksum_tool.py --correct--> output
     must be byte-identical to the committed X5d_Stock_ImmoOff_CSFixed.bin
     (SHA256-verified) and validate 11/11.

  4. PATCH CONTENT SANITY
     The committed gate-patched binary differs from stock in EXACTLY the
     three documented 4-byte sites and nothing else.

  5. XDF STRUCTURAL INTEGRITY
     The current release XDF must parse as XML, contain the expected
     table count, have unique titles, no zero-dimension names, and every
     2D Z axis must satisfy mmedcolcount == X indexcount and
     mmedrowcount == Y indexcount.

Run:
    .venv/bin/python tests/golden_test.py
Exit code 0 = all golden vectors hold.
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = sys.executable or "python3"
CS_TOOL = os.path.join(ROOT, "medc17_checksum_tool.py")
GATE = os.path.join(ROOT, "patch_gate_ews.py")

# ---- golden vectors (re-derive with: sha256sum <file>) -------------------
SHA256_STOCK = "4706f9128123198cbc810b3583e8e5b0bedc1b5f81eadd144fafe239654dc296"
SHA256_GATE = "0d7d45c1bf85f3fde0060fc7f002ecfbb283700217cd57362ea2eb118a024361"
SHA256_GATE_CS = "4379d898c2c6ccef399790b1a6a4df3f3fc4e4a69e2933c4f6de17d0a0e6402e"

GATE_SITES = {0x00A4B6, 0x0908A6, 0x0E2FA8}
GATE_OLD = bytes.fromhex("8b022022")
GATE_NEW = bytes.fromhex("00008212")

RELEASE_XDF = None
for fn in os.listdir(ROOT):
    if fn.startswith("EDC17CP09_HW") and fn.endswith("_Community_v1.2.xdf"):
        RELEASE_XDF = os.path.join(ROOT, fn)
        break

FAILS = []


def check(name, ok, detail=""):
    mark = "PASS" if ok else "FAIL"
    print("  [%s] %s%s" % (mark, name, (" - " + detail) if detail else ""))
    if not ok:
        FAILS.append(name)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def checksum_status(path):
    """Return (valid, total) from the checksum tool, or None on error."""
    r = subprocess.run([PY, CS_TOOL, path, "--json"],
                       capture_output=True, text=True, cwd=ROOT)
    if r.returncode != 0:
        return None
    import json
    d = json.loads(r.stdout)
    return d.get("valid_checksums"), d.get("total_checksums")


def main():
    print("== EDC17CP09 golden test ==")

    stock = os.path.join(ROOT, "mpc_full.bin")
    gate_bin = os.path.join(ROOT, "X5d_Stock_ImmoOff.bin")
    gate_cs_bin = os.path.join(ROOT, "X5d_Stock_ImmoOff_CSFixed.bin")

    # 1. stock dump integrity
    print("1) stock dump integrity")
    check("mpc_full.bin sha256", sha256(stock) == SHA256_STOCK,
          sha256(stock)[:16] + "...")
    cs = checksum_status(stock)
    check("stock checksums 11/11", cs == (11, 11), str(cs))

    # 2. patch reproduction
    print("2) gate patch reproduction")
    r = subprocess.run([PY, GATE, "--verify", gate_bin],
                       capture_output=True, text=True, cwd=ROOT)
    check("patch_gate_ews.py reproduces committed binary",
          r.returncode == 0,
          r.stdout.strip().splitlines()[-1] if r.stdout else r.stderr[:120])

    # 3. checksum correction reproduction
    print("3) checksum correction reproduction")
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
        tmp_out = tf.name
    try:
        r = subprocess.run([PY, CS_TOOL, gate_bin, "--correct",
                            "--out", tmp_out],
                           capture_output=True, text=True, cwd=ROOT)
        ok = (r.returncode == 0 and os.path.exists(tmp_out)
              and open(tmp_out, "rb").read() == open(gate_cs_bin, "rb").read())
        check("checksum --correct reproduces committed CSFixed binary", ok)
    finally:
        if os.path.exists(tmp_out):
            os.unlink(tmp_out)

    # 4. patch content sanity
    print("4) patch content sanity")
    s = open(stock, "rb").read()
    g = open(gate_bin, "rb").read()
    diff_bytes = [i for i in range(min(len(s), len(g))) if s[i] != g[i]]
    expected_diff = set()
    for site in GATE_SITES:
        expected_diff |= {site, site + 1, site + 2, site + 3}
    check("exactly 12 diff bytes in 3 documented sites",
          sorted(diff_bytes) == sorted(expected_diff),
          "sites=%s" % ",".join(hex(x) for x in sorted(diff_bytes)))
    check("site bytes are the documented 8b022022->00008212",
          all(s[site:site + 4] == GATE_OLD and g[site:site + 4] == GATE_NEW
              for site in GATE_SITES))

    # 5. XDF structural integrity
    print("5) XDF structural integrity")
    if not RELEASE_XDF:
        check("release XDF present", False, "no *_Community_v1.2.xdf at root")
    else:
        print("  (file: %s)" % os.path.basename(RELEASE_XDF))
        root = ET.parse(RELEASE_XDF).getroot()
        tables = root.findall(".//XDFTABLE")
        check("XDF parses, 1312 tables", len(tables) == 1312,
              str(len(tables)))
        titles = [t.find("title").text for t in tables if t.find("title") is not None]
        check("unique titles", len(titles) == len(set(titles)))
        bad_zero = [t for t in titles if re.search(r"(^|_)0x|_x0$|x0_?pt$", t)]
        check("no zero-dimension names", not bad_zero, str(bad_zero[:5]))

        def axis_count(xdfaxis, tag):
            for child in xdfaxis:
                if child.tag == "indexcount":
                    return int(child.text)
            return None

        bad2d = 0
        n2d = 0
        for t in tables:
            axes = {ax.get("id"): ax for ax in t.findall("XDFAXIS")}
            z = axes.get("z")
            if z is None:
                continue
            ed = z.find("EMBEDDEDDATA")
            rc = ed.get("mmedrowcount")
            if not rc:
                continue
            n2d += 1
            cc = int(ed.get("mmedcolcount"))
            rc_i = int(rc)
            xlen = axis_count(axes.get("x"), "x")
            ylen = axis_count(axes.get("y"), "y")
            if cc != xlen or rc_i != ylen:
                bad2d += 1
        check("2D geometry: colcount==X, rowcount==Y (all %d 2D tables)" % n2d,
              bad2d == 0, "%d bad" % bad2d)

    print()
    if FAILS:
        print("FAILED: %d check(s): %s" % (len(FAILS), ", ".join(FAILS)))
        return 1
    print("ALL GOLDEN CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
