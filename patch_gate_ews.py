#!/usr/bin/env python3
"""
Canonical EWS gate patch for EDC17CP09 (HW 0281017487, SW 10375506116137U6A).

METHOD (primary): instruction-gate patch.

This is the approach that produced the released binaries
(X5d_Stock_ImmoOff.bin / X5d_Stock_ImmoOff_CSFixed.bin). It is derived
empirically from a US 335d donor pair (immobilizer ON vs OFF): the ON/OFF
diff showed exactly three identical 4-byte changes, all of the form

    8B02 2022   ->   0000 8212

i.e. an `ne d2, d2, #0` (boolean "match present?") rewritten to clear the
result. In the X5 dump those three sites were re-located by their
instruction-context signature, not by the 335d addresses (which do not
carry over):

    0F F4 80 20 8B 02 20 22 00 90

Each X5 candidate was then disassembled (Capstone, TriCore 1.6.1) to
confirm it is the same boolean gate immediately before a `ret`.

Sites (X5 dump, verified):
    0x00A4B6   Customer Block
    0x0908A6   Application software #0
    0x0E2FA8   Application software #0

Output: X5d_Stock_ImmoOff.bin (raw 3-site patch, checksums NOT yet fixed).
Run medc17_checksum_tool.py on the output to get the 11/11 CSFixed binary.

USAGE:
    python3 patch_gate_ews.py                 # verify + write
    python3 patch_gate_ews.py --check-only    # verify sites, write nothing
    python3 patch_gate_ews.py --verify GOLDEN # byte-compare output to GOLDEN
"""

import argparse
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(BASE, "mpc_full.bin")
OUT = os.path.join(BASE, "X5d_Stock_ImmoOff.bin")

ORIGINAL = bytes.fromhex("8b022022")
PATCHED = bytes.fromhex("00008212")

# (offset, block) — block is informational only
SITES = [
    (0x00A4B6, "Customer Block"),
    (0x0908A6, "Application software #0"),
    (0x0E2FA8, "Application software #0"),
]

CONTEXT = bytes.fromhex("0ff480208b0220220090")


def verify_context(data, off):
    """The gate must sit inside the known instruction context."""
    # context window: 4 bytes before the gate + gate + 2 bytes after
    win = data[off - 4:off + 6]
    return CONTEXT in win


def main():
    ap = argparse.ArgumentParser(description="EDC17CP09 EWS gate patch (canonical)")
    ap.add_argument("--check-only", action="store_true",
                    help="Verify sites and context, write nothing")
    ap.add_argument("--verify", metavar="GOLDEN",
                    help="Byte-compare generated output to GOLDEN file")
    args = ap.parse_args()

    if not os.path.exists(SRC):
        print(f"ERROR: source not found: {SRC}")
        sys.exit(1)

    data = bytearray(open(SRC, "rb").read())
    if len(data) != 0x200000:
        print(f"ERROR: unexpected size {len(data)} (expected 0x200000)")
        sys.exit(1)

    print("EWS gate patch for EDC17CP09 (HW 0281017487, SW 10375506116137U6A)")
    print(f"Input:  {SRC}")
    print()

    ok = True
    for off, block in SITES:
        cur = bytes(data[off:off + 4])
        if cur != ORIGINAL:
            print(f"  [FAIL] {off:06x} ({block}): expected {ORIGINAL.hex()}, "
                  f"found {cur.hex()}")
            ok = False
            continue
        ctx = verify_context(data, off)
        tag = "ctx-OK " if ctx else "ctx-MISS"
        if not ctx:
            ok = False
        print(f"  [ {tag}] {off:06x} ({block}): {cur.hex()} -> {PATCHED.hex()}")

    if not ok:
        print("\nERROR: one or more sites failed verification. Aborting.")
        sys.exit(1)

    if args.check_only:
        print("\nAll 3 sites verified (check-only, no write).")
        return

    for off, _ in SITES:
        data[off:off + 4] = PATCHED

    if not args.verify:
        with open(OUT, "wb") as f:
            f.write(bytes(data))
        print(f"\nWrote {OUT} (3 sites patched, checksums NOT fixed).")
        print("Next:  python3 medc17_checksum_tool.py "
              f"{os.path.basename(OUT)} --correct")
    else:
        golden = open(args.verify, "rb").read()
        if bytes(data) == golden:
            print(f"\nREPRODUCTION OK: output byte-identical to {args.verify}")
        else:
            diff = [i for i in range(min(len(bytes(data)), len(golden)))
                    if bytes(data)[i] != golden[i]]
            print(f"\nMISMATCH: {len(diff)} differing bytes, "
                  f"first at {hex(diff[0]) if diff else '-'}")
            sys.exit(1)


if __name__ == "__main__":
    main()
