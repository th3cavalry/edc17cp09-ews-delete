#!/usr/bin/env python3
"""
Apply EDC17CP09 M57 swap edits to mpc_full.bin -> output file.

This is the SAFE first-stage patch: it does calibration/config edits
only, then hands off to medc17_checksum_tool.py to re-correct all 11
checksums and preserve the CVN. No firmware code patches here.

Edits applied (each is a documented, reversible byte change):
  1. VIN neuter (0x180099, 17 bytes) -> all zeros
     (removes the EDC17's stored vehicle ID so it won't hard-bind to
      the 2011 X5 chassis; standalone M57s don't cross-check VIN on
      most builds, and a zeroed VIN avoids a CAS-challenge mismatch.)
  2. Optional: mark the startup-block EWS slot blank
     (0x180074, 4 bytes) -> 0x00000000, IF you choose the no-key path.
     Guarded behind --ews-blank because on some CP09 builds a zeroed
     slot triggers an "EWS not programmed" limp instead of a clean start.
     DEFAULT: leave it alone (option B / lightweight route).

Usage:
  python3 apply_patch.py                 # VIN neuter only  (recommended)
  python3 apply_patch.py --ews-blank     # VIN neuter + blank EWS slot
  python3 apply_patch.py --vin TACOMA... # set a custom 17-char VIN
"""
import argparse, struct, sys, os, shutil, subprocess

BASE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(BASE, "mpc_full.bin")
TOOL = os.path.join(BASE, "medc17_checksum_tool.py")
PY   = os.path.join(BASE, ".venv", "bin", "python")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(BASE, "mpc_swapped.bin"))
    ap.add_argument("--ews-blank", action="store_true",
                    help="Also blank the EWS slot at 0x180074 (risky on some CP09 builds)")
    ap.add_argument("--vin", default=None,
                    help="17-char VIN to write at 0x180099 (default: zero all)")
    ap.add_argument("--skip-correct", action="store_true",
                    help="Only write the edited bin, do NOT run the checksum corrector")
    args = ap.parse_args()

    d = bytearray(open(SRC, "rb").read())
    assert len(d) == 2097152, f"unexpected size {len(d)}"

    # --- Edit 1: VIN (17 ASCII bytes @ 0x180099) ---
    vin_off = 0x180099
    old_vin = d[vin_off:vin_off+17].decode("ascii", "replace")
    if args.vin:
        assert len(args.vin) == 17, "VIN must be 17 chars"
        new_vin = args.vin.encode("ascii")
    else:
        new_vin = b"\x00" * 17
    d[vin_off:vin_off+17] = new_vin
    print(f"[1] VIN @0x180099: {old_vin!r} -> {new_vin.decode('ascii','replace')!r}")

    # --- Edit 2: EWS slot (optional) ---
    if args.ews_blank:
        ews_off = 0x180074
        old = d[ews_off:ews_off+4].hex()
        d[ews_off:ews_off+4] = b"\x00\x00\x00\x00"
        print(f"[2] EWS slot @0x180074: {old} -> 00000000  (risky)")
    else:
        print("[2] EWS slot @0x180074: UNCHANGED (lightweight route)")

    edited = args.out + ".edited"
    open(edited, "wb").write(bytes(d))
    print(f"    wrote edited bin: {edited} ({len(d):,} bytes)")

    if args.skip_correct:
        print("    --skip-correct: stopping before checksum correction")
        return

    # --- Hand off to the checksum corrector (recompute all 11 + keep CVN) ---
    out = args.out
    cmd = [PY, TOOL, edited, "--correct", "--output", out, "--fix-cvn", SRC, "--json"]
    print(f"\n    running: {' '.join(os.path.basename(c) for c in cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(r.stdout or "")
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        print(f"\n    !! corrector exit={r.returncode}")
        return
    # remove the temp edited file, keep the corrected output
    os.remove(edited)
    print(f"\nDONE -> {out}")
    print("NOTE: CVN + all 11 checksums should now be valid. Re-run the analyzer on this file to confirm before flashing.")

if __name__ == "__main__":
    main()
