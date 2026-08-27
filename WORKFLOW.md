# EDC17CP09 M57 → 2016 Tacoma — Standalone Swap Build Notes

DDE: 2011 BMW X5 (E70) M57D30 — Bosch EDC17CP09
HW 0281017487 | SW 10375506116137U6A (config) / 10375135896137T6A (app)
Trans: ZF 6HP28 + shifter | Chassis: 2016 Tacoma, push-button start + Toyota immo KEPT
Target file: `mpc_full.bin` (copy of `original x5 17cp09 .MPC`, 2,097,152 bytes)

--------------------------------------------------------------------
1. FILE VERDICTS
--------------------------------------------------------------------
- `original x5 17cp09 .MPC`  → CORRECT, complete, valid. Keep as golden backup.
    11/11 checksums valid, CVN 0x996D8667, VIN 0089ZH0A7UABGK244.
- `bmw_x5_e70_35d_orig.bin`  → INVALID (partial 0xC3-filled dump). Discard.
- `TC1796_10375506126137T6N...bin` (4MB bench read) → different SW build,
    reference only.

--------------------------------------------------------------------
2. WHAT'S BUILT AND TESTED (all in /home/brandon/Documents/EDC17CP09/)
--------------------------------------------------------------------
- EDC17CP09_M57_0281017487.xdf   TunerPro def, 45 tables (40 cal maps from the
    real scan + 5 ident/EWS/VIN/CVN constants). Valid XML, offsets verified.
- apply_patch.py                 edits + full checksum re-correction pipeline.
    TESTED: produces mpc_swapped.bin with 11/11 checksums valid.
- mpc_swapped.bin                output of the tested run (VIN neutered only).
    25 bytes differ from stock: VIN 0x180099→0x1800A9 zeroed + CVN 0x1FE8FC
    (0x996D8667→0x49246230) + compensation slot 0x1FE86C.
- medc17_checksum_tool.py        checksum analyzer/corrector (CLI:
    `medc17_checksum_tool.py file.bin --json` or `--correct -o out --fix-cvn orig`)
- gen_xdf.py / verify_xdf.py / maps_decoded.json / checksum_mpc.json / scan_mpc.json

Usage:
  .venv/bin/python apply_patch.py                  # VIN neuter + re-checksum
  .venv/bin/python apply_patch.py --vin <17chars>   # custom VIN
  .venv/bin/python apply_patch.py --ews-blank       # + zero EWS slot 0x180074 (RISKY)
  .venv/bin/python medc17_checksum_tool.py <file> --json   # verify any file

--------------------------------------------------------------------
3. THE EWS/IMMOBILIZER REALITY (verified against your exact build)
--------------------------------------------------------------------
An M57 standalone-swap thread (bimmerforums 2423271, same DDE+gearbox swap)
settles most of the questions:

a) EWS gates FUEL + INJECTORS. No/invalid EWS auth = crank, no start.
   "The wrong signal from EWS will disable the fuel pump."
b) ISN showing ERROR_ECU_REJECTED on a standalone DDE is NORMAL and fine.
   Do not chase it.
c) Their "intermittent crank-no-start" was a CRANK SENSOR, not EWS.
   → If yours cranks but not always starts: suspect crank sensor, VSS, or
     injector LED flash pattern BEFORE patching any code.
d) EWS delete for EDC17CP09 IS a code patch (rpmMotorsport sells exactly
   "EDC17Cxx EWS/CAS Immobilizer Delete" for 2009-2018 DDEs). It is NOT a
   2-byte EEPROM trick. The auth routine lives in the application firmware
   (0x020000-0x17FF03, ADD32 x3) and its key material is OTP-fused in the
   Tuning-protection block (0x014000-0x017EFF, has_otp=True).

What the patch plan looks like (do NOT attempt without a bench flasher +
a spare/bric-able DDE, or a paid delete file):
- Locate the EWS-acknowledge branch in the app firmware (the routine that
  reads the key result and enables the fuel pump/injectors) and NOP/skip it.
- Zero/neutral the stored EWS key slot 0x180074 (0xFB41AC86) — but ONLY in
  combination with the code patch; alone it risks an "EWS not programmed"
  limp.
- Recompute all 11 checksums + accept the new CVN (CVN is data-derived;
  it changes with ANY calibration edit — that is normal and fine).

RECOMMENDED ORDER (cheapest-first):
  1. Wire it standalone as-is and try to start (stock immo, no patch).
     If EWS rejects: crank-no-start + fuel pump off. Then:
  2. Use the mpc_swapped.bin (VIN neutered, checksums valid) as first
     bench-flash test — verifies your flasher writes a 2MB EDC17 correctly
     and the ECU accepts re-summed files. Zero risk to the car.
  3. Get the actual EWS delete one of three ways:
       - paid delete file for 10375506116137U6A (rpmMotorsport / similar),
       - a tuner with KESS/FGTech + CP09 immo-off experience,
       - I do the firmware patch (needs: bench flasher confirmed working,
         spare DDE to absorb a bricked flash, and your go-ahead).

--------------------------------------------------------------------
4. K-BUS / DIAGNOSTIC ACCESS (if you want to talk to the DDE for coding)
--------------------------------------------------------------------
EDC17CP09 DDE diagnostics: K-Line (5-pin round or OBD adapter).
Per the M57 thread: with IKE + GM (gateway master) on the K-bus you can
access DDE/cluster/EWS diagnostics standalone. DDE & cluster came from the
same 2011 X5, so they are already paired.
Your custom CAN trunk (DDE ↔ 6HP28 TCU ↔ shifter) is SEPARATE from K-bus —
keep the two buses physically isolated; bridge only the start-enable power
signal from the Toyota side.

--------------------------------------------------------------------
5. CUSTOM CAN TRUNK (DDE ↔ 6HP28 TCU ↔ shifter)
--------------------------------------------------------------------
Single 2-wire CAN (H/L), 120 Ω at both ends.
- DDE: drivetrain CAN from EDC17CP09 pinout (engine side, 2.5k→120Ω only
  if DDE is the first node — check the DDE's own termination first).
- 6HP28 TCU: drivetrain CAN + the shifter/range selector lines (P/N gear
  position to TCU — the EWS thread shows EWS also waited on P/N signal;
  on a standalone with no EWS the TCU still needs range selection).
- The DDE must see: crank sync (Hall crank sensor), MAP, rail pressure,
  coolant temp, throttle/accel pedal, ignition (KL15), fuel pump enable,
  injection rails. Tacoma side supplies: starter enable (Toyota immo),
  KL30, KL15, gear-select from the shifter to the TCU.

--------------------------------------------------------------------
6. TUNING LATER (once it runs)
--------------------------------------------------------------------
XDF labels are reconstructed from axis shape — verify on the dyno.
Prime suspects for M57 swap work:
- 0x034xxx 21×32 (MAP × temp)      → torque request / injected quantity
- 0x1B4xxx 8×8, 0x1BAxxx 16×10     → boost target / VNT duty
- 0x1D2F04-0x1D4810 16-wide        → smoke limiter / SOI
- 0x1DB1EC / 0x1DB3F0 16×16        → torque/speed limiters
- 0x1DE74E 14×16                   → torque model
Log rail pressure, boost, EGT, requested vs delivered torque before
moving any of these far.
