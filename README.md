# EDC17CP09 — EWS Immobilizer Reverse Engineering

**Bosch MED17 (EDC17CP09) • BMW M57N2 3.0d • E70 X5 35d (US)**

> A complete reverse-engineering package for the EDC17CP09 diesel ECU: a **1,312-table TunerPro XDF** calibration database, TriCore disassembly research, and a verified **EWS (immobilizer) delete patch** — packaged for community distribution.

---

## Target ECU

| Property            | Value                                                                                   |
| :------------------ | :-------------------------------------------------------------------------------------- |
| ECU family          | Bosch MED17 — EDC17CP09                                                                 |
| Engine              | BMW M57N2 3.0 L turbo-diesel, 6-cylinder                                                 |
| Vehicle             | BMW E70 X5 35d, US specification                                                         |
| ECU hardware number | `0281017487` — read from flash `0xFE33`                                                  |
| ECU software number | `10375506116137U6A` — read from flash `0x001A`, replicated across all four flash banks   |
| Flash size          | 2 MB (`0x200000`)                                                                        |
| Dump checksums      | 11 / 11 valid (OpenRemap verification)                                                   |

---

## Safety Notice

> ⚠️ **The XDF and patched binaries are ECU-specific.**
> Calibration addresses are **not stable across firmware compilations**. The XDF filename embeds the exact hardware and software numbers it was built for:
>
> `EDC17CP09_HW0281017487_SW10375506116137U6A_Community_v1.2.xdf`
>
> **Do not load it on an ECU whose HW/SW numbers differ.** Incorrect addresses can corrupt calibrations and brick the unit.
>
> 🔋 **Keep a known-good flash tool and a backup of the stock dump** before flashing any modified binary, and verify all 11 checksums pass after any modification.

---

## Repository Contents

| File                                                                  | Description                                             |
| :-------------------------------------------------------------------- | :------------------------------------------------------ |
| `mpc_full.bin`                                                        | Stock 2 MB flash dump — 11/11 checksums valid           |
| `X5d_Stock_ImmoOff.bin`                                               | EWS-delete patched dump, stock layout                   |
| `X5d_Stock_ImmoOff_CSFixed.bin`                                       | EWS-delete patched dump, checksums recalculated         |
| `EDC17CP09_HW0281017487_SW10375506116137U6A_Community_v1.2.xdf`       | Final community XDF — 1,312 tables                     |
| `gen_xdf.py`                                                          | XDF generator — deterministic, re-runnable              |
| `master_dataset.json`                                                 | Merged, verified master dataset (all entries)           |
| `patch_gate_ews.py`                                                   | Canonical gate-patch script (`0x00A4B6`, `0x0908A6`, `0x0E2FA8`) |
| `patch_ews_delete.py`                                                 | Legacy NOP-patch variant — see note below                |
| `apply_patch.py`                                                      | VIN-zeroing variant for standalone swaps               |
| `medc17_checksum_tool.py`                                             | Stock/medc17 checksum read + correct                   |
| `EDC17CP09_immo_diff_analysis.txt`                                    | 335d donor ON/OFF diff analysis                         |
| `critical_maps_validated.json`                                        | Validated critical-map set                              |
| `XDF_v8_DriversWish_ADC_1D_Corrected.json`                            | Corrected Driver's Wish 1D ADC curves                   |
| `critical_maps_from_sweep.json`                                       | Pointer-sweep map set                                   |
| `final_identification_v2.json`                                        | Address-keyed identification results                    |
| `530d_curves*.json`, `a2l_*.json`, `*_matches*.json`                  | OLS/A2L cross-reference pipeline artifacts              |
| `ghidra/`                                                             | Ghidra scripts and source (pointer sweep, analysis)     |
| `tests/golden_test.py`                                                | Reproducible-output tests for binary + XDF + patch      |
| `archive/`                                                            | Superseded XDF iterations (do not use) — see `archive/README.md` |

> ℹ️ **Patch method note.** Three immobilizer-defeat approaches were evaluated: (1) **instruction-gate patch** — the canonical method, it is what produced the released binaries; (2) NOP patch (`patch_ews_delete.py`); (3) VIN-zeroing (`apply_patch.py`). Only the gate patch is supported. The NOP and VIN scripts are retained for research only and are **not** recommended for flashing.

---

## XDF Calibration Database

### Table Breakdown

| Kind                 | Count  | Title Prefix | Description                                                        |
| :------------------- | -----: | :----------- | :----------------------------------------------------------------- |
| 1D curves            |    966 | `CURV_`      | Flat N-word curves, incl. 60 verified ADC linearization curves     |
| 2D grids (total)     |     83 |              | Entries with 2D dimensions — 52 true grids + 31 degenerate        |
| Scalars              |    172 | `SCAL_`      | 16-bit configuration and threshold values                          |
| DTC / mask arrays    |    122 | `MASK_`      | N×2 diagnostic and event mask arrays                               |
| **Total**            | **1,312** |           |                                                                    |

**Overlap detection.** 181 of 1,336 entries in `master_dataset.json` are strict same-kind containment duplicates (one sweep pointer landing inside another table of identical type) and are skipped by the generator's dedup pass, leaving **1,312** entries in the emitted XDF. The generator warns on any remaining same-kind address overlap so the count is stable across runs.

### Naming Convention

Every title follows a strict, deterministic pattern — no freeform labels, no zero dimensions:

| Pattern               | Meaning                                    | Example                 |
| :-------------------- | :----------------------------------------- | :---------------------- |
| `CURV_<addr>_<N>pt`   | 1D curve, N points, hex flash address      | `CURV_40008_8pt`        |
| `MAP2_<addr>_<Y>x<X>` | 2D map, Y rows × X columns                 | `MAP2_4C01F_3x3`        |
| `SCAL_<addr>`         | 16-bit scalar                              | `SCAL_6F63F`            |
| `MASK_<addr>_<N>x2`   | N×2 mask array                             | `MASK_6F9A0_16x2`       |

> ℹ️ **Addresses are flash offsets, not RAM addresses.** The XDF `BASEOFFSET` is `0`, so every table address can be used directly against the 2 MB dump.

### Categories

Nine TunerPro categories organize the tables by Bosch functional group:

| Category               | Functional Group                                     |
| :--------------------- | :--------------------------------------------------- |
| Engine Maps            | Core drive maps: torque, fueling, limits             |
| Injection              | Injection timing and quantity tables                 |
| Rail Pressure          | Rail pressure control maps                           |
| Torque / Limiter       | Torque management and limiter values                 |
| Emissions              | Emissions-related corrections                        |
| Driver's Wish          | Driver demand (torque request) curves                |
| DTC Masks              | DFES diagnostic and DTC mask arrays                  |
| Immobilizer / Security | WFS security and immobilization-related values       |
| Scalar / Config        | General configuration values                         |

---

## Methodology

### 1. Binary Acquisition & Verification

- Stock 2 MB flash dump acquired from a US E70 X5 35d
- OpenRemap checksum verification: **11/11 valid**
- HW and SW numbers extracted directly from the dump (ASCII strings, cross-bank replication confirms the live software)

### 2. Calibration Discovery — TriCore Pointer Sweep

- Full flash disassembled with **Capstone (TriCore)**; Ghidra used for cross-reference and annotation
- 16-bit calibration pointer sweep across the binary; every candidate passed a binary-layout verification (word structure, monotonicity, payload sanity)
- Result: **1,336 unique verified calibration objects**

### 3. OLS / A2L Cross-Reference

- 530d donor OLS file converted to A2L (reference mapping package)
- Axis values and payload data matched to identify known curves; Bosch German curve descriptions carried into table descriptions where addresses matched

### 4. Driver's Wish ADC Verification

- Voltage linearization tables confirmed as **1D curves** (not 2D maps)
- EDC17 ADC values are stored in **millivolts (0–5000)**
- Payload filter: only curves scaling between **400 and 4800 mV** were accepted; structural headers (e.g. `[25, 25, 25]`) were rejected as garbage
- **60 verified ADC curves** with real `[count][axis][values]` axes stored in flash

### 5. XDF Generation

- Classic TunerPro XDF dialect (v1.60): `XDFHEADER`, `BINHEADER`, `TABLEINFO`, `TABLE` with `Xaxis` / `Yaxis` / `Zaxis` nodes
- **2D geometry rule:** `mmedcolcount = X-axis length`, `mmedrowcount = Y-axis length` — validated against a genuine TunerPro reference XDF (10/10 of its 2D tables follow this exactly)
- Degenerate-dimension entries (e.g. `2x0`) are rendered as 1D curves, never as zero-dimension maps
- Axes physically stored in flash carry real offsets; tables without a stored axis use linear index axes — no fabricated offsets
- **Overlap filter:** the generator warns on overlapping tables and skips same-kind strict-containment duplicates before emitting XML

---

## EWS / Immobilizer Delete

### Method

A US 335d donor pair (immobilizer ON / OFF) was diffed. Three identical 4-byte changes were found, all sharing the same instruction-context signature:

```text
8B02 2022   →   0000 8212
```

The 335d donor sites (`0x00A4B6`, `0x0968D0`, `0x0E5F4E`) do not exist at the same offsets in the X5 dump. The shared context signature

```text
0F F4 80 20 8B 02 20 22 00 90
```

was therefore located inside the X5 binary, and each candidate site was disassembled (Capstone, TriCore) to confirm it gates the EWS check.

This is the **canonical** method — it is what produced the released patched binaries. Two other approaches were investigated but are **not** supported:

- **NOP patch** (`patch_ews_delete.py`) — nullifies the EWS check instruction (`8B022022` → `00008212`, same payload). Retained for research but not recommended.
- **VIN zeroing** (`apply_patch.py`) — clears the VIN config block. See the VIN-zeroing risk note below.

### Verified Patch Sites (X5 dump)

| Site         | Original   | Patched    | Verification                                | Block              |
| :----------- | :--------- | :--------- | :------------------------------------------ | :----------------- |
| `0x00A4B6`   | `8B022022` | `00008212` | Context signature `0FF4…` + disassembly      | Customer Block     |
| `0x0908A6`   | `8B022022` | `00008212` | Context signature `0FF4…` + disassembly      | Application SW #0  |
| `0x0E2FA8`   | `8B022022` | `00008212` | Context signature `0FF4…` + disassembly      | Application SW #0  |

### Output Binaries

| File                      | Notes                                            |
| :------------------------ | :----------------------------------------------- |
| `X5d_Stock_ImmoOff.bin`   | 3-site patch applied, stock layout (9/11 valid)   |
| `X5d_Stock_ImmoOff_CSFixed.bin` | 3-site patch + checksums recalculated (11/11) |

> ⚠️ **These binaries disable the immobilizer.** Use only on a vehicle where that is intended, and flash with a tool that can verify the result.

### VIN Zeroing Risk

> ⚠️ **Zeroing the VIN is destructive and unsupported for general use.**

The VIN lives at flash `0x180099` (17 ASCII characters, e.g. `0089ZH0A7UABGK244` on the X5 dump) inside the **Dataset #0** calibration block. The EWS key slot immediately follows at `0x180074`.

On the stock X5 dump neither the VIN nor the EWS key slot is all-zero, so a clean zero-fill would be immediately obvious as a modification. The risks of zeroing both:

- **EWS / immobilizer:** the immobilizer match fails — the ECU will not attempt fuel/ignition enable unless the delete patch is also applied, otherwise the engine will **crank but not start**.
- **DTC / limp:** a zeroed VIN trips VIN-related DTCs (`2Axx`, `2Fxx`) on the next fault cycle; on some EDC17 variants the ECU logs a "configuration mismatch" and may enter a reduced-power limp mode until the VIN is restored.
- **DME-SVN sync:** the VIN propagates to the ABS/DSC/DDE over CAN in the X5 diesel; zeroing it on a standalone swap can break the stability/traction systems that read the VIN as a sync token.
- **Diagnostic:** any future dealer/pro-tool session will see a blank VIN and refuse to run guided procedures against the unit.

**For standalone use:** the supported path is the instruction-gate patch on `mpc_full.bin`; you do **not** need to touch the VIN. The VIN-zeroing path (`apply_patch.py`) is research only and is **not** required to defeat the immobilizer. Always restore the original, valid VIN after a standalone installation.

---

## Regenerating the XDF

```bash
cd EDC17CP09
python3 gen_xdf.py
```

The generator reads `master_dataset.json`, rebuilds the XDF deterministically (with overlap filtering), and prints a summary count only — no binary or hex data to stdout.

---

## Tests

A golden test pins known-good inputs to known-good outputs so any regression in the tools is caught in one command:

```bash
cd EDC17CP09
python3 tests/golden_test.py
```

The suite checks:

- `mpc_full.bin` verifies **11/11** checksums with `medc17_checksum_tool.py`;
- `patch_gate_ews.py --verify X5d_Stock_ImmoOff.bin` reproduces the committed binary **byte-for-byte**;
- `X5d_Stock_ImmoOff.bin` → `medc17_checksum_tool.py --correct` → **byte-identical** to `X5d_Stock_ImmoOff_CSFixed.bin`;
- the 3-site patch is applied at **exactly** `0x00A4B6`, `0x0908A6`, `0x0E2FA8`, and nowhere else;
- the v1.2 XDF parses as XML with **1,312** entries (966 curves + 83 2D + 172 scalars + 122 masks), **zero** `x0` zero-dimension names, and correct per-axis `mmedcolcount`/`mmedrowcount` on all 52 true 2D grids.

---

## Project Status

| Workstream                                    | Status      |
| :-------------------------------------------- | :---------- |
| Binary acquisition & checksum verification    | ✅ Done      |
| OpenRemap map detection (40 tables, 200 axes) | ✅ Done      |
| TriCore pointer sweep (1,336 objects)         | ✅ Done      |
| OLS / A2L cross-reference (530d donor)        | ✅ Done      |
| Driver's Wish ADC 1D correction               | ✅ Done      |
| EWS gate patch sites located & disassembled   | ✅ Done      |
| Overlap detection in XDF generator            | ✅ Done (v1.2) |
| Golden test suite                              | ✅ Done      |
| Community XDF v1.2 (HW/SW-pinned filename)    | ✅ Released  |
| Archive of superseded XDFs                    | ✅ Done      |
| Ghidra annotation pass                        | 🔄 In progress |

---

## Limitations

- **Labels are best-effort.** Table titles and descriptions derive from Bosch taxonomy and OLS cross-reference — verify against vehicle behavior before tuning.
- **Axis values.** Only curves with axes physically stored in flash carry real axis values; all other tables use linear index axes (`0…N−1`). No offsets were fabricated.
- **2D orientation.** Dimensions are stored as rows × columns; the vehicle-axis orientation of X/Y is not encoded in the ECU layout.
- **Overlap dedup.** Same-kind containment duplicates are removed at generation time (see the Table Breakdown note); 31 degenerate 2D entries are emitted as 1D curves, not as 2D tables with a `0` dimension.

---

## Credits

- **Th3cavalry** — project owner, flash acquisition, verification
- **Hermes (Nous Research)** — automation, disassembly, XDF generation
- Community mapping references (530d OLS/A2L set)
- OpenRemap — map scanning and checksum tooling
- Ghidra / Capstone — TriCore disassembly

---

*Calibration data is provided for research and personal use. Verify every value before use on a moving vehicle.*
