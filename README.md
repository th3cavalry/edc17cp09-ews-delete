# EDC17CP09 XDF — TunerPro Definition from Binary RE

Building a complete, accurate TunerPro XDF for the BMW EDC17CP09 M57 3.0d (US spec X5 35d, E70) by reverse engineering the flash binary.

No DAMOS, no donor definition — pure binary analysis.

## Target

| Field | Value |
|-------|-------|
| ECU | Bosch EDC17CP09 |
| Processor | Infineon TC1796 (TriCore) |
| Hardware | 0281017487 |
| Software | 10375506116137U6A |
| Part Number | 851241701 |
| Flash Size | 2 MB (0x200000) |
| Calibration Region | 0x040000 – 0x200000 |
| Code Region | 0x020000 – 0x180000 |

## Methodology

1. **Map detection** — OpenRemap `scan-maps` identifies candidate 2D/3D tables and their axes by pattern scoring
2. **Ghidra cross-references** — Import the binary into Ghidra with TriCore language, then trace code reads to each table address. The calling function reveals what the table controls (fuel request, torque limit, boost target, etc.)
3. **Axis classification** — Axis value ranges and step sizes identify physical units: RPM (800–7500, step 500), load/mbar (100–2500, step 50–250), fuel mass/mm³, rail pressure/bar, pedal position/%
4. **EDC17 taxonomy** — Map the tables to standard Bosch EDC17 function groups:
   - **Driver Request** (`DrvDesTorq`) — pedal-to-torque conversion
   - **Torque Structure** — base torque, torque limits, smoke limiter
   - **Fuel Quantity** (`EngPrt_qLim`) — injection quantity limits
   - **Rail Pressure** (`Rail_pSetPointBas`) — common rail target
   - **Injection Timing** (`InjCrv_phiMI1Bas`) — SOI angle
   - **Injection Duration** (`InjVlv_tiET`) — injector open time
   - **Boost Control** (`PCR_pDesBas`) — MAP target
   - **VNT / Wastegate** (`PCR_VNTDesBas`) — turbo actuator duty
   - **EGR** (`EGRCtrl`) — recirculation valve
   - **Idle** — idle speed controller
   - **Limiters** — RPM, torque, smoke, rail pressure caps
5. **Scaling factors** — Determine the math equation for each axis and data column (e.g., raw ×0.1 = bar, raw ×1.0 = RPM)
6. **Validation** — Write known test values, read back, confirm TunerPro displays correct physical units

## Tools

| Tool | Purpose |
|------|---------|
| Ghidra 12.1.3 | TriCore disassembly, decompiler, cross-reference tracing |
| OpenRemap | Automated map/axis detection from raw binary |
| medc17-checksum-tool | Validate and correct 11-block CRC after edits |
| Python + capstone | Scripted binary analysis and disassembly |
| TunerPro | Load and validate the XDF against the bin |

## File Structure

```
├── mpc_full.bin              # Stock 2MB flash dump (HW 0281017487, 11/11 checksums valid)
├── scan_mpc.json             # OpenRemap output: 40 tables + 200 axes
├── maps_decoded.json         # Decoded tables with axis offsets and raw values
├── gen_xdf.py               # XDF generator (reads maps_decoded.json → .xdf)
├── verify_xdf.py            # Validates XDF XML structure and address correctness
├── medc17_checksum_tool.py  # Checksum validation/correction utility
├── README.md                # This file
└── .gitignore               # Excludes venv, Ghidra project, non-XDF binaries
```

## Usage

```bash
# 1. Generate XDF from decoded maps
python gen_xdf.py

# 2. Validate the output
python verify_xdf.py

# 3. Verify checksums on the binary
python medc17_checksum_tool.py --verify mpc_full.bin

# 4. Load in TunerPro
#    Open EDC17CP09_M57_0281017487.xdf → load mpc_full.bin
```

## Status

| Phase | Status |
|-------|--------|
| Binary acquisition & validation | ✅ Done |
| Map detection (OpenRemap) | ✅ 40 tables found |
| Axis extraction | ✅ All monotonic, aligned |
| Ghidra cross-reference tracing | 🔄 In progress |
| Map naming (EDC17 taxonomy) | 🔄 In progress |
| Scaling factor determination | ⏳ Pending |
| XDF generation v1 (generic labels) | ✅ Done |
| XDF generation v2 (RE-backed labels) | 🔄 In progress |
| Final XDF (complete coverage) | ⏳ Pending |

## Known Map Families (EDC17 Standard)

Based on Bosch EDC17 architecture, these are the calibration groups we expect to find:

| Group | Function | Expected Maps | Status |
|-------|----------|--------------|--------|
| Driver Request | Pedal → torque demand | 12×12 (×5 variants per mode) | ✅ Detected |
| Torque Limiters | Max torque caps | 16×5, 16×11 (low/high range pairs) | ✅ Detected |
| Fuel Quantity | Injection mass limit | 6×16, 8×10 | ✅ Detected |
| Rail Pressure | Common rail setpoint | 6×4, 6×6, 8×8 | ✅ Detected |
| Injection Timing | SOI angle (°CA BTDC) | 8×8 | ✅ Detected |
| Boost Target | MAP setpoint | 21×32 | ✅ Detected |
| VNT/Wastegate | Turbo duty cycle | 8×16 | ✅ Detected |
| RPM Limiter | Max RPM cap | 8×8 | ✅ Detected |
| Main Torque | Primary torque structure | 16×16 | ✅ Detected |

## Contributing

This is a solo RE project. If you have EDC17CP09 experience, DAMOS files for HW 0281017487, or WinOLS definitions for this software version, open an issue or PR.

## License

Reverse engineering for interoperability, research, and repair.
