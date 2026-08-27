# EDC17CP09 XDF Reverse Engineering

Building a complete, accurate TunerPro XDF definition for BMW EDC17CP09 (M57 3.0d) firmware through binary reverse engineering.

## Target
- **ECU:** Bosch EDC17CP09
- **Hardware:** 0281017487
- **Software:** 10375506116137U6A
- **Processor:** TC1796 (TriCore)
- **Binary:** 2MB flash dump (mpc_full.bin)

## Approach
1. **Automated map detection** via OpenRemap (40 calibration tables + 200 axes detected)
2. **Ghidra cross-reference analysis** to trace which code reads each table
3. **EDC17 taxonomy mapping** using standard Bosch map families (Torque, Fuel, Boost, Injection)
4. **Physics-based validation** of axis ranges and value distributions
5. **Iterative refinement** with proper scaling factors and units

## Status
- ✅ Binary validation (11/11 checksums valid)
- ✅ Map detection (40 tables identified)
- ✅ Axis extraction (all monotonic, properly aligned)
- 🔄 Ghidra code reference tracing (in progress)
- 🔄 Map classification and naming (in progress)
- ⏳ Scaling factor determination
- ⏳ Final XDF generation

## Tools
- **Ghidra 12.1.3** - TriCore disassembly and cross-reference analysis
- **OpenRemap** - Automated map/axis detection
- **Python** - Binary analysis, validation, XDF generation
- **TunerPro XDF** - Target output format

## Methodology
This project uses pure reverse engineering without relying on DAMOS files or proprietary tools. Every map is validated through:
- Code cross-references (what function reads this address?)
- Axis pattern analysis (RPM, load, temperature ranges)
- Value distribution (min/max/avg to infer units and scaling)
- EDC17 standard map families (torque structure, fuel request, boost control)

## Output
`EDC17CP09_M57_0281017487.xdf` - TunerPro definition file with complete map coverage

## License
Reverse engineering for interoperability and repair purposes.
