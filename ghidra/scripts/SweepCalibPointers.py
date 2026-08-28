# Sweeps TriCore code region for LEA/MOVH+ADD pairs resolving to calibration region.
# Cross-references against known maps, validates data structures, decompiles callers.
# @category EDC17CP09
# @author Hermes

from ghidra.program.model.listing import *
from ghidra.program.model.address import *
from ghidra.program.model.mem import *
from ghidra.program.model.scalar import *
from ghidra.program.model.symbol import *
from ghidra.app.decompiler import *
from ghidra.program.model.pcode import *
from ghidra.util.task import TaskMonitor

import json
import os

CODE_START = 0x020000
CODE_END = 0x180000
CALIB_START = 0x040000
CALIB_END = 0x200000

program = currentProgram
listing = program.getListing()
memory = program.getMemory()
space = program.getAddressFactory().getDefaultAddressSpace()

# Load known map addresses from scan_mpc.json
knownAddresses = set()
try:
    jsonPath = "/home/brandon/Documents/EDC17CP09/scan_mpc.json"
    with open(jsonPath, 'r') as f:
        scan_data = json.load(f)
    for entry in scan_data.get('tables', []):
        addr = entry.get('address', 0)
        knownAddresses.add(addr)
except Exception as e:
    println("Warning: Could not load scan_mpc.json: %s" % str(e))

println("Known addresses from scan_mpc.json: %d" % len(knownAddresses))

# Sweep instructions in code region
codeStart = space.getAddress(CODE_START)
codeEnd = space.getAddress(CODE_END)

instrIter = listing.getInstructions(codeStart, True)
calibRefs = {}  # calib_addr -> [code_refs]

instrCount = 0
while instrIter.hasNext() and not monitor.isCancelled():
    instr = instrIter.next()
    instrAddr = instr.getAddress()
    addr = instrAddr.getOffset()
    if addr >= CODE_END:
        break
    instrCount += 1

    # Check each operand for references into calibration region
    for i in range(instr.getNumOperands()):
        try:
            ops = instr.getOpObjects(i)
            for op in ops:
                if isinstance(op, Scalar):
                    val = op.getUnsignedValue()
                    if CALIB_START <= val < CALIB_END:
                        if val not in calibRefs:
                            calibRefs[val] = []
                        calibRefs[val].append(addr)
                elif isinstance(op, Address):
                    val = op.getOffset()
                    if CALIB_START <= val < CALIB_END:
                        if val not in calibRefs:
                            calibRefs[val] = []
                        calibRefs[val].append(addr)
        except Exception as e:
            pass

println("Instructions scanned: %d" % instrCount)
println("Unique calibration addresses referenced: %d" % len(calibRefs))

# Filter known maps
newRefs = {}
for calibAddr, codeRefs in calibRefs.items():
    if calibAddr not in knownAddresses:
        newRefs[calibAddr] = codeRefs

println("New (not in scan_mpc.json): %d" % len(newRefs))

# Structural heuristic validation
def classifyStructure(data):
    """Classify the data structure type based on heuristics."""
    # Check for all zeros or all FF
    allZero = all(b == 0 for b in data[:32])
    allFF = all(b == 0xFF for b in data[:32])
    if allZero or allFF:
        return "EMPTY"
    
    # Check for 1D scalar (single byte or word)
    # If bytes 2-31 are all zero or constant, likely a scalar
    restConstant = len(set(data[2:32])) <= 2
    if restConstant and (data[0] != 0 or data[1] != 0):
        return "SCALAR_1D"
    
    # Check for DTC mask array (sequential 2-byte values, many zeros mixed in)
    zeroCount = sum(1 for i in range(0, 32, 2) if data[i] == 0 and data[i+1] == 0)
    if 8 <= zeroCount <= 14:
        return "DTC_MASK"
    
    # Check for 2D map header (axis count bytes followed by data)
    axisCount = data[0] & 0xFF
    if 2 <= axisCount <= 32:
        # Check if next bytes look like axis values (monotonically increasing)
        monotonic = True
        for i in range(1, min(axisCount, 8)):
            if (data[i] & 0xFF) <= (data[i-1] & 0xFF) and data[i] != 0:
                monotonic = False
                break
        if monotonic:
            return "2D_MAP_WITH_AXIS"
    
    # Check for curve (small axis count + values)
    if 2 <= axisCount <= 16:
        return "CURVE"
    
    return "UNKNOWN"

def inferDimensions(structType, data):
    """Infer dimensions based on structure type."""
    if structType == "SCALAR_1D":
        return "1x1 (2 bytes)"
    elif structType == "DTC_MASK":
        return "N x 2 bytes (mask array)"
    elif structType == "2D_MAP_WITH_AXIS":
        rows = data[0] & 0xFF
        cols = data[rows + 1] & 0xFF if (rows + 1) < len(data) else 1
        if cols < 2 or cols > 32:
            cols = 1
        return "%d x %d" % (rows, cols)
    elif structType == "CURVE":
        pts = data[0] & 0xFF
        return "%d x 1 (curve)" % pts
    else:
        return "unknown"

def decompileFunction(func):
    """Decompile a function and return C code."""
    if func is None:
        return ""
    try:
        decompiler = state.getTool().getService(DecompileInterface)
        if decompiler is None:
            return "[decompiler unavailable]"
        results = decompiler.decompileFunction(func, 60, monitor)
        if results is not None and results.decompileCompleted():
            return results.getDecompiledFunction().getC()
    except Exception as e:
        return "[decompile error: %s]" % str(e)
    return "[no decompiled output]"

def categorizeByContext(context, structType):
    """Categorize map based on decompiled context."""
    ctxLower = context.lower()
    if "ews" in ctxLower or "wegfahr" in ctxLower or "immo" in ctxLower:
        return "EWS/Immobilizer"
    if "dfes" in ctxLower or "dtc" in ctxLower or "error" in ctxLower:
        return "DTC/Error"
    if "torque" in ctxLower or "drehmoment" in ctxLower or "begrenzung" in ctxLower:
        return "Torque/Limiter"
    if "rail" in ctxLower or "druck" in ctxLower or "pressure" in ctxLower:
        return "RailPressure"
    if "boost" in ctxLower or "lade" in ctxLower or "turbo" in ctxLower:
        return "Boost/VNT"
    if "inject" in ctxLower or "einspritz" in ctxLower or "injcrv" in ctxLower:
        return "Injection"
    if "egr" in ctxLower or "dpf" in ctxLower or "regener" in ctxLower:
        return "Emissions"
    if "accped" in ctxLower or "fahrer" in ctxLower or "pedal" in ctxLower:
        return "DriversWish"
    if structType == "DTC_MASK":
        return "DTC/Error"
    if structType == "SCALAR_1D":
        return "Scalar/Config"
    return "Uncategorized"

def bytesToHex(data, length):
    """Convert bytes to hex string."""
    return " ".join("%02x" % (b & 0xFF) for b in data[:min(length, len(data))])

# Validate and process each discovered pointer
results = []
validated = 0

for calibAddr, codeRefs in newRefs.items():
    # Read data at calibration address
    data = bytearray(256)
    try:
        memory.getBytes(space.getAddress(calibAddr), data)
    except Exception as e:
        continue
    
    # Classify structure type
    structType = classifyStructure(data)
    if structType == "UNKNOWN" or structType == "EMPTY":
        continue
    
    # Determine inferred dimensions
    dimensions = inferDimensions(structType, data)
    
    # Find calling function and decompile
    decompiledContext = ""
    for codeRef in codeRefs:
        func = listing.getFunctionContaining(space.getAddress(codeRef))
        if func is not None:
            decompiledContext = decompileFunction(func)
            break
    
    # Categorize by context
    category = categorizeByContext(decompiledContext, structType)
    
    result = {
        "calib_addr": "0x%X" % calibAddr,
        "code_refs": ["0x%X" % ref for ref in codeRefs],
        "struct_type": structType,
        "dimensions": dimensions,
        "category": category,
        "decompiled_context": decompiledContext[:500] + "..." if len(decompiledContext) > 500 else decompiledContext,
        "first_bytes_hex": bytesToHex(data, 32)
    }
    
    results.append(result)
    validated += 1
    
    if validated >= 2000:
        println("Hit 2000 validated limit, stopping.")
        break

println("Validated new maps: %d" % validated)

# Write results to JSON
outputPath = "/home/brandon/Documents/EDC17CP09/new_maps_discovered.json"
with open(outputPath, 'w') as f:
    json.dump(results, f, indent=2)

println("Results written to: %s" % outputPath)
