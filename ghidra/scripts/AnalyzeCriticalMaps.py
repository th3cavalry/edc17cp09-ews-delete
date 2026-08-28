// Ghidra Jython script for analyzing discovered calibration pointers
// Uses Ghidra decompiler to determine TRUE dimensions and categories

from ghidra.program.model.listing import *
from ghidra.program.model.address import *
from ghidra.app.decompiler import *
from java.io import FileWriter
import json
from collections import Counter

# Critical addresses from sweep (selected samples)
CRITICAL_ADDRESSES = [
    # EWS candidates
    0x040008, 0x04003A, 0x04005D, 0x042FD9,
    # Driver's Wish candidates  
    0x191F6F, 0x1928F4, 0x19783C, 0x198140, 0x199000,
    # Torque limiters
    0x1B005D, 0x1B0158, 0x1B043A, 0x1B0497, 0x1B0FC5,
]

program = currentProgram
decompiler = state.getTool().getService(DecompileInterface)
listing = program.getListing()
memory = program.getMemory()
space = program.getAddressFactory().getDefaultAddressSpace()

results = []

for calib_addr in CRITICAL_ADDRESSES:
    # Get function containing a reference to this address
    # First, find instructions that reference this address
    refs_to_addr = []
    
    # Search for references to this calibration address
    for func in listing.getFunctions(True):
        code_iter = func.getEntryPoint().getAddressSet()
        try:
            instr_iter = listing.getInstructions(func.getEntryPoint(), True)
            while instr_iter.hasNext():
                instr = instr_iter.next()
                addr = instr.getAddress()
                
                # Check if this instruction references our calibration address
                try:
                    for i in range(instr.getNumOperands()):
                        op_objects = instr.getOpObjects(i)
                        for op in op_objects:
                            if hasattr(op, 'getAddress'):
                                op_addr = op.getAddress()
                                if op_addr and op_addr.getOffset() == calib_addr:
                                    refs_to_addr.append((func.getName(), addr))
                            elif hasattr(op, 'getValue'):
                                # Scalar value
                                val = op.getValue()
                                if isinstance(val, int) and val == calib_addr:
                                    refs_to_addr.append((func.getName(), addr))
                except:
                    pass
        except:
            pass
    
    # Get decompiled C code for the function
    decompiled_code = ""
    func_name = "unknown"
    
    if refs_to_addr:
        func_name = refs_to_addr[0][0]
        func = listing.getFunctionByName(func_name)
        if func:
            try:
                results_decomp = decompiler.decompileFunction(func, 60, monitor)
                if results_decomp and results_decomp.decompileCompleted():
                    decompiled_code = results_decomp.getDecompiledFunction().getC()
            except:
                decompiled_code = "[decompile error]"
    
    # Read data at calibration address
    data = bytearray(512)
    try:
        memory.getBytes(space.getAddress(calib_addr), data)
    except:
        data = bytearray(512)
    
    # Analyze structure
    first_bytes_hex = " ".join(f"{b:02x}" for b in data[:64])
    
    # Check for array loop patterns in C code
    is_array_loop = False
    array_size = 0
    if "for (" in decompiled_code or "while (" in decompiled_code:
        is_array_loop = True
        # Look for common array iteration patterns
        import re
        match = re.search(r'for\s*\(\s*\w+\s*=\s*\w+;\s*\w+\s*<\s*(\d+)', decompiled_code)
        if match:
            array_size = int(match.group(1))
    
    # Determine dimensions based on C code analysis
    if "struct" in decompiled_code or "typedef" in decompiled_code:
        # Check for struct definitions
        if "struct {" in decompiled_code:
            # Multi-dimensional struct
            rows_match = re.search(r'(\d+)\s*\[\s*(\d+)\s*\]', decompiled_code)
            if rows_match:
                dims = f"{rows_match.group(1)}x{rows_match.group(2)}"
            else:
                dims = "struct"
        else:
            dims = "struct"
    elif is_array_loop and array_size > 0:
        # Single-dimensional array with known loop count
        dims = f"{array_size}x1"
    elif calib_addr >= 0x189000 and calib_addr < 0x18B000:
        # DTC mask range - typically small arrays
        dims = "Nx2 (DTC mask)"
    else:
        # Fall back to raw data analysis
        axis_count = data[0] & 0xFF
        if 2 <= axis_count <= 32:
            rows = axis_count
            cols = data[rows+1] & 0xFF if rows+1 < len(data) else 1
            dims = f"{rows}x{cols}"
        else:
            dims = "unknown"
    
    # Categorize
    category = "Uncategorized"
    if calib_addr >= 0x040000 and calib_addr < 0x045000:
        category = "EWS/Immobilizer"
    elif calib_addr >= 0x190000 and calib_addr < 0x1A0000:
        category = "Driver's Wish"
    elif calib_addr >= 0x1AF000 and calib_addr < 0x1B3000:
        category = "Torque/Limiter"
    elif calib_addr >= 0x189000 and calib_addr < 0x18B000:
        category = "DTC/Error"
    
    result = {
        "calib_addr": f"0x{calib_addr:06X}",
        "category": category,
        "dimensions": dims,
        "is_array_loop": is_array_loop,
        "array_size": array_size if is_array_loop else 0,
        "first_bytes_hex": first_bytes_hex,
        "refs_from_func": func_name,
        "decompiled_preview": decompiled_code[:500] if len(decompiled_code) > 500 else decompiled_code
    }
    
    results.append(result)
    print(f"Analyzed 0x{calib_addr:06X}: {category} | {dims} | refs: {func_name}")

# Save results
output_path = "/home/brandon/Documents/EDC17CP09/ghidra_analysis_results.json"
with open(output_path, 'w') as f:
    json.dump(results, f, indent=2)

print(f"\nSaved to {output_path}")

# Print summary
cat_counts = Counter(r['category'] for r in results)
print("\nCategory breakdown:")
for cat, count in cat_counts.most_common():
    print(f"  {cat}: {count}")
