// Ghidra Jython script for analyzing discovered calibration pointers
// Uses Ghidra decompiler to determine TRUE dimensions and categories

import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.util.task.TaskMonitor;
import java.io.*;

public class AnalyzeCriticalMaps extends GhidraScript {

    // Critical addresses from sweep
    long[] CRITICAL_ADDRESSES = {
        0x040008, 0x04003A, 0x04005D, 0x042FD9,  // EWS
        0x191F6F, 0x1928F4, 0x19783C, 0x198140, 0x199000,  // Driver's Wish
        0x1B005D, 0x1B0158, 0x1B043A, 0x1B0497, 0x1B0FC5  // Torque
    };

    @Override
    protected void run() throws Exception {
        Program program = currentProgram;
        DecompilerInterface decompiler = state.getTool().getService(DecompileInterface);
        Listing listing = program.getListing();
        Memory memory = program.getMemory();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

        println("Starting Ghidra analysis of critical calibration pointers...\n");

        for (long calib_addr : CRITICAL_ADDRESSES) {
            analyzeAddress(program, decompiler, listing, memory, space, calib_addr);
        }

        println("\nAnalysis complete.");
    }

    void analyzeAddress(Program program, DecompilerInterface decompiler, Listing listing, 
                        Memory memory, AddressSpace space, long calib_addr) throws Exception {
        
        println("=== Analyzing 0x" + Long.toHexString(calib_addr).toUpperCase() + " ===");
        
        // Find functions that reference this calibration address
        String func_name = findReferencingFunction(listing, calib_addr);
        
        // Get decompiled C code
        String decompiled_code = "";
        if (func_name != null && !func_name.isEmpty()) {
            println("Function: " + func_name);
            Function func = listing.getFunctionByName(func_name);
            if (func != null) {
                DecompileResults results = decompiler.decompileFunction(func, 60, monitor);
                if (results != null && results.decompileCompleted()) {
                    decompiled_code = results.getDecompiledFunction().getC();
                    
                    // Print first 1000 chars of decompiled code
                    String preview = decompiled_code.length() > 1000 
                        ? decompiled_code.substring(0, 1000) + "..."
                        : decompiled_code;
                    println("Decompiled preview:");
                    println(preview);
                } else {
                    println("Decompile failed: " + results.getErrorMessage());
                }
            }
        } else {
            println("No referencing function found");
        }

        // Read data at calibration address
        byte[] data = new byte[512];
        try {
            memory.getBytes(space.getAddress(calib_addr), data);
        } catch (Exception e) {
            println("Error reading memory: " + e.getMessage());
            return;
        }

        String first_bytes_hex = bytesToHex(data, 64);
        println("\nFirst 64 bytes: " + first_bytes_hex);

        // Analyze structure from C code
        String dims = analyzeDimensions(decompiled_code, data);
        println("Dimensions: " + dims);

        // Determine category
        String category = determineCategory(calib_addr, dims);
        println("Category: " + category);

        println("\n");
    }

    String findReferencingFunction(Listing listing, long target_addr) {
        for (Function func : listing.getFunctions(true)) {
            try {
                InstructionIterator iter = listing.getInstructions(func.getEntryPoint(), true);
                while (iter.hasNext()) {
                    Instruction instr = iter.next();
                    Address addr = instr.getAddress();
                    
                    // Check operands for our target address
                    for (int i = 0; i < instr.getNumOperands(); i++) {
                        Object[] ops = instr.getOpObjects(i);
                        for (Object op : ops) {
                            if (op instanceof Address) {
                                if (((Address) op).getOffset() == target_addr) {
                                    return func.getName();
                                }
                            } else if (op instanceof Scalar) {
                                if (((Scalar) op).getUnsignedValue() == target_addr) {
                                    return func.getName();
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // Skip functions that fail
            }
        }
        return null;
    }

    String analyzeDimensions(String decompiled_code, byte[] data) {
        // Check for struct definitions in C code
        if (decompiled_code.contains("struct") || decompiled_code.contains("typedef")) {
            if (decompiled_code.contains("struct {") || decompiled_code.contains("struct\n{")) {
                return "struct";
            }
        }
        
        // Check for array loops with known sizes
        if (decompiled_code.contains("for (") || decompiled_code.contains("while (")) {
            // Look for loop patterns like "for (i = 0; i < 256; i++)"
            int idx = decompiled_code.indexOf("for (");
            if (idx >= 0) {
                String for_clause = decompiled_code.substring(idx, Math.min(idx + 100, decompiled_code.length()));
                // Try to extract the loop bound
                int gt_idx = for_clause.indexOf("<");
                if (gt_idx >= 0) {
                    int semicolon_idx = for_clause.indexOf(";", gt_idx);
                    if (semicolon_idx > 0) {
                        String bound_str = for_clause.substring(gt_idx + 1, semicolon_idx).trim();
                        try {
                            int bound = Integer.parseInt(bound_str);
                            return bound + "x1";
                        } catch (NumberFormatException e) {
                            // Try to extract number from string
                            String num = bound_str.replaceAll("\\D+", "");
                            if (!num.isEmpty()) {
                                return num + "x1";
                            }
                        }
                    }
                }
            }
        }
        
        // Fall back to raw data analysis
        int axis_count = data[0] & 0xFF;
        if (axis_count >= 2 && axis_count <= 32) {
            int rows = axis_count;
            int cols = data.length > rows + 1 ? (data[rows + 1] & 0xFF) : 1;
            return rows + "x" + cols;
        } else if (axis_count == 1 || axis_count == 0) {
            // Likely a scalar or small array
            return "scalar/array";
        }
        
        return "unknown";
    }

    String determineCategory(long addr, String dims) {
        if (addr >= 0x040000 && addr < 0x045000) {
            return "EWS/Immobilizer";
        } else if (addr >= 0x190000 && addr < 0x1A0000) {
            return "Driver's Wish";
        } else if (addr >= 0x1AF000 && addr < 0x1B3000) {
            return "Torque/Limiter";
        } else if (addr >= 0x189000 && addr < 0x18B000) {
            return "DTC/Error";
        }
        
        // Use dimensions to help categorize
        if (dims.contains("Nx2") || dims.contains("mask")) {
            return "DTC/Error";
        }
        
        return "Uncategorized";
    }

    String bytesToHex(byte[] data, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(len, data.length); i++) {
            sb.append(String.format("%02x", data[i] & 0xFF));
            if (i < Math.min(len, data.length) - 1) {
                sb.append(" ");
            }
        }
        return sb.toString();
    }
}
