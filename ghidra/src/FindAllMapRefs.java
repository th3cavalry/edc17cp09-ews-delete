// FindAllMapRefs.java - Find code references to all 40 map addresses
// Searches for loads/stores to map data regions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import java.util.*;
import java.io.*;

public class FindAllMapRefs extends GhidraScript {
    
    // Our 40 map addresses
    long[] mapAddresses = {
        0x03454A, 0x034A8A, 0x034FCA,  // 32x21 maps
        0x1AA9D0, 0x1B448C, 0x1B540A, 0x1BA3BE, 0x1BA6DA,
        0x1C008C, 0x1C0094, 0x1D2F04, 0x1D2F0E, 0x1D3148,
        0x1D3150, 0x1D338C, 0x1D3396, 0x1D3A58, 0x1D3A66,
        0x1D3CB0, 0x1D3EE0, 0x1D3EEA, 0x1D45AC, 0x1D45BE,
        0x1D4802, 0x1D4810, 0x1D4A34, 0x1D5868, 0x1D598C,
        0x1D5B10, 0x1D5C34, 0x1D5F0C, 0x1D6068, 0x1D9420,
        0x1DB1EC, 0x1DB3F0, 0x1DBE00, 0x1DBF14, 0x1DC0AC,
        0x1DE74E, 0x1DE952
    };
    
    @Override
    protected void run() throws Exception {
        Listing listing = currentProgram.getListing();
        Memory memory = currentProgram.getMemory();
        
        PrintWriter out = new PrintWriter("/home/brandon/Documents/EDC17CP09/ghidra_map_refs.txt");
        out.println("=== MAP ADDRESS REFERENCES ===\n");
        
        // Get all instructions
        InstructionIterator iter = listing.getInstructions(true);
        
        Map<Long, List<String>> refs = new HashMap<>();
        for (long addr : mapAddresses) {
            refs.put(addr, new ArrayList<>());
        }
        
        int count = 0;
        while (iter.hasNext()) {
            Instruction instr = iter.next();
            String mnemonic = instr.getMnemonicString();
            
            // Look for load/store instructions
            if (mnemonic.startsWith("LD") || mnemonic.startsWith("ST") || 
                mnemonic.startsWith("MOV") || mnemonic.contains("mov")) {
                
                // Get operands
                for (int i = 0; i < instr.getNumOperands(); i++) {
                    Scalar scalar = instr.getScalar(i);
                    if (scalar != null) {
                        long value = scalar.getSignedValue();
                        
                        // Check if this references any of our maps
                        for (long mapAddr : mapAddresses) {
                            // Allow for offset addressing (map address ± 64 bytes)
                            if (Math.abs(value - mapAddr) < 128) {
                                String ref = String.format("0x%08X: %s %s", 
                                    instr.getAddress().getOffset(),
                                    mnemonic,
                                    instr.toString());
                                refs.get(mapAddr).add(ref);
                            }
                        }
                    }
                }
            }
            
            count++;
            if (count % 100000 == 0) {
                out.println("Processed " + count + " instructions...");
                out.flush();
            }
        }
        
        out.println("\nProcessed " + count + " total instructions\n");
        out.println("=== RESULTS ===\n");
        
        // Report findings
        int found = 0;
        for (long mapAddr : mapAddresses) {
            List<String> refList = refs.get(mapAddr);
            if (!refList.isEmpty()) {
                found++;
                out.println(String.format("Map @ 0x%06X: %d references", mapAddr, refList.size()));
                for (int i = 0; i < Math.min(5, refList.size()); i++) {
                    out.println("  " + refList.get(i));
                }
                if (refList.size() > 5) {
                    out.println("  ... and " + (refList.size() - 5) + " more");
                }
                out.println();
            }
        }
        
        out.println(String.format("\nTotal: %d/%d maps have code references", found, mapAddresses.length));
        out.close();
        
        println("Analysis complete. Found references for " + found + "/" + mapAddresses.length + " maps");
        println("Results saved to ghidra_map_refs.txt");
    }
}
