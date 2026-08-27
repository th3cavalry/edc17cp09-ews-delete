/*
 * TraceTables.java - Ghidra postscript
 * For each calibration table address, find all code references and the containing functions.
 * Output: table_offset -> list of {code_addr, function_name}
 */
// @category EDC17
// @author Hermes

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.lang.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class TraceTables extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Code region: 0x020000 - 0x180000
        long CODE_LO = 0x020000;
        long CODE_HI = 0x180000;
        
        // Table addresses (from maps_decoded.json - the 40 top tables)
        long[] tableAddrs = {
            0x344EA, 0x3491C, 0x34D4E, 0x35180, 0x355B2,
            0x359E4, 0x35E16, 0x36248, 0x3667A, 0x36AAC,
            0x36EDE, 0x37310, 0x37742, 0x37B74, 0x37FA6,
            0x383D8, 0x3880A, 0x38C3C, 0x3906E, 0x394A0,
            0x398D2, 0x39D04, 0x3A136, 0x3A568, 0x3A99A,
            0x3ADCC, 0x3B1FE, 0x3B630, 0x3BA62, 0x3BE94,
            0x3C2C6, 0x3C6F8, 0x3CB2A, 0x3CF5C, 0x3D38E,
            0x3D7C0, 0x3DBF2, 0x3E024, 0x3E456, 0x3E888
        };
        
        PrintWriter out = new PrintWriter(new FileWriter(
            "/home/brandon/Documents/EDC17CP09/trace_tables.txt"));
        
        out.println("=== EDC17CP09 Table -> Code Reference Trace ===");
        out.println();
        
        for (long tableAddr : tableAddrs) {
            out.println("--- Table @ 0x" + Long.toHexString(tableAddr).toUpperCase() + " ---");
            
            // Search code region for 32-bit LE references to this address
            byte[] target = new byte[4];
            target[0] = (byte)(tableAddr & 0xFF);
            target[1] = (byte)((tableAddr >> 8) & 0xFF);
            target[2] = (byte)((tableAddr >> 16) & 0xFF);
            target[3] = (byte)((tableAddr >> 24) & 0xFF);
            
            int refsFound = 0;
            Address searchAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(CODE_LO);
            Address endAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(CODE_HI);
            
            while (searchAddr != null && searchAddr.compareTo(endAddr) < 0) {
                Address found = mem.findBytes(searchAddr, endAddr, target, null, true, monitor);
                if (found == null) break;
                
                long refOffset = found.getOffset();
                Function func = fm.getFunctionContaining(found);
                String funcName = func != null ? func.getName() + " (0x" + Long.toHexString(func.getEntryPoint().getOffset()) + ")" : "UNKNOWN";
                
                out.println("  Code ref @ 0x" + Long.toHexString(refOffset).toUpperCase() + " in " + funcName);
                refsFound++;
                
                searchAddr = found.add(1);
                if (refsFound > 20) {
                    out.println("  ... (truncated at 20 refs)");
                    break;
                }
            }
            
            if (refsFound == 0) {
                out.println("  NO code references found");
            }
            out.println();
        }
        
        out.close();
        println("Trace complete. Output: trace_tables.txt");
    }
}
