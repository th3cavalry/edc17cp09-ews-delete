// Ghidra postScript: decompile the EWS TASK (caller of state machine) + trace auth flag
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.TaskMonitor;
import java.util.*;

public class EwsTask extends GhidraScript {
    Memory mem;
    TaskMonitor monitor;
    DecompInterface dec;
    StringBuilder out = new StringBuilder();

    public void run() throws Exception {
        mem = currentProgram.getMemory();
        monitor = getMonitor();
        dec = new DecompInterface();
        dec.openProgram(currentProgram);

        // 1) decompile the function containing the call to the state machine (0x154eb0)
        Function cf = getFunctionAt(currentProgram.getAddressFactory().getAddress("00154eb0"));
        out.append("=== EWS task (fn containing call at 0x154eb0) ===\n");
        if (cf != null) {
            out.append("fn = " + cf.getName() + " [" + cf.getEntryPoint() + " .. " + cf.getBody().getMaxAddress() + "] size=" +
                (cf.getBody().getMaxAddress().getOffset()-cf.getBody().getMinAddress().getOffset()) + "\n");
            DecompileResults r = dec.decompileFunction(cf, 200, monitor);
            if (r.decompileCompleted()) out.append(r.getDecompiledFunction().getC());
            else out.append("decompile failed: " + r.getErrorMessage() + "\n");
        } else {
            out.append("no function at 0x154eb0\n");
        }

        // 2) find ALL functions that call the EWS state machine FUN_0008def6
        Address smEntry = currentProgram.getAddressFactory().getAddress("0008def6");
        Function sm = getFunctionAt(smEntry);
        out.append("\n=== all callers of EWS state machine FUN_0008def6 ===\n");
        if (sm != null) {
            Reference[] callers = getReferencesTo(smEntry);
            for (Reference r : callers) {
                out.append("  call site 0x" + Long.toHexString(r.getFromAddress().getOffset()) + "\n");
            }
            // decompile each caller's function
            Set<Long> seen = new HashSet<>();
            for (Reference r : callers) {
                Function f = getFunctionAt(r.getFromAddress());
                if (f != null && !seen.contains(f.getEntryPoint().getOffset())) {
                    seen.add(f.getEntryPoint().getOffset());
                    out.append("\n########## caller " + f.getName() + " [0x" +
                        Long.toHexString(f.getEntryPoint().getOffset()) + "] ##########\n");
                    try {
                        DecompileResults rr = dec.decompileFunction(f, 200, monitor);
                        if (rr.decompileCompleted()) out.append(rr.getDecompiledFunction().getC());
                        else out.append("decompile failed: " + rr.getErrorMessage() + "\n");
                    } catch (Exception ex) { out.append("exc: "+ex+"\n"); }
                }
            }
        }

        java.io.File f = new java.io.File("/home/brandon/Documents/EDC17CP09/ghidra_ews_task.txt");
        try (java.io.PrintWriter w = new java.io.PrintWriter(f)) { w.print(out); }
        println("wrote "+f+" ("+out.length()+" chars)");
    }
}
