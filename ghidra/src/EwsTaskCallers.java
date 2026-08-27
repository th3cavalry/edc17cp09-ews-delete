// Ghidra postScript: find + decompile callers of the EWS task FUN_00154e82 (fuel gate)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.TaskMonitor;
import java.util.*;

public class EwsTaskCallers extends GhidraScript {
    TaskMonitor monitor;
    DecompInterface dec;
    StringBuilder out = new StringBuilder();

    public void run() throws Exception {
        monitor = getMonitor();
        dec = new DecompInterface();
        dec.openProgram(currentProgram);
        AddressFactory af = currentProgram.getAddressFactory();

        Address taskEntry = af.getAddress("00154e82");
        out.append("=== callers of EWS task FUN_00154e82 (fuel-gate hunt) ===\n");
        Reference[] callers = getReferencesTo(taskEntry);
        out.append("total ref sites: " + callers.length + "\n");
        Set<Long> seen = new LinkedHashSet<>();
        for (Reference r : callers) {
            out.append("  call site 0x" + Long.toHexString(r.getFromAddress().getOffset()) + " type=" + r.getReferenceType() + "\n");
            Function f = getFunctionAt(r.getFromAddress());
            if (f != null && !seen.contains(f.getEntryPoint().getOffset())) {
                seen.add(f.getEntryPoint().getOffset());
                long sz = f.getBody().getMaxAddress().getOffset()-f.getBody().getMinAddress().getOffset();
                out.append("\n########## CALLER " + f.getName() + " [0x" + Long.toHexString(f.getEntryPoint().getOffset()) + "] size=" + sz + " ##########\n");
                if (sz > 20000) { out.append("(too big, size " + sz + ")\n"); continue; }
                try {
                    DecompileResults rr = dec.decompileFunction(f, 300, monitor);
                    if (rr.decompileCompleted()) out.append(rr.getDecompiledFunction().getC());
                    else out.append("decompile failed: " + rr.getErrorMessage() + "\n");
                } catch (Exception ex) { out.append("exc: " + ex + "\n"); }
            }
        }
        // also: the task is small; find what it returns to — but mainly we want callers.
        java.io.File f = new java.io.File("/home/brandon/Documents/EDC17CP09/ghidra_ews_taskcallers.txt");
        try (java.io.PrintWriter w = new java.io.PrintWriter(f)) { w.print(out); }
        println("wrote " + f + " (" + out.length() + " chars)");
    }
}
