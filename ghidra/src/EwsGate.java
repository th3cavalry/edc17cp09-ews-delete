// Ghidra postScript: find the FUEL CUT gate that consumes the EWS authorization result
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.TaskMonitor;
import java.util.*;

public class EwsGate extends GhidraScript {
    Memory mem;
    TaskMonitor monitor;
    DecompInterface dec;

    public void run() throws Exception {
        Address CODE_LO = currentProgram.getAddressFactory().getAddress("0x020000");
        Address CODE_HI = currentProgram.getAddressFactory().getAddress("0x180000");
        mem = currentProgram.getMemory();
        monitor = getMonitor();
        dec = new DecompInterface();
        dec.openProgram(currentProgram);
        StringBuilder out = new StringBuilder();

        // EWS globals seen in the state machine FUN_0008def6
        long[] ewsGlobals = {
            0x000319f, // status/handshake flag (checked & 0x80)
            0x00031a0, // set to 0x80
            0x0003586, // counter (< 0xf0)
            0x0003587,
            0x000356b, 0x000356c,
            0x000090e, 0x0000933, 0x0000929, 0x0000932, 0x0000917, 0x0000915,
            0x000092d, 0x000092c, 0x0000923, 0x000090d, 0x0000906,
        };

        // 1) For each EWS global, find referencing functions
        out.append("=== EWS global -> referencing functions ===\n");
        Set<Long> consumerFns = new LinkedHashSet<>();
        for (long g : ewsGlobals) {
            Address ga = currentProgram.getAddressFactory().getAddress(Long.toHexString(g));
            Reference[] refs = getReferencesTo(ga);
            out.append("0x" + Long.toHexString(g) + " refs=" + refs.length + " -> fns:");
            Set<Long> fns = new LinkedHashSet<>();
            for (Reference r : refs) {
                if (r.getFromAddress().compareTo(CODE_LO) >= 0 && r.getFromAddress().compareTo(CODE_HI) < 0) {
                    Function fn = getFunctionAt(r.getFromAddress());
                    if (fn != null) { fns.add(fn.getEntryPoint().getOffset()); consumerFns.add(fn.getEntryPoint().getOffset()); }
                }
            }
            for (Long f : fns) out.append(" 0x" + Long.toHexString(f));
            out.append("\n");
        }

        // 2) The caller of FUN_0008def6 is at 0x00154eb0 — decompile its function
        out.append("\n=== caller of EWS state machine (fn at 0x154eb0) ===\n");
        Function cf = getFunctionAt(currentProgram.getAddressFactory().getAddress("0x00154eb0"));
        if (cf != null) {
            out.append("caller fn = " + cf.getName() + " [" + cf.getEntryPoint() + "," + cf.getBody().getMaxAddress() + "]\n");
        }

        // 3) Decompile consumer functions (those that reference EWS globals), skip the state machine itself
        out.append("\n=== decompiled EWS consumer functions ===\n");
        List<Long> order = new ArrayList<>(consumerFns);
        // sort by address
        Collections.sort(order);
        int done = 0;
        for (long faddr : order) {
            Function f = getFunctionAt(currentProgram.getAddressFactory().getAddress(Long.toHexString(faddr)));
            if (f == null) continue;
            long fsize = f.getBody().getMaxAddress().getOffset() - f.getBody().getMinAddress().getOffset();
            if (faddr == 0x0008def6) { out.append("skipping state machine 0x8def6\n"); continue; }
            if (fsize > 8000) { out.append("skip " + f.getName() + " (size " + fsize + ")\n"); continue; }
            done++;
            if (done > 40) { out.append("...stopping at 40\n"); break; }
            out.append("\n########## " + f.getName() + " [0x" + Long.toHexString(faddr) + "] size=" + fsize + " ##########\n");
            try {
                DecompileResults r = dec.decompileFunction(f, 90, monitor);
                if (r.decompileCompleted()) out.append(r.getDecompiledFunction().getC());
                else out.append("decompile failed: " + r.getErrorMessage() + "\n");
            } catch (Exception ex) { out.append("decompile exception: " + ex + "\n"); }
        }

        // 4) also decompile the caller of the state machine specifically
        if (cf != null) {
            out.append("\n########## CALLER " + cf.getName() + " ##########\n");
            try {
                DecompileResults r = dec.decompileFunction(cf, 120, monitor);
                if (r.decompileCompleted()) out.append(r.getDecompiledFunction().getC());
                else out.append("decompile failed: " + r.getErrorMessage() + "\n");
            } catch (Exception ex) { out.append("decompile exception: " + ex + "\n"); }
        }

        java.io.File f = new java.io.File("/home/brandon/Documents/EDC17CP09/ghidra_ews_gate.txt");
        try (java.io.PrintWriter w = new java.io.PrintWriter(f)) { w.print(out); }
        println("wrote " + f + " (" + out.length() + " chars)");
    }
}
