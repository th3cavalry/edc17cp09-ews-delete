// Ghidra postScript: force-function at EWS call site + decompile the EWS task
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.TaskMonitor;

public class EwsForce extends GhidraScript {
    TaskMonitor monitor;
    DecompInterface dec;
    StringBuilder out = new StringBuilder();

    public void run() throws Exception {
        monitor = getMonitor();
        dec = new DecompInterface();
        dec.openProgram(currentProgram);

        AddressFactory af = currentProgram.getAddressFactory();
        FunctionManager fm = currentProgram.getFunctionManager();

        // find nearest function start before 0x154eb0, or force one
        Address callSite = af.getAddress("00154eb0");
        // search backwards for a likely function entry (look for a region not in any fn)
        // try force-creating at a few candidate entries
        long[] candidates = {0x154e90, 0x154ea0, 0x154e80, 0x154e00, 0x154d00, 0x154c00};
        Function made = null;
        for (long c : candidates) {
            Address a = af.getAddress(c);
            if (fm.getFunctionAt(a) == null) {
                made = fm.createFunction(a, "EWS_TASK_FORCED_"+Long.toHexString(c));
                if (made != null) { out.append("forced fn at 0x"+Long.toHexString(c)+" -> "+made.getEntryPoint()+" .. "+made.getBody().getMaxAddress()+"\n"); break; }
            } else {
                out.append("0x"+Long.toHexString(c)+" already in fn\n");
            }
        }

        // Also: find the biggest function whose body is near 0x154eb0 by scanning
        FunctionIterator it = fm.getFunctions(true);
        List<Function> near = new java.util.ArrayList<>();
        while (it.hasNext()) {
            Function f = it.next();
            long lo=f.getBody().getMinAddress().getOffset(), hi=f.getBody().getMaxAddress().getOffset();
            if (lo < 0x156000 && hi > 0x154000) near.add(f);
        }
        out.append("\nfunctions overlapping 0x154000-0x156000: "+near.size()+"\n");
        for (Function f : near) out.append("  "+f.getName()+" ["+f.getEntryPoint()+".."+f.getBody().getMaxAddress()+"] size="+(f.getBody().getMaxAddress().getOffset()-f.getBody().getMinAddress().getOffset())+"\n");

        if (made != null) {
            DecompileResults r = dec.decompileFunction(made, 300, monitor);
            out.append("\n===== forced EWS task decompile =====\n");
            if (r.decompileCompleted()) out.append(r.getDecompiledFunction().getC());
            else out.append("failed: "+r.getErrorMessage()+"\n");
        }

        java.io.File f = new java.io.File("/home/brandon/Documents/EDC17CP09/ghidra_ews_force.txt");
        try (java.io.PrintWriter w = new java.io.PrintWriter(f)) { w.print(out); }
        println("wrote "+f+" ("+out.length()+" chars)");
    }
}
