// Ghidra postScript: find function containing 0x154eb0 by scanning all function bodies
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.TaskMonitor;
import java.util.*;

public class EwsCaller extends GhidraScript {
    TaskMonitor monitor;
    DecompInterface dec;
    StringBuilder out = new StringBuilder();

    public void run() throws Exception {
        monitor = getMonitor();
        dec = new DecompInterface();
        dec.openProgram(currentProgram);
        long target = 0x154eb0;

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        List<Function> hits = new ArrayList<>();
        while (it.hasNext()) {
            Function f = it.next();
            long lo = f.getBody().getMinAddress().getOffset();
            long hi = f.getBody().getMaxAddress().getOffset();
            if (lo <= target && target <= hi) hits.add(f);
        }
        out.append("functions containing 0x154eb0: " + hits.size() + "\n");
        for (Function f : hits) {
            out.append("  " + f.getName() + " [" + f.getEntryPoint() + " .. " + f.getBody().getMaxAddress() + "] size=" +
                (f.getBody().getMaxAddress().getOffset()-f.getBody().getMinAddress().getOffset()) + "\n");
            DecompileResults r = dec.decompileFunction(f, 300, monitor);
            out.append("----- decompiled " + f.getName() + " -----\n");
            if (r.decompileCompleted()) out.append(r.getDecompiledFunction().getC());
            else out.append("decompile failed: " + r.getErrorMessage() + "\n");
        }

        java.io.File f = new java.io.File("/home/brandon/Documents/EDC17CP09/ghidra_ews_caller.txt");
        try (java.io.PrintWriter w = new java.io.PrintWriter(f)) { w.print(out); }
        println("wrote "+f+" ("+out.length()+" chars)");
    }
}
