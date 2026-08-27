// Ghidra postScript: find the FUEL CUT gate — code refs to EWS RAM authorization globals
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.TaskMonitor;
import java.util.*;

public class EwsFuelGate extends GhidraScript {
    Memory mem;
    TaskMonitor monitor;
    DecompInterface dec;
    StringBuilder out = new StringBuilder();

    public void run() throws Exception {
        Address CODE_LO = currentProgram.getAddressFactory().getAddress("0x020000");
        Address CODE_HI = currentProgram.getAddressFactory().getAddress("0x180000");
        mem = currentProgram.getMemory();
        monitor = getMonitor();
        dec = new DecompInterface();
        dec.openProgram(currentProgram);

        // EWS authorization RAM globals (resolved: block 0xd0000000)
        String[] names = {"0x000319f","0x00031a0","0x0003586","0x0003587","0x000356b",
                          "0x000090e","0x0000933","0x0000929","0x000092c","0x0000906",
                          "0x0002432","0x00031a0","0x000359e","0x00035ce","0x00035ae"};
        long[] ews = new long[names.length];
        for (int i=0;i<names.length;i++) ews[i] = 0xd0000000L | Long.parseLong(names[i].substring(2),16);

        out.append("=== code refs to EWS RAM globals ===\n");
        Set<Long> consumers = new LinkedHashSet<>();
        Map<Long,List<Long>> refByGlobal = new HashMap<>();
        for (int i=0;i<ews.length;i++) {
            Address ga = currentProgram.getAddressFactory().getAddress(Long.toHexString(ews[i]));
            Reference[] refs = getReferencesTo(ga);
            List<Long> fns = new ArrayList<>();
            for (Reference r : refs) {
                if (r.getFromAddress().compareTo(CODE_LO) >= 0 && r.getFromAddress().compareTo(CODE_HI) < 0) {
                    Function fn = getFunctionAt(r.getFromAddress());
                    if (fn != null) {
                        if (!fns.contains(fn.getEntryPoint().getOffset())) fns.add(fn.getEntryPoint().getOffset());
                        consumers.add(fn.getEntryPoint().getOffset());
                    }
                }
            }
            refByGlobal.put(ews[i], fns);
            out.append("  0x" + Long.toHexString(ews[i]) + "  refs=" + refs.length + "  fns=" +
                fns.stream().map(a->"0x"+Long.toHexString(a)).collect(java.util.stream.Collectors.joining(",")) + "\n");
        }

        out.append("\n=== decompiled consumer functions (fuel gate candidates) ===\n");
        List<Long> order = new ArrayList<>(consumers);
        Collections.sort(order);
        int done=0;
        for (long faddr : order) {
            Function f = getFunctionAt(currentProgram.getAddressFactory().getAddress(Long.toHexString(faddr)));
            if (f==null) continue;
            long sz = f.getBody().getMaxAddress().getOffset()-f.getBody().getMinAddress().getOffset();
            if (faddr==0x0008def6){ out.append("skip state machine 0x8def6\n"); continue; }
            if (sz>9000){ out.append("skip "+f.getName()+" size="+sz+"\n"); continue; }
            done++;
            if (done>60){ out.append("stop at 60\n"); break; }
            out.append("\n########## "+f.getName()+" [0x"+Long.toHexString(faddr)+"] size="+sz+" ##########\n");
            try {
                DecompileResults r = dec.decompileFunction(f, 120, monitor);
                if (r.decompileCompleted()) out.append(r.getDecompiledFunction().getC());
                else out.append("decompile failed: "+r.getErrorMessage()+"\n");
            } catch (Exception ex){ out.append("exc: "+ex+"\n"); }
        }

        java.io.File f = new java.io.File("/home/brandon/Documents/EDC17CP09/ghidra_ews_fuelgate.txt");
        try (java.io.PrintWriter w = new java.io.PrintWriter(f)) { w.print(out); }
        println("wrote "+f+" ("+out.length()+" chars)");
    }
}
