// Ghidra postScript: EWS gate hunt — correct Ghidra formatting ([a4]0x40, no #)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.TaskMonitor;
import java.util.*;

public class EwsHunt extends GhidraScript {
    Memory mem;
    TaskMonitor monitor;

    public void run() throws Exception {
        Address CODE_LO = currentProgram.getAddressFactory().getAddress("0x020000");
        Address CODE_HI = currentProgram.getAddressFactory().getAddress("0x180000");
        mem = currentProgram.getMemory();
        monitor = getMonitor();
        StringBuilder out = new StringBuilder();

        // 1) byte-pattern search: config LE32 refs
        out.append("=== LE32 refs ===\n");
        int[][] pats = {
            {0x34,0x00,0x18,0x00},
            {0x74,0x00,0x18,0x00},
            {0x99,0x00,0x18,0x00},
            {0x93,0x00,0x18,0x00},
            {0xb4,0x35,0x0d,0x00},
            {0x80,0x71,0x0d,0x00},
            {0x00,0x18,0x00,0x00},
        };
        String[] names = {"0x180034", "0x180074", "0x180099", "0x180093", "0x0d35b4", "0x0d7180", "0x180000"};
        for (int p=0;p<pats.length;p++) {
            byte[] pat = new byte[pats[p].length];
            for (int i=0;i<pat.length;i++) pat[i]=(byte)pats[p][i];
            int n=0;
            Address a = CODE_LO;
            List<Address> hits = new ArrayList<>();
            while (true) {
                a = mem.findBytes(a, pat, null, true, monitor);
                if (a == null || a.compareTo(CODE_HI)>=0) break;
                hits.add(a);
                n++;
                a = a.add(1);
                if (n>3000) break;
            }
            out.append("--- " + names[p] + " (n=" + n + ") ---\n");
            for (Address h : hits) {
                if (hits.indexOf(h) < 30) {
                    Function fn = getFunctionAt(h);
                    out.append(String.format("  %08x  fn=%s\n", h.getOffset(), fn!=null?fn.getName():"-"));
                }
            }
        }

        // 2) functions containing config-indexed accesses [a4]0x40/41/42 (EWS key) or [a4]0xXX for 0x30-0x60
        out.append("\n=== functions with [a4]0x3x-0x6x indexed config accesses ===\n");
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        List<Function> matches = new ArrayList<>();
        int total=0;
        while (it.hasNext()) {
            Function f = it.next();
            Address s = f.getBody().getMinAddress();
            Address e = f.getBody().getMaxAddress();
            if (s.compareTo(CODE_LO)<0 || e.compareTo(CODE_HI)>=0) continue;
            InstructionIterator iit = currentProgram.getListing().getInstructions(f.getBody(), true);
            StringBuilder sb = new StringBuilder();
            while (iit.hasNext()) {
                Instruction ins = iit.next();
                sb.append(ins.toString()).append('\n');
            }
            String body = sb.toString();
            if (body.contains("[a4]0x40") || body.contains("[a4]0x41") || body.contains("[a4]0x42") ||
                body.contains("[a4]0x43") || body.contains("[a4]0x44") || body.contains("[a4]0x36")) {
                matches.add(f);
                total++;
            }
        }
        out.append("[matched " + total + " functions]\n");

        // 3) for each matched function: full disasm + XREFs (callers/callees)
        for (Function f : matches) {
            out.append("\n##### " + f.getName() + " ["+f.getEntryPoint()+","+f.getBody().getMaxAddress()+"]\n");
            // callers
            Reference[] callers = getReferencesTo(f.getEntryPoint());
            out.append("  callers ("+callers.length+"):");
            for (Reference r : callers) out.append(String.format(" %08x", r.getFromAddress().getOffset()));
            out.append("\n");
            // callees
            Set<String> callees = new LinkedHashSet<>();
            InstructionIterator iit = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (iit.hasNext()) {
                Instruction ins = iit.next();
                for (Reference r : getReferencesFrom(ins.getAddress())) {
                    if (r.getReferenceType().isCall()) {
                        Function cf = getFunctionAt(r.getToAddress());
                        callees.add(String.format("%08x%s", r.getToAddress().getOffset(),
                            cf!=null? " "+cf.getName() : ""));
                    }
                }
            }
            out.append("  callees: " + callees + "\n");
            int n=0;
            iit = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (iit.hasNext() && n<1200) {
                Instruction ins = iit.next();
                out.append(String.format("  %08x:  %s\n", ins.getAddress().getOffset(), ins));
                n++;
            }
        }

        // 4) decompile the top candidates (small ones likely EWS handlers)
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        out.append("\n=== DECOMPILATION of matched functions ===\n");
        for (Function f : matches) {
            if (f.getBody().getMaxAddress().getOffset() - f.getBody().getMinAddress().getOffset() > 4000) continue;
            try {
                DecompileResults r = dec.decompileFunction(f, 90, monitor);
                out.append("\n########## DECOMPILED " + f.getName() + " ##########\n");
                if (r.decompileCompleted()) {
                    out.append(r.getDecompiledFunction().getC());
                } else {
                    out.append("decompile failed: " + r.getErrorMessage());
                }
            } catch (Exception ex) {
                out.append("decompile exception: " + ex + "\n");
            }
        }

        java.io.File f = new java.io.File("/home/brandon/Documents/EDC17CP09/ghidra_ews_hunt.txt");
        try (java.io.PrintWriter w = new java.io.PrintWriter(f)) { w.print(out); }
        println("wrote " + f + " (" + out.length() + " chars)");
    }
}
