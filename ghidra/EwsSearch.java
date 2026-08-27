// Ghidra postScript: locate EWS/config references in EDC17CP09 TriCore code
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import java.util.*;

public class EwsSearch extends GhidraScript {
    Memory mem;
    TaskMonitor monitor;

    public void run() throws Exception {
        Address CODE_LO = currentProgram.getAddressFactory().getAddress("0x020000");
        Address CODE_HI = currentProgram.getAddressFactory().getAddress("0x180000");
        mem = currentProgram.getMemory();
        monitor = getMonitor();
        StringBuilder out = new StringBuilder();

        // 1) direct LE32 refs in code (findBytes loop)
        int[][] pats = {
            {0x34,0x00,0x18,0x00},
            {0x74,0x00,0x18,0x00},
            {0x99,0x00,0x18,0x00},
            {0x93,0x00,0x18,0x00},
            {0xb4,0x35,0x0d,0x00},
            {0x80,0x71,0x0d,0x00},
            {0x00,0x18,0x00,0x00},
        };
        String[] names = {"0x180034(startup)", "0x180074(EWSkey)", "0x180099(VIN2)",
                          "0x180093(VIN1)", "0x0d35b4(crc1)", "0x0d7180(crc2)", "0x180000(cfgbase)"};
        for (int p=0;p<pats.length;p++) {
            byte[] pat = new byte[pats[p].length];
            for (int i=0;i<pat.length;i++) pat[i]=(byte)pats[p][i];
            out.append("\n--- " + names[p] + " ---\n");
            int n=0;
            Address a = CODE_LO;
            while (true) {
                a = mem.findBytes(a, pat, null, true, monitor);
                if (a == null) break;
                if (a.compareTo(CODE_HI)>=0) break;
                if (n<25) {
                    Function fn = getFunctionAt(a);
                    out.append(String.format("  %08x  fn=%s\n", a.getOffset(), fn!=null?fn.getName():"-"));
                }
                n++;
                a = a.add(1);
                if (n>5000) break;
            }
            out.append("  total: " + n + "\n");
        }

        // 2) data refs to KEY / STARTUP / VIN / cfgbase
        for (String hex : new String[]{"0x180074","0x180034","0x180099","0x180093","0x180000"}) {
            Address ta = currentProgram.getAddressFactory().getAddress(hex);
            Reference[] refs = getReferencesTo(ta);
            out.append("\n=== refs to " + hex + " (" + refs.length + ") ===\n");
            for (Reference r : refs) {
                out.append(String.format("  from %08x (%s)\n", r.getFromAddress().getOffset(),
                    getInstructionAt(r.getFromAddress())));
            }
        }

        // 3) functions loading [a4]#0x40..0x42 (EWS key words)
        out.append("\n=== functions containing [a4]#0x40/41/42 (EWS key region loads) ===\n");
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int count=0;
        while (it.hasNext() && count<60) {
            Function f = it.next();
            Address s = f.getBody().getMinAddress();
            Address e = f.getBody().getMaxAddress();
            if (s.compareTo(CODE_LO)<0) continue;
            if (e.compareTo(CODE_HI)>=0) continue;
            InstructionIterator iit = currentProgram.getListing().getInstructions(f.getBody(), true);
            StringBuilder sb = new StringBuilder();
            while (iit.hasNext()) {
                Instruction ins = iit.next();
                sb.append(ins.toString()).append('\n');
            }
            String body = sb.toString();
            if (body.contains("[a4]#0x40") || body.contains("[a4]#0x41") || body.contains("[a4]#0x42")) {
                out.append("\n##### fn " + f.getName() + "  ["+f.getEntryPoint()+","+e+"] size="+(e.getOffset()-s.getOffset())+"\n");
                int n=0;
                iit = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (iit.hasNext() && n<800) {
                    Instruction ins = iit.next();
                    out.append(String.format("  %08x:  %s\n", ins.getAddress().getOffset(), ins));
                    n++;
                }
                count++;
            }
        }
        out.append("\n[total fns matching [a4]#0x40-0x42: " + count + "]\n");

        // 4) function map of config-parse cluster 0x8de00-0x8f200
        out.append("\n=== functions in 0x8de00-0x8f200 (config parse cluster) ===\n");
        it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            Address s = f.getEntryPoint();
            if (s.compareTo(currentProgram.getAddressFactory().getAddress("0x8de00"))>=0 &&
                s.compareTo(currentProgram.getAddressFactory().getAddress("0x8f200"))<0) {
                out.append("  fn " + f.getName() + " [" + s + "," + f.getBody().getMaxAddress() + "]\n");
            }
        }

        java.io.File f = new java.io.File("/home/brandon/Documents/EDC17CP09/ghidra_ews_search.txt");
        try (java.io.PrintWriter w = new java.io.PrintWriter(f)) { w.print(out); }
        println("wrote " + f + " (" + out.length() + " chars)");
    }
}
