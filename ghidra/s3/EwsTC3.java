// Ghidra postScript: locate call sites of EWS task FUN_00154e82 (simple, no decompiler)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

public class EwsTC3 extends GhidraScript {
    StringBuilder out = new StringBuilder();
    public void run() throws Exception {
        AddressFactory af = currentProgram.getAddressFactory();
        Address taskEntry = af.getAddress("00154e82");
        out.append("=== callers of EWS task FUN_00154e82 ===\n");
        Reference[] callers = getReferencesTo(taskEntry);
        out.append("total ref sites: " + callers.length + "\n");
        for (Reference r : callers) {
            Function f = getFunctionAt(r.getFromAddress());
            out.append(String.format("  call 0x%08x type=%-12s fn=%s [%s..%s] size=%d%n",
                r.getFromAddress().getOffset(), r.getReferenceType().toString(),
                f!=null?f.getName():"-",
                f!=null?f.getEntryPoint():"-",
                f!=null?f.getBody().getMaxAddress():"-",
                f!=null?(f.getBody().getMaxAddress().getOffset()-f.getBody().getMinAddress().getOffset()):-1));
        }
        java.io.File f = new java.io.File("/home/brandon/Documents/EDC17CP09/ghidra_taskcall_sites.txt");
        try (java.io.PrintWriter w = new java.io.PrintWriter(f)) { w.print(out); }
        println("wrote " + f + " (" + out.length() + " chars)");
    }
}
