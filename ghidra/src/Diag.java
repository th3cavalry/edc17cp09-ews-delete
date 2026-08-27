// Ghidra postScript: diagnostic — how does Ghidra format TriCore instructions?
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.util.*;

public class Diag extends GhidraScript {
    public void run() throws Exception {
        StringBuilder out = new StringBuilder();
        out.append("total functions: " + currentProgram.getFunctionManager().getFunctionCount() + "\n");

        // known-good code sites from capstone sweep:
        // 0x8def8: ld.bu d0,[a4]#0x41 ; 0x113e0c: ld.w d0,[a4]#0x40 ; 0x8df1c: jlt.u ...
        Address[] sites = {
            currentProgram.getAddressFactory().getAddress("0x8def8"),
            currentProgram.getAddressFactory().getAddress("0x113e0c"),
            currentProgram.getAddressFactory().getAddress("0x8df1c"),
            currentProgram.getAddressFactory().getAddress("0xb19cc"),
            currentProgram.getAddressFactory().getAddress("0x9bdf4"),
        };
        for (Address a : sites) {
            out.append("\n--- around " + a + " ---\n");
            InstructionIterator it = currentProgram.getListing().getInstructions(a, true);
            int n=0;
            while (it.hasNext() && n<10) {
                Instruction ins = it.next();
                out.append(String.format("  %08x:  %s\n", ins.getAddress().getOffset(), ins));
                n++;
            }
        }
        // sample a few random functions
        out.append("\n--- sample functions ---\n");
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        int c=0;
        while (fit.hasNext() && c<5) {
            Function f = fit.next();
            out.append("fn " + f.getName() + " ["+f.getEntryPoint()+","+f.getBody().getMaxAddress()+"] size="+(f.getBody().getMaxAddress().getOffset()-f.getBody().getMinAddress().getOffset())+"\n");
            c++;
        }
        java.io.File f = new java.io.File("/home/brandon/Documents/EDC17CP09/ghidra_diag.txt");
        try (java.io.PrintWriter w = new java.io.PrintWriter(f)) { w.print(out); }
        println("wrote diag");
    }
}
