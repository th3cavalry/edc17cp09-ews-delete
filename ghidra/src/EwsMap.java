// Ghidra postScript: dump memory blocks + resolve EWS global addresses + find code refs
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import java.util.*;

public class EwsMap extends GhidraScript {
    Memory mem;
    TaskMonitor monitor;
    StringBuilder out = new StringBuilder();

    public void run() throws Exception {
        monitor = getMonitor();
        mem = currentProgram.getMemory();

        out.append("=== MEMORY BLOCKS ===\n");
        for (MemoryBlock b : mem.getBlocks()) {
            out.append(String.format("  %-16s [%08x .. %08x] size=%d readable=%s\n",
                b.getName(), b.getStart().getOffset(), b.getEnd().getOffset(),
                b.getSize(), b.isRead()));
        }

        // resolve EWS global symbols by name suffix
        String[] suffixes = {"319f","31a0","3586","3587","356b","356c","90e","933","929",
            "932","917","915","92d","92c","923","90d","906","359e","35ce","35ae","35be"};
        out.append("\n=== EWS global symbols (name -> address) ===\n");
        SymbolTable symTab = currentProgram.getSymbolTable();
        SymbolIterator sit = symTab.getAllSymbols(true);
        Map<String, List<Long>> bySuffix = new HashMap<>();
        while (sit.hasNext()) {
            Symbol s = sit.next();
            String n = s.getName();
            // strip prefixes DAT_, _DAT_, UNK_, &
            String core = n.replaceFirst("^[_\\&]?DAT_?","").replaceFirst("^UNK_?","");
            for (String suf : suffixes) {
                if (core.endsWith(suf) && core.length() <= suf.length()+2) {
                    bySuffix.computeIfAbsent(suf, k->new ArrayList<>()).add(s.getAddress().getOffset());
                }
            }
        }
        for (String suf : suffixes) {
            List<Long> addrs = bySuffix.getOrDefault(suf, new ArrayList<>());
            out.append("  0x"+suf+" -> " + addrs.stream().map(a->"0x"+Long.toHexString(a)).collect(java.util.stream.Collectors.toList()) + "\n");
        }

        java.io.File f = new java.io.File("/home/brandon/Documents/EDC17CP09/ghidra_ews_map.txt");
        try (java.io.PrintWriter w = new java.io.PrintWriter(f)) { w.print(out); }
        println("wrote " + f + " (" + out.length() + " chars)");
    }
}
