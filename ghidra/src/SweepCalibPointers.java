// Sweeps TriCore code region for LEA/MOVH+ADD pairs resolving to calibration region.
// Cross-references against known maps, validates data structures, decompiles callers.
// @category EDC17CP09
// @author Hermes

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.util.*;

public class SweepCalibPointers extends GhidraScript {

    static final long CODE_START = 0x020000L;
    static final long CODE_END   = 0x180000L;
    static final long CALIB_START = 0x040000L;
    static final long CALIB_END   = 0x200000L;

    @Override
    protected void run() throws Exception {
        Program program = currentProgram;
        Listing listing = program.getListing();
        Memory memory = program.getMemory();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

        // Load known map addresses from scan_mpc.json
        Set<Long> knownAddresses = new HashSet<>();
        try {
            String jsonPath = "/home/brandon/Documents/EDC17CP09/scan_mpc.json";
            BufferedReader br = new BufferedReader(new FileReader(jsonPath));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            br.close();
            // Simple parse: find "address": 0xNNN patterns
            String json = sb.toString();
            int idx = 0;
            while ((idx = json.indexOf("\"address\"", idx)) >= 0) {
                int colon = json.indexOf(':', idx);
                if (colon < 0) break;
                int start = colon + 1;
                while (start < json.length() && !Character.isDigit(json.charAt(start)) && json.charAt(start) != '0') start++;
                int end = start;
                while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == 'x' || json.charAt(end) == 'X' || (json.charAt(end) >= 'a' && json.charAt(end) <= 'f') || (json.charAt(end) >= 'A' && json.charAt(end) <= 'F'))) end++;
                String numStr = json.substring(start, end).trim();
                try {
                    long addr;
                    if (numStr.startsWith("0x") || numStr.startsWith("0X")) {
                        addr = Long.parseLong(numStr.substring(2), 16);
                    } else {
                        addr = Long.parseLong(numStr);
                    }
                    knownAddresses.add(addr);
                } catch (NumberFormatException e) {}
                idx = end;
            }
        } catch (Exception e) {
            println("Warning: Could not load scan_mpc.json: " + e.getMessage());
        }
        println("Known addresses from scan_mpc.json: " + knownAddresses.size());

        // Sweep instructions in code region
        Address codeStart = space.getAddress(CODE_START);
        Address codeEnd = space.getAddress(CODE_END);

        InstructionIterator iter = listing.getInstructions(codeStart, true);
        Map<Long, List<Long>> calibRefs = new HashMap<>(); // calib_addr -> [code_refs]

        int instrCount = 0;
        while (iter.hasNext() && !monitor.isCancelled()) {
            Instruction instr = iter.next();
            Address instrAddr = instr.getAddress();
            long addr = instrAddr.getOffset();
            if (addr >= CODE_END) break;
            instrCount++;

            // Check each operand for references into calibration region
            for (int i = 0; i < instr.getNumOperands(); i++) {
                RefType refType = instr.getOperandRefType(i);
                Address[] refs = null;
                try {
                    refs = instr.getOpObjects(i) instanceof Address[] ? (Address[]) instr.getOpObjects(i) : null;
                } catch (Exception e) {}

                // Try scalar operands
                Object[] ops = instr.getOpObjects(i);
                for (Object op : ops) {
                    if (op instanceof Scalar) {
                        long val = ((Scalar) op).getUnsignedValue();
                        if (val >= CALIB_START && val < CALIB_END) {
                            calibRefs.computeIfAbsent(val, k -> new ArrayList<>()).add(addr);
                        }
                    } else if (op instanceof Address) {
                        long val = ((Address) op).getOffset();
                        if (val >= CALIB_START && val < CALIB_END) {
                            calibRefs.computeIfAbsent(val, k -> new ArrayList<>()).add(addr);
                        }
                    }
                }
            }
        }
        println("Instructions scanned: " + instrCount);
        println("Unique calibration addresses referenced: " + calibRefs.size());

        // Filter known maps
        Map<Long, List<Long>> newRefs = new HashMap<>();
        for (Map.Entry<Long, List<Long>> entry : calibRefs.entrySet()) {
            if (!knownAddresses.contains(entry.getKey())) {
                newRefs.put(entry.getKey(), entry.getValue());
            }
        }
        println("New (not in scan_mpc.json): " + newRefs.size());

        // Structural heuristic validation for each discovered pointer
        List<Map<String, Object>> results = new ArrayList<>();
        int validated = 0;

        for (Map.Entry<Long, List<Long>> entry : newRefs.entrySet()) {
            long calibAddr = entry.getKey();
            List<Long> codeRefs = entry.getValue();

            // Read data at calibration address
            byte[] data = new byte[256];
            try {
                memory.getBytes(space.getAddress(calibAddr), data);
            } catch (Exception e) {
                continue;
            }

            // Classify structure type
            String structType = classifyStructure(data);
            if (structType.equals("UNKNOWN")) continue;

            // Determine inferred dimensions
            String dimensions = inferDimensions(structType, data);

            // Find calling function and decompile
            String decompiledContext = "";
            for (long codeRef : codeRefs) {
                Function func = listing.getFunctionContaining(space.getAddress(codeRef));
                if (func != null) {
                    decompiledContext = decompileFunction(func);
                    break;
                }
            }

            // Categorize by context
            String category = categorizeByContext(decompiledContext, structType);

            Map<String, Object> result = new HashMap<>();
            result.put("calib_addr", "0x" + Long.toHexString(calibAddr));
            result.put("code_refs", codeRefs.stream().map(a -> "0x" + Long.toHexString(a)).collect(java.util.stream.Collectors.toList()));
            result.put("struct_type", structType);
            result.put("dimensions", dimensions);
            result.put("category", category);
            result.put("decompiled_context", decompiledContext.length() > 500 ? decompiledContext.substring(0, 500) + "..." : decompiledContext);
            result.put("first_bytes_hex", bytesToHex(data, 32));

            results.add(result);
            validated++;

            if (validated >= 2000) {
                println("Hit 2000 validated limit, stopping.");
                break;
            }
        }

        println("Validated new maps: " + validated);

        // Write results to JSON
        String outputPath = "/home/brandon/Documents/EDC17CP09/new_maps_discovered.json";
        FileWriter fw = new FileWriter(outputPath);
        // Manual JSON construction for compatibility
        fw.write("[\n");
        for (int i = 0; i < results.size(); i++) {
            Map<String, Object> r = results.get(i);
            fw.write("  {\n");
            fw.write("    \"calib_addr\": \"" + r.get("calib_addr") + "\",\n");
            fw.write("    \"code_refs\": " + r.get("code_refs") + ",\n");
            fw.write("    \"struct_type\": \"" + r.get("struct_type") + "\",\n");
            fw.write("    \"dimensions\": \"" + r.get("dimensions") + "\",\n");
            fw.write("    \"category\": \"" + r.get("category") + "\",\n");
            fw.write("    \"first_bytes_hex\": \"" + r.get("first_bytes_hex") + "\",\n");
            String ctx = ((String) r.get("decompiled_context")).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
            fw.write("    \"decompiled_context\": \"" + ctx + "\"\n");
            fw.write("  }" + (i < results.size() - 1 ? "," : "") + "\n");
        }
        fw.write("]\n");
        fw.close();
        println("Results written to: " + outputPath);
    }

    String classifyStructure(byte[] data) {
        // Check for all zeros or all FF
        boolean allZero = true, allFF = true;
        for (int i = 0; i < 32; i++) {
            if (data[i] != 0) allZero = false;
            if (data[i] != (byte) 0xFF) allFF = false;
        }
        if (allZero || allFF) return "EMPTY";

        // Check for 1D scalar (single byte or word)
        // If bytes 2-31 are all zero or constant, likely a scalar
        boolean restConstant = true;
        for (int i = 2; i < 32; i++) {
            if (data[i] != data[2]) { restConstant = false; break; }
        }
        if (restConstant && (data[0] != 0 || data[1] != 0)) return "SCALAR_1D";

        // Check for DTC mask array (sequential 2-byte values, many zeros mixed in)
        int zeroCount = 0;
        for (int i = 0; i < 32; i += 2) {
            if (data[i] == 0 && data[i+1] == 0) zeroCount++;
        }
        if (zeroCount >= 8 && zeroCount <= 14) return "DTC_MASK";

        // Check for 2D map header (axis count bytes followed by data)
        int axisCount = data[0] & 0xFF;
        if (axisCount >= 2 && axisCount <= 32) {
            // Check if next bytes look like axis values (monotonically increasing)
            boolean monotonic = true;
            for (int i = 1; i < Math.min(axisCount, 8); i++) {
                if ((data[i] & 0xFF) <= (data[i-1] & 0xFF) && data[i] != 0) {
                    monotonic = false;
                    break;
                }
            }
            if (monotonic) return "2D_MAP_WITH_AXIS";
        }

        // Check for curve (small axis count + values)
        if (axisCount >= 2 && axisCount <= 16) return "CURVE";

        return "UNKNOWN";
    }

    String inferDimensions(String structType, byte[] data) {
        switch (structType) {
            case "SCALAR_1D":
                return "1x1 (2 bytes)";
            case "DTC_MASK":
                return "N x 2 bytes (mask array)";
            case "2D_MAP_WITH_AXIS":
                int rows = data[0] & 0xFF;
                int cols = data[rows + 1] & 0xFF;
                if (cols < 2 || cols > 32) cols = 1;
                return rows + " x " + cols;
            case "CURVE":
                int pts = data[0] & 0xFF;
                return pts + " x 1 (curve)";
            default:
                return "unknown";
        }
    }

    String decompileFunction(Function func) {
        if (func == null) return "";
        try {
            DecompileResults results;
            DecompileInterface decompiler = state.getTool().getService(DecompileInterface.class);
            if (decompiler == null) return "[decompiler unavailable]";
            results = decompiler.decompileFunction(func, 60, monitor);
            if (results != null && results.decompileCompleted()) {
                return results.getDecompiledFunction().getC();
            }
        } catch (Exception e) {
            return "[decompile error: " + e.getMessage() + "]";
        }
        return "[no decompiled output]";
    }

    String categorizeByContext(String context, String structType) {
        String ctxLower = context.toLowerCase();
        if (ctxLower.contains("ews") || ctxLower.contains("wegfahr") || ctxLower.contains("immo")) return "EWS/Immobilizer";
        if (ctxLower.contains("dfes") || ctxLower.contains("dtc") || ctxLower.contains("error")) return "DTC/Error";
        if (ctxLower.contains("torque") || ctxLower.contains("drehmoment") || ctxLower.contains("begrenzung")) return "Torque/Limiter";
        if (ctxLower.contains("rail") || ctxLower.contains("druck") || ctxLower.contains("pressure")) return "RailPressure";
        if (ctxLower.contains("boost") || ctxLower.contains("lade") || ctxLower.contains("turbo")) return "Boost/VNT";
        if (ctxLower.contains("inject") || ctxLower.contains("einspritz") || ctxLower.contains("injcrv")) return "Injection";
        if (ctxLower.contains("egr") || ctxLower.contains("dpf") || ctxLower.contains("regener")) return "Emissions";
        if (ctxLower.contains("accped") || ctxLower.contains("fahrer") || ctxLower.contains("pedal")) return "DriversWish";
        if (structType.equals("DTC_MASK")) return "DTC/Error";
        if (structType.equals("SCALAR_1D")) return "Scalar/Config";
        return "Uncategorized";
    }

    String bytesToHex(byte[] data, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(len, data.length); i++) {
            sb.append(String.format("%02x", data[i] & 0xFF));
            if (i < Math.min(len, data.length) - 1) sb.append(" ");
        }
        return sb.toString();
    }
}
