// Export DeviceControl info
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class DeviceCtrlExport extends GhidraScript {
    public void run() throws Exception {
        File outputFile = new File("/tmp/devicecontrol_report.txt");
        PrintWriter writer = new PrintWriter(new FileWriter(outputFile));
        
        writer.println("=== Program: " + currentProgram.getName() + " ===");
        writer.println();
        
        writer.println("=== External Libraries (Imports) ===");
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator symbols = st.getAllSymbols(true);
        java.util.Map<String, List<String>> imports = new java.util.TreeMap<>();
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            if (sym.isExternal()) {
                String lib = sym.getParentNamespace().getName();
                imports.computeIfAbsent(lib, k -> new ArrayList<>()).add(sym.getName());
            }
        }
        for (String lib : imports.keySet()) {
            writer.println(lib + ": " + imports.get(lib).size() + " funcs");
        }
        writer.println();
        
        writer.println("=== Interesting Strings ===");
        Listing listing = currentProgram.getListing();
        DataIterator di = listing.getDefinedData(true);
        int count = 0;
        while (di.hasNext() && count < 300) {
            Data d = di.next();
            if (d.hasStringValue()) {
                String val = d.getDefaultValueRepresentation();
                String lower = val.toLowerCase();
                if (lower.contains("device") || lower.contains("network") || lower.contains("usb") ||
                    lower.contains("easyusb") || lower.contains("enable") || lower.contains("disable") ||
                    lower.contains("stop") || lower.contains("support") || lower.contains("firewall") ||
                    lower.contains("process") || lower.contains("driver") || lower.contains("\\\\") ||
                    lower.contains("ioctl") || lower.contains("control")) {
                    writer.println("  " + val);
                    count++;
                }
            }
        }
        writer.println();
        
        writer.println("=== Named Functions ===");
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator funcs = fm.getFunctions(true);
        int fcount = 0;
        while (funcs.hasNext()) {
            Function func = funcs.next();
            String name = func.getName();
            if (!name.startsWith("FUN_") && !name.startsWith("thunk_") && !name.equals("entry")) {
                writer.println("  " + func.getEntryPoint() + " " + name);
                fcount++;
            }
        }
        writer.println("Total named funcs: " + fcount);
        writer.println("Total funcs: " + fm.getFunctionCount());
        
        writer.close();
        println("Exported: " + outputFile.getAbsolutePath());
    }
}