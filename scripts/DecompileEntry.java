// Decompile entry and surrounding functions
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;

public class DecompileEntry extends GhidraScript {
    public void run() throws Exception {
        File outFile = new File("/tmp/entry_decompiled.txt");
        PrintWriter writer = new PrintWriter(new FileWriter(outFile));
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        
        // Get entry point
        SymbolTable st = currentProgram.getSymbolTable();
        Address entryAddr = null;
        SymbolIterator syms = st.getExternalEntryPointIterator();
        while (syms.hasNext()) {
            Symbol sym = syms.next();
            entryAddr = sym.getAddress();
            writer.println("Entry Symbol: " + sym.getName() + " @ " + entryAddr);
        }
        if (entryAddr == null) {
            entryAddr = currentProgram.getMinAddress();
        }
        
        FunctionManager fm = currentProgram.getFunctionManager();
        Function entryFunc = fm.getFunctionAt(entryAddr);
        if (entryFunc != null) {
            writer.println("\n### Entry Function: " + entryFunc.getName() + " @ " + entryAddr);
            DecompileResults res = ifc.decompileFunction(entryFunc, 60, monitor);
            if (res != null && res.decompileCompleted()) {
                writer.println(res.getDecompiledFunction().getC());
            } else {
                writer.println("Decompile failed");
            }
        } else {
            writer.println("No function at entry: " + entryAddr);
        }
        
        // Try to find functions containing interesting names
        String[] keywords = {"net", "device", "enable", "disable", "stop", "support", "usb", "firewall", "process", "limit", "sniffer", "driver"};
        FunctionIterator funcs = fm.getFunctions(true);
        int count = 0;
        while (funcs.hasNext()) {
            Function func = funcs.next();
            String name = func.getName().toLowerCase();
            if (name.startsWith("fun_") || name.startsWith("thunk") || name.startsWith("unwind")) continue;
            boolean match = false;
            for (String kw : keywords) {
                if (name.contains(kw)) { match = true; break; }
            }
            if (match && count < 25) {
                writer.println("\n### Function: " + func.getName() + " @ " + func.getEntryPoint());
                DecompileResults res = ifc.decompileFunction(func, 45, monitor);
                if (res != null && res.decompileCompleted()) {
                    writer.println(res.getDecompiledFunction().getC());
                }
                count++;
            }
        }
        writer.println("\nTotal matched funcs: " + count);
        writer.close();
        ifc.dispose();
        println("Exported: " + outFile.getAbsolutePath());
    }
}