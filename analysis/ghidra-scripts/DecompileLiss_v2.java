// Decompile LissHelper main & UDP logic
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import java.io.*;

public class DecompileLiss extends GhidraScript {
    public void run() throws Exception {
        File outFile = new File("/tmp/liss_decompiled.txt");
        PrintWriter writer = new PrintWriter(new FileWriter(outFile));
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        
        String[] keywords = {"udPPPPj", "start-lissNet", "start-lissnet:%s", "support-use-device-control",
            "LISS_SDK_SendMMCStopStrategy", "LISS_SDK_SendMMCMonitorKeywordFilePath", "stop-device-control",
            "stopnetwork", "stopdevice", "stopprocess", "LISSNetInfoSniffer", "WSARecvFrom", "strategy"};
        
        Listing listing = currentProgram.getListing();
        DataIterator di = listing.getDefinedData(true);
        java.util.Set<Address> xrefTargets = new java.util.HashSet<>();
        java.util.Set<String> uniqueStrs = new java.util.HashSet<>();
        while (di.hasNext()) {
            Data d = di.next();
            if (d.hasStringValue()) {
                String val = d.getDefaultValueRepresentation();
                for (String kw : keywords) {
                    if (val.contains(kw)) {
                        uniqueStrs.add(val);
                        xrefTargets.add(d.getAddress());
                        break;
                    }
                }
            }
        }
        
        writer.println("=== Unique Strings (" + uniqueStrs.size() + ") ===");
        for (String s : uniqueStrs) writer.println("  " + s);
        writer.println();
        
        ReferenceManager rm = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();
        java.util.Set<Function> bizFuncs = new java.util.LinkedHashSet<>();
        for (Address addr : xrefTargets) {
            ReferenceIterator refs = rm.getReferencesTo(addr);
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Function func = fm.getFunctionContaining(ref.getFromAddress());
                if (func != null) bizFuncs.add(func);
            }
        }
        
        // Add entry function
        AddressIterator ait = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (ait.hasNext()) {
            Function f = fm.getFunctionContaining(ait.next());
            if (f != null) bizFuncs.add(f);
        }
        
        int decompiled = 0;
        for (Function func : bizFuncs) {
            if (func.getName().startsWith("thunk_")) continue;
            writer.println("\n### Function: " + func.getName() + " @ " + func.getEntryPoint());
            DecompileResults res = ifc.decompileFunction(func, 120, monitor);
            if (res != null && res.decompileCompleted()) {
                writer.println(res.getDecompiledFunction().getC());
                decompiled++;
            } else {
                writer.println("// decompile failed");
            }
        }
        writer.println("\nTotal funcs: " + bizFuncs.size() + ", decompiled: " + decompiled);
        writer.close();
        ifc.dispose();
        println("Exported: /tmp/liss_decompiled.txt funcs=" + bizFuncs.size() + " decompiled=" + decompiled);
    }
}