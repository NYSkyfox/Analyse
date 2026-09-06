// FindCallers.java - 查找指定函数的所有调用者并反编译调用者（精简）
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class FindCallers extends GhidraScript {
    public void run() throws Exception {
        String prog = currentProgram.getName();
        File out = new File("/tmp/callers_" + prog + ".txt");
        PrintWriter pw = new PrintWriter(out, "UTF-8");
        pw.println("==== CALLERS " + prog + " ====");
        String[] targets = getScriptArgs();
        FunctionManager fm = currentProgram.getFunctionManager();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        for (String t : targets) {
            Address a = currentProgram.getAddressFactory().getAddress(t);
            Function target = fm.getFunctionContaining(a);
            if (target == null) { pw.println(t + " => NO-FUNC"); continue; }
            pw.println("\n##### TARGET: " + target.getName() + " @ " + target.getEntryPoint());
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(target.getEntryPoint());
            int n = 0;
            while (refs.hasNext()) {
                Reference r = refs.next();
                Function caller = fm.getFunctionContaining(r.getFromAddress());
                if (caller == null) continue;
                pw.println("\n### CALLER: " + caller.getName() + " @ " + caller.getEntryPoint() + " (ref@" + r.getFromAddress() + ")");
                DecompileResults res = decomp.decompileFunction(caller, 60, monitor);
                if (res.decompileCompleted()) {
                    String code = res.getDecompiledFunction().getC();
                    String[] lines = code.split("\n");
                    for (int i = 0; i < Math.min(lines.length, 100); i++) pw.println("  " + lines[i]);
                } else {
                    pw.println("  DECOMPILE-FAILED");
                }
                n++;
                if (n >= 8) break;
            }
            pw.println("\n[total callers shown: " + n + "]");
            pw.flush();
        }
        pw.close();
        println("WROTE " + out.getAbsolutePath());
    }
}