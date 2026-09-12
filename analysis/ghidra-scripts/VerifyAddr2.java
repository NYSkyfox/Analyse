// VerifyAddr2.java - 验证关键函数地址并反编译，输出到 /tmp
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class VerifyAddr2 extends GhidraScript {
    public void run() throws Exception {
        String prog = currentProgram.getName();
        File out = new File("/tmp/verify_" + prog + ".txt");
        PrintWriter pw = new PrintWriter(out, "UTF-8");
        pw.println("==== VERIFYADDR " + prog + " ====");
        FunctionManager fm = currentProgram.getFunctionManager();
        AddressFactory af = currentProgram.getAddressFactory();
        String[] addrs = getScriptArgs();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        for (String a : addrs) {
            try {
                Address addr = af.getAddress(a);
                Function f = fm.getFunctionContaining(addr);
                if (f == null) { pw.println(a + " => NO-FUNC"); continue; }
                pw.println("\n### " + a + " => " + f.getName() + " @ " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses());
                DecompileResults res = decomp.decompileFunction(f, 60, monitor);
                if (res.decompileCompleted()) {
                    pw.println(res.getDecompiledFunction().getC());
                } else {
                    pw.println("  DECOMPILE-FAILED");
                }
                pw.flush();
            } catch (Exception e) {
                pw.println(a + " => ERROR " + e.getMessage());
            }
        }
        pw.close();
        println("WROTE " + out.getAbsolutePath());
    }
}
