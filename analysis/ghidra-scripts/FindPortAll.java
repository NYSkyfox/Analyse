// FindPortAll.java - 扫描 PUSH 0x1f68(8040) / 0x1f6d(8045) / 0x2346(9030) / 0x1e60(7778)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.scalar.Scalar;
import java.io.*;

public class FindPortAll extends GhidraScript {
    public void run() throws Exception {
        String prog = currentProgram.getName();
        File out = new File("/tmp/portall_" + prog + ".txt");
        PrintWriter pw = new PrintWriter(out, "UTF-8");
        pw.println("==== PORTALL " + prog + " ====");
        FunctionManager fm = currentProgram.getFunctionManager();
        int[] targets = {0x1f68, 0x1f6d, 0x2346, 0x1e60};
        for (int t : targets) {
            pw.println("\n--- port 0x" + Integer.toHexString(t) + " = " + t + " ---");
            InstructionIterator ii = currentProgram.getListing().getInstructions(true);
            int cnt = 0;
            while (ii.hasNext() && cnt < 15) {
                Instruction ins = ii.next();
                if (ins.getMnemonicString().equals("PUSH")) {
                    for (int i = 0; i < ins.getNumOperands(); i++) {
                        Object[] objs = ins.getOpObjects(i);
                        for (Object o : objs) {
                            if (o instanceof Scalar) {
                                long val = ((Scalar) o).getValue();
                                if (val == t) {
                                    Function f = fm.getFunctionContaining(ins.getAddress());
                                    pw.println("  @ " + ins.getAddress() + " in " + (f != null ? f.getName() : "?"));
                                    cnt++;
                                }
                            }
                        }
                    }
                }
            }
            if (cnt == 0) pw.println("  not found");
        }
        pw.close();
        println("WROTE " + out.getAbsolutePath());
    }
}
