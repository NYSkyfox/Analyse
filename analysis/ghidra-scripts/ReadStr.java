// ReadStr.java - 读取指定地址的字符串
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;

public class ReadStr extends GhidraScript {
    public void run() throws Exception {
        String[] addrs = getScriptArgs();
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        println("==== READSTR " + currentProgram.getName() + " ====");
        for (String a : addrs) {
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(a);
                Data d = listing.getDataAt(addr);
                if (d != null) {
                    Object v = d.getValue();
                    println(a + " => " + (v != null ? v : "(null)"));
                } else {
                    // 手动读 ASCII
                    byte[] b = new byte[64];
                    int n = mem.getBytes(addr, b);
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < n && b[i] != 0; i++) {
                        if (b[i] >= 32 && b[i] < 127) sb.append((char) b[i]);
                        else break;
                    }
                    println(a + " => RAW: " + sb.toString());
                }
            } catch (Exception e) {
                println(a + " => ERROR " + e.getMessage());
            }
        }
    }
}
