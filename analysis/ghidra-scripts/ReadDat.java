// ReadDat.java - 读取 Teacher.exe 中数据地址内容
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;

public class ReadDat extends GhidraScript {
    public void run() throws Exception {
        String[] addrs = getScriptArgs();
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        println("==== READDAT " + currentProgram.getName() + " ====");
        for (String a : addrs) {
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(a);
                // 尝试读 ASCII 字符串（最长64）
                byte[] b = new byte[96];
                int n = mem.getBytes(addr, b);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < n; i++) {
                    if (b[i] == 0) break;
                    if (b[i] >= 32 && b[i] < 127) sb.append((char) b[i]);
                    else { sb.append('.'); }
                }
                println(a + " => ASCII: " + sb.toString());
                // 尝试读宽字符
                StringBuilder wsb = new StringBuilder();
                for (int i = 0; i + 1 < n; i += 2) {
                    char c = (char)((b[i+1] << 8) | b[i]);
                    if (c == 0) break;
                    if (c >= 32 && c < 127) wsb.append(c);
                    else { wsb.append('.'); }
                }
                println(a + " => WIDE:  " + wsb.toString());
            } catch (Exception e) {
                println(a + " => ERROR " + e.getMessage());
            }
        }
    }
}
