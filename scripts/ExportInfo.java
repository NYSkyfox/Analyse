// Export program information
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;

public class ExportInfo extends GhidraScript {
    public void run() throws Exception {
        File outputFile = new File("/tmp/analysis_report.txt");
        PrintWriter writer = new PrintWriter(new FileWriter(outputFile));
        
        writer.println("=== Program: " + currentProgram.getName() + " ===");
        writer.println();
        
        // Function count
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int funcCount = 0;
        writer.println("=== Functions ===");
        while (functions.hasNext() && funcCount < 100) {
            Function func = functions.next();
            writer.println(func.getName() + " @ " + func.getEntryPoint());
            funcCount++;
        }
        writer.println("Total functions: " + currentProgram.getFunctionManager().getFunctionCount());
        writer.println();
        
        // Strings
        writer.println("=== Defined Strings (first 50) ===");
        Listing listing = currentProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);
        int strCount = 0;
        while (dataIter.hasNext() && strCount < 50) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                writer.println(data.getDefaultValueRepresentation());
                strCount++;
            }
        }
        writer.println();
        
        // Imports
        writer.println("=== External Libraries ===");
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator extSyms = symTable.getExternalSymbols();
        java.util.Set<String> libs = new java.util.HashSet<>();
        while (extSyms.hasNext()) {
            Symbol sym = extSyms.next();
            String libName = sym.getParentNamespace().getName();
            libs.add(libName);
        }
        for (String lib : libs) {
            writer.println(lib);
        }
        
        writer.close();
        println("Report exported to: " + outputFile.getAbsolutePath());
    }
}
