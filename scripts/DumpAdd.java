import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

public class DumpAdd extends GhidraScript {
    @Override
    public void run() throws Exception {
        Function f = getGlobalFunctions("add").isEmpty() ? null : getGlobalFunctions("add").get(0);
        if (f == null) {
            println("FUNCTION add NOT FOUND");
            return;
        }
        println("Found function: " + f.getName() + " at " + f.getEntryPoint());
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        DecompileResults res = decomp.decompileFunction(f, 30, new ConsoleTaskMonitor());
        println("---- DECOMPILED ----");
        println(res.getDecompiledFunction().getC());
        println("---- END ----");
    }
}
