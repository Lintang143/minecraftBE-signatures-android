import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import java.io.FileWriter;
import java.util.*;

public class ExtractSignatures extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Ambil path output JSON dari argumen script (default: /workspace/signatures.json)
        String[] args = getScriptArgs();
        String outputPath = (args.length > 0) ? args[0] : "signatures.json";

        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symbolTable.getAllSymbols(true);
        Memory memory = currentProgram.getMemory();

        FileWriter writer = new FileWriter(outputPath);
        writer.write("[\n");

        boolean first = true;
        while (symbols.hasNext() && !monitor.isCancelled()) {
            Symbol sym = symbols.next();
            String name = sym.getName(true);

            // Filter simbol penting: RTTI/Vtable (_ZTS, _ZTV, _ZTI) dan Fungsi C++
            if (name.startsWith("_Z") || sym.getSymbolType() == SymbolType.FUNCTION) {
                long address = sym.getAddress().getUnscaledAddress();
                
                // Ambil 16-byte pattern pertama sebagai signature awal
                String bytePattern = getBytePattern(memory, sym.getAddress(), 16);

                if (!first) {
                    writer.write(",\n");
                }
                first = false;

                writer.write(String.format(
                    "  {\n" +
                    "    \"name\": \"%s\",\n" +
                    "    \"address\": \"0x%X\",\n" +
                    "    \"type\": \"%s\",\n" +
                    "    \"pattern\": \"%s\"\n" +
                    "  }",
                    escapeJson(name),
                    address,
                    sym.getSymbolType().toString(),
                    bytePattern
                ));
            }
        }

        writer.write("\n]\n");
        writer.close();
        println("[+] Successful export signatures to: " + outputPath);
    }

    private String getBytePattern(Memory memory, Address addr, int length) {
        StringBuilder sb = new StringBuilder();
        try {
            byte[] bytes = new byte[length];
            int bytesRead = memory.getBytes(addr, bytes);
            for (int i = 0; i < bytesRead; i++) {
                sb.append(String.format("%02X ", bytes[i]));
            }
        } catch (MemoryAccessException e) {
            return "N/A";
        }
        return sb.toString().trim();
    }

    private String escapeJson(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "");
    }
}
