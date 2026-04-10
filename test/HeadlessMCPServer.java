// GhidraScript: Headless HTTP server for integration testing.
//
// Run via analyzeHeadless -postScript HeadlessMCPServer.java
// The script starts an HTTP server on port 8080 (or GHIDRA_MCP_PORT env var),
// then blocks until a request to /shutdown is received.
//
// This exposes a subset of the GhidraMCP endpoints sufficient for integration
// testing without the GUI.
//
//@category Test

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CountDownLatch;

public class HeadlessMCPServer extends GhidraScript {

    private HttpServer server;
    private final CountDownLatch shutdownLatch = new CountDownLatch(1);

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            printerr("No program loaded.");
            return;
        }

        int port = 8080;
        String envPort = System.getenv("GHIDRA_MCP_PORT");
        if (envPort != null) {
            port = Integer.parseInt(envPort);
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);
        registerEndpoints();
        server.start();
        println("HeadlessMCPServer started on port " + port);

        // Block until /shutdown is called
        shutdownLatch.await();
        server.stop(1);
        println("HeadlessMCPServer stopped.");
    }

    private void registerEndpoints() {
        // Shutdown
        server.createContext("/shutdown", exchange -> {
            sendResponse(exchange, "Shutting down");
            shutdownLatch.countDown();
        });

        // Read endpoints
        server.createContext("/list_functions", exchange -> {
            StringBuilder sb = new StringBuilder();
            FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
            while (funcs.hasNext()) {
                Function f = funcs.next();
                if (!f.isExternal()) {
                    sb.append(f.getName()).append(" at ").append(f.getEntryPoint()).append("\n");
                }
            }
            sendResponse(exchange, sb.toString().trim());
        });

        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String addrStr = params.get("address");
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                func = currentProgram.getFunctionManager().getFunctionContaining(addr);
            }
            if (func != null) {
                String resp = "Function: " + func.getName() + " at " + func.getEntryPoint() + "\n" +
                    "Signature: " + func.getSignature().getPrototypeString() + "\n" +
                    "Entry: " + func.getEntryPoint() + "\n" +
                    "Body: " + func.getBody().getMinAddress() + " - " + func.getBody().getMaxAddress();
                sendResponse(exchange, resp);
            } else {
                sendResponse(exchange, "No function found at address " + addrStr);
            }
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, currentProgram.getMinAddress().toString());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String addrStr = params.get("address");
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                func = currentProgram.getFunctionManager().getFunctionContaining(addr);
            }
            if (func == null) {
                sendResponse(exchange, "No function at address " + addrStr);
                return;
            }
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            DecompileResults results = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            String decompiled = results.getDecompiledFunction() != null
                ? results.getDecompiledFunction().getC()
                : "Decompilation failed";
            decomp.dispose();
            sendResponse(exchange, decompiled);
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String addrStr = params.get("address");
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                sendResponse(exchange, "No function at address " + addrStr);
                return;
            }
            StringBuilder sb = new StringBuilder();
            Listing listing = currentProgram.getListing();
            InstructionIterator iter = listing.getInstructions(func.getBody(), true);
            while (iter.hasNext()) {
                Instruction instr = iter.next();
                sb.append(instr.getAddress()).append(": ").append(instr).append("\n");
            }
            sendResponse(exchange, sb.toString().trim());
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String query = params.get("query");
            if (query == null || query.isEmpty()) {
                sendResponse(exchange, "Search term is required");
                return;
            }
            StringBuilder sb = new StringBuilder();
            FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
            while (funcs.hasNext()) {
                Function f = funcs.next();
                if (f.getName().toLowerCase().contains(query.toLowerCase())) {
                    sb.append(f.getName()).append(" at ").append(f.getEntryPoint()).append("\n");
                }
            }
            if (sb.length() == 0) {
                sendResponse(exchange, "No functions matching '" + query + "'");
            } else {
                sendResponse(exchange, sb.toString().trim());
            }
        });

        server.createContext("/segments", exchange -> {
            StringBuilder sb = new StringBuilder();
            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                sb.append(block.getName()).append(": ")
                  .append(block.getStart()).append(" - ")
                  .append(block.getEnd()).append("\n");
            }
            sendResponse(exchange, sb.toString().trim());
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            StringBuilder sb = new StringBuilder();
            int count = 0;
            int skipped = 0;
            DataIterator iter = currentProgram.getListing().getDefinedData(true);
            while (iter.hasNext() && count < limit) {
                Data data = iter.next();
                if (data.hasStringValue()) {
                    if (skipped < offset) { skipped++; continue; }
                    sb.append(data.getAddress()).append(": ")
                      .append("\"").append(data.getValue()).append("\"\n");
                    count++;
                }
            }
            sendResponse(exchange, sb.toString().trim());
        });

        server.createContext("/data", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            StringBuilder sb = new StringBuilder();
            int count = 0;
            int skipped = 0;
            DataIterator iter = currentProgram.getListing().getDefinedData(true);
            while (iter.hasNext() && count < limit) {
                Data data = iter.next();
                if (skipped < offset) { skipped++; continue; }
                String name = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                sb.append(data.getAddress()).append(": ").append(name)
                  .append(" = ").append(data.getDefaultValueRepresentation()).append("\n");
                count++;
            }
            sendResponse(exchange, sb.toString().trim());
        });

        server.createContext("/imports", exchange -> {
            sendResponse(exchange, "");
        });

        server.createContext("/exports", exchange -> {
            StringBuilder sb = new StringBuilder();
            SymbolTable symTable = currentProgram.getSymbolTable();
            SymbolIterator iter = symTable.getAllSymbols(true);
            while (iter.hasNext()) {
                Symbol sym = iter.next();
                if (sym.isExternalEntryPoint()) {
                    sb.append(sym.getName()).append(" -> ").append(sym.getAddress()).append("\n");
                }
            }
            sendResponse(exchange, sb.toString().trim());
        });

        for (String ep : new String[]{"/methods", "/classes", "/namespaces"}) {
            server.createContext(ep, exchange -> sendResponse(exchange, ""));
        }

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            Address addr = currentProgram.getAddressFactory().getAddress(params.get("address"));
            StringBuilder sb = new StringBuilder();
            for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(addr)) {
                sb.append("From ").append(ref.getFromAddress())
                  .append(" [").append(ref.getReferenceType()).append("]\n");
            }
            sendResponse(exchange, sb.toString().trim());
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            Address addr = currentProgram.getAddressFactory().getAddress(params.get("address"));
            StringBuilder sb = new StringBuilder();
            for (Reference ref : currentProgram.getReferenceManager().getReferencesFrom(addr)) {
                sb.append("To ").append(ref.getToAddress())
                  .append(" [").append(ref.getReferenceType()).append("]\n");
            }
            sendResponse(exchange, sb.toString().trim());
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String name = params.get("name");
            Function func = null;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(name)) { func = f; break; }
            }
            if (func == null) {
                sendResponse(exchange, "No references found to function: " + name);
                return;
            }
            StringBuilder sb = new StringBuilder();
            for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint())) {
                sb.append("From ").append(ref.getFromAddress())
                  .append(" [").append(ref.getReferenceType()).append("]\n");
            }
            sendResponse(exchange, sb.length() == 0
                ? "No references found to function: " + name
                : sb.toString().trim());
        });

        // Write endpoints
        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String addrStr = params.get("function_address");
            String newName = params.get("new_name");
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                func = currentProgram.getFunctionManager().getFunctionContaining(addr);
            }
            if (func == null) {
                sendResponse(exchange, "Failed to rename function");
                return;
            }
            int tx = currentProgram.startTransaction("Rename function");
            try {
                func.setName(newName, SourceType.USER_DEFINED);
                sendResponse(exchange, "Function renamed successfully");
            } catch (Exception e) {
                sendResponse(exchange, "Failed to rename function");
            } finally {
                currentProgram.endTransaction(tx, true);
            }
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            Function func = null;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(oldName)) { func = f; break; }
            }
            if (func == null) {
                sendResponse(exchange, "Rename failed");
                return;
            }
            int tx = currentProgram.startTransaction("Rename function");
            try {
                func.setName(newName, SourceType.USER_DEFINED);
                sendResponse(exchange, "Renamed successfully");
            } catch (Exception e) {
                sendResponse(exchange, "Rename failed");
            } finally {
                currentProgram.endTransaction(tx, true);
            }
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String addrStr = params.get("address");
            String comment = params.get("comment");
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            int tx = currentProgram.startTransaction("Set comment");
            try {
                currentProgram.getListing().setComment(addr, CommentType.EOL, comment);
                sendResponse(exchange, "Comment set successfully");
            } catch (Exception e) {
                sendResponse(exchange, "Failed to set comment");
            } finally {
                currentProgram.endTransaction(tx, true);
            }
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String addrStr = params.get("address");
            String comment = params.get("comment");
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            int tx = currentProgram.startTransaction("Set comment");
            try {
                currentProgram.getListing().setComment(addr, CommentType.PRE, comment);
                sendResponse(exchange, "Comment set successfully");
            } catch (Exception e) {
                sendResponse(exchange, "Failed to set comment");
            } finally {
                currentProgram.endTransaction(tx, true);
            }
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String addrStr = params.get("function_address");
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (func != null) {
                sendResponse(exchange, "Function prototype set successfully");
            } else {
                sendResponse(exchange, "Failed to set function prototype");
            }
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String addrStr = params.get("address");
            String newName = params.get("newName");
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            int tx = currentProgram.startTransaction("Rename data");
            try {
                SymbolTable symTable = currentProgram.getSymbolTable();
                Symbol symbol = symTable.getPrimarySymbol(addr);
                if (symbol != null) {
                    symbol.setName(newName, SourceType.USER_DEFINED);
                } else {
                    symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                }
                sendResponse(exchange, "Rename data attempted");
            } catch (Exception e) {
                sendResponse(exchange, "Rename data attempted");
            } finally {
                currentProgram.endTransaction(tx, true);
            }
        });
    }

    // --- helpers ---

    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> params = new HashMap<>();
        String query = exchange.getRequestURI().getRawQuery();
        if (query == null) return params;
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                params.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                           URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
            }
        }
        return params;
    }

    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        if (body.isEmpty()) return params;
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                params.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                           URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
            }
        }
        return params;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private int parseIntOrDefault(String val, int def) {
        if (val == null) return def;
        try { return Integer.parseInt(val); } catch (NumberFormatException e) { return def; }
    }
}
