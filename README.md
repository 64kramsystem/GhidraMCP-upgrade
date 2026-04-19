# GhidraMCP-next

Fork of [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP), updated for Ghidra 12, and with some improvements.

## Changes from upstream

- Java 21 / Ghidra 12.0.x compatibility
- Replaced deprecated `CodeUnit` comment constants with `CommentType` enum
- Fixed `renameData` to work on addresses without defined data
- CI builds against latest Ghidra 12.0.x with automated releases
- Integration test suite (runs headless in CI)

## Installation

Download the latest [release](https://github.com/64kramsystem/GhidraMCP-next/releases) ZIP, then in Ghidra:

1. File > Install Extensions > `+` > select the ZIP
2. Restart Ghidra
3. File > Configure > Developer > enable GhidraMCPPlugin

The plugin starts an HTTP server on port 8080 (configurable via Edit > Tool Options > GhidraMCP HTTP Server).

## MCP client setup

See the [upstream README](https://github.com/LaurieWired/GhidraMCP#mcp-clients) for Claude Desktop, Cline, and other MCP client configurations. Use `bridge_mcp_ghidra.py` from the release.

## Building from source

```bash
# Copy Ghidra JARs to lib/
mkdir -p lib
for jar in Base Decompiler Docking Generic Project SoftwareModeling Utility Gui; do
  cp "$GHIDRA_HOME"/Ghidra/*/lib/${jar}.jar lib/ 2>/dev/null ||
  cp "$GHIDRA_HOME"/Ghidra/*/*/lib/${jar}.jar lib/
done

mvn clean package assembly:single
```

Output: `target/GhidraMCP-next-1.0-SNAPSHOT.zip`

## Testing

```bash
bash test_endpoints.sh
```

Requires Ghidra running with the plugin enabled and a program open with at least one function. See the script header for setup with the included test binary (`test/fixtures/test_6502.bin`).
