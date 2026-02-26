# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GhidraMCP is a Model Context Protocol (MCP) server for Ghidra that enables AI language models to autonomously reverse engineer applications. It has two components:

1. **Java Ghidra Plugin** — An embedded HTTP server (port 8080) that exposes Ghidra's analysis API as REST endpoints
2. **Python MCP Bridge** (`bridge_mcp_ghidra.py`) — Translates MCP protocol calls into HTTP requests to the Ghidra plugin

Data flow: `MCP Client → Python Bridge → HTTP → Ghidra Plugin → Ghidra API`

## Build Commands

### Java Plugin (Gradle)
Requires `GHIDRA_INSTALL_DIR` environment variable pointing to a Ghidra installation (11.3.2+), Java 21.

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
gradle                    # Build the extension zip
```

The build uses Ghidra's `buildExtension.gradle` script. Output goes to `dist/`.

### Python Bridge
```bash
pip install -r requirements.txt    # mcp>=1.2.0, requests>=2
python bridge_mcp_ghidra.py        # Run with stdio transport (default)
python bridge_mcp_ghidra.py --transport streamable-http --mcp-host 127.0.0.1 --mcp-port 8081
python bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/
```

### Testing
No automated test suite exists. The plugin is tested manually by installing into Ghidra and exercising endpoints.

## Architecture

### Handler System (Java)
All HTTP endpoints are implemented as subclasses of the abstract `Handler` class (`handlers/Handler.java`). Handlers are **auto-discovered at startup** via reflection (`org.reflections`) — any class extending `Handler` in `com.lauriewired.handlers` is automatically registered.

To add a new endpoint:
1. Create a class extending `Handler` in the appropriate subpackage
2. Call `super(tool, "/your_endpoint")` in the constructor
3. Implement `handle(HttpExchange exchange)`

Handler subpackages organize by operation type:
- `handlers/get/` — Read-only queries (list functions, get xrefs, etc.)
- `handlers/set/` — Rename/modify operations
- `handlers/act/` — Complex actions (decompile, create structs/enums/classes)
- `handlers/comment/` — Comment operations
- `handlers/search/` — Search operations

### Key Utilities (Java)
- `util/GhidraUtils.java` — Program access, data type resolution, comment setting
- `util/ParseUtils.java` — HTTP response helpers (`sendResponse`, `parseQueryParams`, `parsePostBody`)
- `util/StructUtils.java` / `util/EnumUtils.java` — Structure and enum manipulation

### Thread Safety
All Ghidra API calls from HTTP handlers must run on Swing EDT. Handlers use `SwingUtilities.invokeAndWait()` to safely access Ghidra's non-thread-safe APIs.

### MCP Bridge (Python)
`bridge_mcp_ghidra.py` uses `FastMCP` from the `mcp` SDK. Each MCP tool is a decorated function that calls `safe_get()` or `safe_post()` to talk to the Ghidra HTTP server. The bridge supports stdio, SSE (deprecated), and streamable-http transports.

### Dependencies
- **Java**: `gson:2.10.1` (JSON), `reflections:0.10.2` (handler discovery), Ghidra framework
- **Python**: `mcp>=1.2.0`, `requests>=2`

## Adding a New Tool

1. **Java side**: Create a new `Handler` subclass in the appropriate `handlers/` subpackage. It will be auto-registered.
2. **Python side**: Add a `@mcp.tool()` decorated function in `bridge_mcp_ghidra.py` that calls the new endpoint via `safe_get()` or `safe_post()`.
