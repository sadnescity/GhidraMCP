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
pip install -r requirements.txt    # mcp>=2.2,<3, requests>=2
python bridge_mcp_ghidra.py        # Run with stdio transport (default)
python bridge_mcp_ghidra.py --transport streamable-http --mcp-host 127.0.0.1 --mcp-port 8081
python bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/   # pin to one instance
```

`--ghidra-server` is a **pin**, not a default: the bridge asks that port which
program it holds and targets that program. Without it there is no target, and
every call is refused until a session says which program it means with
`use_program(name)` or `use_instance(port)`. The bridge never chooses on the
caller's behalf — see "Targeting" below.

### Testing
```bash
# Python bridge -- real HTTP servers stand in for Ghidra on a private port range
uv run --no-project --with pytest --with requests --with "mcp>=2.2,<3" python -m pytest tests/ -q

# Java plugin -- pure logic and the rules that keep handlers honest
export GHIDRA_INSTALL_DIR=/path/to/ghidra && gradle test
```
Use `--no-project`: a virtualenv left in the project directory is copied into
the extension zip, which is how an 11 MB one once shipped inside a 1.5 MB
extension. `mcp>=2.2,<3` matches the pin in `pyproject.toml` (mcp 2.x: FastMCP is now
`MCPServer`, transport host/port go to `run()`, and it speaks MCP 2026-07-28
while still serving 2025-era clients).

The Java tests cover what can be tested without a running Ghidra: the identity
guard's decision, transaction naming, and two rules over the sources -- that no
handler opens a transaction without naming the session, and that the HTTP
server keeps its single-threaded executor (`Handler` carries the session in a
field, which is only safe while requests are dispatched one at a time). Handler
behaviour against a real program is still tested by hand.

## Architecture

### Targeting: which Ghidra instance a call reaches
Several Ghidra instances can be up at once, each with its own program, and
several bridge processes talk to them — one per Claude Code session. Getting
this wrong is not a visible failure: two programs built from the same engine
share addresses, so a call answered by the wrong database returns a plausible
answer, and a write lands silently in the wrong game.

The rules the bridge follows:

* **The target is a program, never a port.** Which game answers on 8080 is
  decided by boot order and changes between restarts.
* **Nothing is chosen implicitly.** No default port, no auto-selection when only
  one instance is up, no background thread that re-points a session. Boot order
  is not a choice.
* **The program is confirmed before every call** (~0.3 ms on loopback). If the
  port now holds something else, or has gone quiet, the bridge looks for the
  program elsewhere; finding it on exactly one port it follows it there, and on
  none or several it raises and sends nothing.
* **Every request names the database** it believes it is addressing
  (`X-Ghidra-File-ID`) **and the session asking** (`X-Ghidra-Session`), so the
  instance can refuse what is not its own and the undo stack records who acted.
* **A refusal raises**, never returns as a line of text among the results.

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
`bridge_mcp_ghidra.py` uses `MCPServer` (formerly `FastMCP`) from the `mcp` 2.x SDK. Each MCP tool is a decorated function that calls `safe_get()` or `safe_post()` to talk to the Ghidra HTTP server. The bridge supports stdio, SSE (deprecated), and streamable-http transports.

### Dependencies
- **Java**: `gson:2.10.1` (JSON), `reflections:0.10.2` (handler discovery), Ghidra framework
- **Python**: `mcp>=2.2,<3`, `requests>=2`

## Adding a New Tool

1. **Java side**: Create a new `Handler` subclass in the appropriate `handlers/` subpackage. It will be auto-registered.
2. **Python side**: Add a `@mcp.tool()` decorated function in `bridge_mcp_ghidra.py` that calls the new endpoint via `safe_get()` or `safe_post()`.
