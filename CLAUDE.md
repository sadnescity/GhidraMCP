# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

A Ghidra extension (Java) plus a standalone MCP server (Java). No Python, no SDK.

- **Per CodeBrowser** (`core/InstanceServer`, in the extension): a loopback HTTP endpoint on the
  first free port from 8080. `/instances` says what it holds (port, project, every open program
  with its file id), `/mcp/tools` lists the tool schemas, `/mcp/call` runs one tool on the
  program named by the required `X-Ghidra-File-ID` header. Calls run one at a time on a single
  thread. This is a private API, not MCP.
- **MCP server** (`mcp/`, no Ghidra imports, excluded from the extension jar; `gradle bridgeJar`
  builds `dist/ghidra-mcp-bridge.jar` = `mcp/` + catalog + Gson): `StdioMain` (stdio transport),
  `McpServer` (JSON-RPC, dual-era: MCP 2026-07-28 stateless with per-request `_meta`,
  `server/discover`, `resultType`, `ttlMs`/`cacheScope`, `subscriptions/listen`; and the
  `initialize` handshake for 2025-11-25/06-18 clients), `Router` (discovery, resolving the
  `program` argument, forwarding). After the first call that reaches Ghidra, the bundled catalog
  is compared with the live one; if they differ the live one wins and listeners get
  `notifications/tools/list_changed`.
- There is deliberately no HTTP MCP endpoint and no per-client state.

## Targeting rules (do not weaken)

Two programs built from one engine share addresses: a call answered by the wrong database
looks right and a write lands silently in the wrong game. So:

- Every tool takes a required `program` (name, `project:/path`, or file id). Nothing is
  remembered between calls: MCP 2026-07-28 forbids relying on earlier requests, and one stdio
  process can serve several conversations or subagents.
- The target is a program (file id), never a port; it is looked up on every port at every call.
- Nothing is chosen implicitly: no default, no auto-selection, not even with one program. A
  value matching more than one open program is refused (`AMBIGUOUS`), and nothing is sent.
- The instance refuses a call whose file id it does not have open (`NOT_HERE`, HTTP 409) or
  that names no file id (`NO_PROGRAM`, HTTP 400).
- A refusal is an MCP error result, never a line of text among results.

`src/test/java/com/lauriewired/mcp/McpServerTest.java` pins these, and the protocol, against
fake instances on a private port range.

## Adding a tool

1. Add a method to a class in `tools/` (or a new class listed in `ToolRegistry.TOOL_CLASSES`):
   ```java
   @Tool(name = "do_thing", readOnly = false, description = "What it does and returns.")
   public String doThing(Ctx ctx,
           @P(value = "address", description = "...") String address,
           @P(value = "limit", def = "100", description = "...") int limit) { ... }
   ```
   Parameter types: String, int, long, boolean, JsonArray, JsonObject. `def = P.NULL` for an
   optional parameter that may be absent; no `def` means required.
2. That is all: the schema comes from the annotations (`gradle generateCatalog` writes it into
   the bridge jar). Never rename an existing tool or parameter: permission
   allowlists and skills name them.

Use the `Ctx` helpers so every tool behaves alike: `ctx.addr()` (addresses or symbol names,
`BAD_ADDRESS`), `ctx.fnAt()` / `ctx.fnByName()` (`FUNCTION_NOT_FOUND`, `AMBIGUOUS`),
`ctx.type()` (never falls back to another type), `ctx.decompile()` (cached decompiler),
`ctx.write(name, () -> ...)` (one transaction on the Swing thread, named after the calling
session, rolled back on any exception). Fail with `ToolError`; page lists with `Page`.

## Build and test

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC   # Ghidra 12.2 needs Java 25
gradle          # dist/ghidra_12.2_PUBLIC_<date>_GhidraMCP.zip
gradle test
```

The tests cover what runs without Ghidra: the router's targeting rules, transaction naming
(only `Ctx.write` opens transactions, always with `txName`), and that the instance server stays
single-threaded. Tool behaviour against real programs is tested by hand against a running
Ghidra through the bridge jar.
