[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# GhidraMCP

An MCP server that lets an LLM (Claude Code, Codex, Cursor, ...) read and annotate the programs
open in Ghidra: decompile, follow references, rename, type, comment, define structures, search,
patch and emulate.

Two pieces, both Java, nothing else to install (no Python, no SDK):

- the **Ghidra extension**, which serves the programs open in each CodeBrowser on loopback;
- the **MCP server**, `ghidra-mcp-bridge.jar` (~350 KB, any JDK 21+), which the MCP client
  starts over stdio and which sends each call to the Ghidra that has the program open.

It implements MCP **2026-07-28** (stateless: `server/discover`, per-request `_meta`, cache
hints, `subscriptions/listen`) and still answers clients that open with the older `initialize`
handshake (2025-11-25, 2025-06-18).

Continued from LaurieWired's [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) by way of
[pinksawtooth](https://github.com/pinksawtooth/GhidraMCP); several tools follow ideas from
LaurieWired's 2.0 rewrite and from [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp)
(see [Credits](#credits)).

## What it is good at

- **Several programs at once, safely.** Any number of Ghidra instances, each with any number of
  programs open. Every call names its *program* (`program="SLUS_012.57"`), never a port, and is
  sent only to the instance that has exactly that database open. Nothing is ever chosen for you
  and nothing is remembered between calls. See [Targeting](#targeting).
- **Errors are errors.** A failed call comes back as an MCP error with a stable code
  (`[FUNCTION_NOT_FOUND]`, `[BAD_ADDRESS]`, `[AMBIGUOUS]`, ...) and a message that says what to
  do. Unknown types are never replaced by `int`; misspelt parameters are rejected.
- **Fast decompilation.** One decompiler is kept open per program: after the first call a
  decompile takes a few milliseconds instead of a quarter of a second.
- **Whole-function annotation in one call.** `set_variables`, `set_comments`, `create_label`
  with a list, `import_c_types` for many types at once.
- **Retro-console friendly.** Overlay blocks from files, equates for hardware registers,
  references for pointer tables, `find_code_gaps` for code analysis missed, P-code emulation of
  decompressors and checksums.

## Install

Requires Ghidra 12.2 (Java 25).

1. Download the release zip, or build it (see [Building](#building)).
2. In Ghidra: `File` > `Install Extensions` > `+` > choose the zip > restart Ghidra.
3. Open a program in the **CodeBrowser** and enable the plugin: `File` > `Configure` >
   `Developer` > `GhidraMCPPlugin`. (Ghidra may offer it in a "New Plugins Found" dialog.)

Each CodeBrowser then serves its open programs on the first free loopback port from 8080.

## Connect a client

```json
{ "mcpServers": { "ghidra-mcp": {
    "command": "java",
    "args": ["-jar", "/path/to/ghidra-mcp-bridge.jar"] } } }
```

Claude Code: `claude mcp add ghidra-mcp -- java -jar /path/to/ghidra-mcp-bridge.jar` (the
[Claude Code plugin](https://github.com/sadnescity/ghidra-claude-plugin) ships the jar and
this configuration).

`ghidra-mcp-bridge.jar` is built into `dist/` next to the extension zip. The client starts it,
so **start order does not matter**: it is up with Ghidra closed (the tools are listed from the
catalog bundled in the jar, and calls answer that no Ghidra is running), finds Ghidra as soon as
it opens, and finds it again after a restart. If the jar and the installed extension come from
different builds, the first call that reaches Ghidra switches to the extension's tool list and
tells clients listening on `subscriptions/listen` (`notifications/tools/list_changed`).

Options: `--discovery-base-port 8080`, `--discovery-range 100`, `--ghidra-timeout 120`
(seconds), `--version`.

There is no HTTP MCP endpoint: MCP over HTTP is meant for remote servers, and a local one would
be one more open port to protect.

## Targeting

Two programs built from one engine share addresses, so a call answered by the wrong database
looks plausible and a write lands silently in the wrong game. The rules:

- **Every call names its program.** Each tool takes a required `program` argument, exactly as
  `list_instances` shows it: the program's name, or `project:/path` when the name is open in
  more than one project. Nothing is remembered between calls, so no call can land in a program
  because someone else chose it earlier (one server process may serve several conversations or
  subagents at once).
- **The target is a program, never a port.** Which Ghidra answers on 8080 is decided by boot
  order and changes between restarts; the program is looked up on every port at every call.
  A port that does not answer in time is not taken as empty (the program might be open there
  too): calls are refused with `[BUSY]` until it answers. A Ghidra busy with a long call still
  answers, because only the calls themselves wait their turn.
- **Nothing is chosen implicitly.** A call without `program` is refused, even when only one
  program is open. A name open in two places is refused (`[AMBIGUOUS]`) with the values that
  tell them apart. Several programs of one project, and one program open in two CodeBrowser
  windows of the same Ghidra, are fine. Only two copies of one project open in two Ghidra
  processes cannot be told apart, and are refused until one is closed.
- **The instance checks too.** Each call names the database's file id; an instance that does not
  have it open refuses (`[NOT_HERE]`).
- Every change is recorded in Ghidra's undo history under the client's session id.

## Tools

| Tool | | What it does |
|---|---|---|
| `list_instances` | | Every running Ghidra and every open program in it, with the `program` value to pass (answered by the MCP server itself) |
| **Program** | | |
| `get_program_info` |  | Identify the target program: name, project path, format, processor/language, compiler spec, endianness, pointer size, image base, address range, memory blocks, function count, entry points, unsaved changes. |
| `get_current_address` |  | Get the address the analyst has selected in the Ghidra listing (cursor position). |
| `get_current_function` |  | Get the function containing the analyst's cursor in the Ghidra listing. |
| `goto_address` |  | Move the analyst's Ghidra listing and decompiler view to an address (or a function/label name), bringing the target program to the front. |
| `save_program` | write | Save the program's changes to the project, as File > Save does. |
| **Listings** | | |
| `list_functions` |  | List functions as 'name @ address', in address order, optionally filtered by a case-insensitive substring of the name. |
| `list_methods` |  | List function names only, in address order (paged). |
| `search_functions_by_name` |  | Find functions whose name contains a substring (case-insensitive), as 'name @ address'. |
| `list_classes` |  | List class namespaces (fully qualified), paged. |
| `list_namespaces` |  | List non-global namespaces (fully qualified), paged. |
| `list_segments` |  | List memory blocks: name, range, size, permissions (r/w/x, v=volatile), initialized or not, overlay or not. |
| `list_imports` |  | List imported (external) symbols with their library. |
| `list_exports` |  | List exported symbols / entry points as 'name @ address'. |
| `list_data_items` |  | List defined data: address, label, type, value. |
| `list_strings` |  | List defined strings as 'address: "text"', optionally filtered by a case-insensitive substring of the text. |
| **Functions** | | |
| `decompile_function` |  | Decompile a function by name and return its C pseudocode. |
| `decompile_function_by_address` |  | Decompile the function at, or containing, an address (or a function/label name) and return its C pseudocode. |
| `disassemble_function` |  | Disassemble a function's body: one line per instruction, 'address: bytes  instruction ; comment', labels on their own line. |
| `get_listing` |  | Show the listing from an address onward, whether or not it belongs to a function: instructions, defined data and undefined bytes, with labels and comments. |
| `get_function_by_address` |  | Describe the function at, or containing, an address: name, entry, signature, calling convention, body range and size, parameters, flags (thunk, no-return, external), plate comment. |
| `create_function` | write | Create a function at one or more addresses, disassembling first if the bytes are undefined. |
| `delete_function` | write | Delete the function defined at one or more addresses (the inverse of create_function). |
| `disassemble` | write | Disassemble undefined bytes starting at an address, following the flow (calls, branches) as Ghidra's D key does, without creating a function. |
| `rename_function` | write | Rename a function given its current name. |
| `rename_function_by_address` | write | Rename the function at, or containing, an address. |
| `set_function_prototype` | write | Set a function's signature from a C prototype, e.g. |
| `set_function_no_return` | write | Mark (or unmark) a function as never returning, e.g. |
| **Variables** | | |
| `list_variables` |  | List a function's parameters and local variables as the decompiler shows them: name, type, storage, and whether the name/type was set by a user. |
| `rename_variable` | write | Rename a parameter or local variable of a function, as shown in the decompiler. |
| `set_local_variable_type` | write | Set the type of a parameter or local variable, as shown in the decompiler (e.g. |
| `set_variables` | write | Rename and/or retype several variables of one function in a single decompile and a single transaction (all or nothing). |
| **References and call graph** | | |
| `get_xrefs_to` |  | List references TO an address (or symbol): 'from-address (in function) TYPE'. |
| `get_xrefs_from` |  | List references FROM an instruction or data address: 'to-address (name) TYPE'. |
| `get_function_xrefs` |  | List references to a function's entry point, by name or (preferably) address. |
| `get_function_calls` |  | One level of the call graph around a function. |
| `get_callee` |  | List the distinct functions called by the function at, or containing, an address, as 'name @ address' (external functions marked). |
| **Comments** | | |
| `set_decompiler_comment` | write | Set the comment the decompiler shows above the statement at an address (a PRE comment). |
| `set_disassembly_comment` | write | Set the end-of-line comment shown in the disassembly at an address (an EOL comment). |
| `set_comment` | write | Set a listing comment of any kind at any address (code or data). |
| `set_comments` | write | Set many comments in one transaction (all or nothing). |
| `get_comments` |  | Read comments. |
| **Labels and bookmarks** | | |
| `rename_data` | write | Name the data (or any location) at an address: renames its primary label, or creates one if it has none. |
| `create_label` | write | Create labels (extra names at addresses, e.g. |
| `delete_label` | write | Delete a label at an address by name (function names are not labels: use delete_function). |
| `get_data_by_label` |  | Look up a label: '<label> -> <address> : <type> <value>' for each place it names. |
| `add_bookmark` | write | Create a bookmark at an address (replacing one of the same type and category there). |
| `list_bookmarks` |  | List bookmarks: 'address type/category: comment', optionally only one type. |
| **Data types** | | |
| `create_struct` | write | Create a structure, optionally with its members. |
| `add_struct_members` | write | Add members to an existing structure (in one transaction). |
| `remove_struct_members` | write | Remove members from a structure by name. |
| `clear_struct` | write | Remove every member of a structure, keeping its name (and size 0). |
| `modify_struct_field` | write | Change one field of a structure or union in place: rename it, retype it (at the same offset; a larger type takes undefined bytes after it, and fails if a defined field is in the way), and/or set its comment. |
| `get_struct` |  | Show a structure (or union) as C, with every field's offset, type, name and comment, and the undefined gaps between them. |
| `create_union` | write | Create a union with its members. |
| `create_enum` | write | Create an enum, optionally with values. |
| `add_enum_values` | write | Add values to an existing enum. |
| `remove_enum_values` | write | Remove values from an enum by name. |
| `get_enum` |  | Show an enum: its values (hex and decimal) and comments. |
| `create_typedef` | write | Create a typedef: a new name for an existing type, e.g. |
| `import_c_types` | write | Parse C declarations (structs, unions, enums, typedefs, function pointer typedefs) with Ghidra's C parser and add them to the program. |
| `list_data_types` |  | List the program's data types as 'path  kind  size', optionally filtered by a substring of the name, a category prefix and/or a kind. |
| `rename_data_type` | write | Rename a data type in place; every use of it follows. |
| `delete_data_type` | write | Delete a data type. |
| `set_global_data_type` | write | Apply a data type at an address (define a global): e.g. |
| `clear_data` | write | Undefine the data (or instructions) covering an address range, making the bytes undefined again. |
| **C++ classes** | | |
| `create_class` | write | Create a C++ class: a class namespace and its structure (in /classes/...), optionally with data members. |
| `add_class_members` | write | Add data members to a class's structure. |
| `remove_class_members` | write | Remove data members from a class's structure by name. |
| **Memory** | | |
| `read_memory` |  | Read program memory as a hex dump with ASCII, 16 bytes per line. |
| `get_bytes` |  | Read raw bytes as a hex dump (same as read_memory; kept for existing callers). |
| `set_bytes` | write | Write bytes into program memory (patch). |
| `create_memory_block` | write | Add a memory block, e.g. |
| **Search** | | |
| `search_bytes` |  | Search memory for a byte pattern. |
| `search_instructions` |  | Search instructions by a regular expression, matched against both the raw text ('jal 0x80012345') and the listing text with names ('jal clamp_int'), e.g. |
| `find_code_gaps` |  | Find stretches of executable memory that no function covers: undefined bytes, and instructions outside any function. |
| **References and equates** | | |
| `add_reference` | write | Add a reference from an instruction or data address to a target the analyzer could not infer: a pointer computed at run time, a jump-table entry, a callback stored in a table. |
| `remove_reference` | write | Remove the references from one address to another (all kinds), e.g. |
| `set_equate` | write | Show a constant operand by name (an equate), e.g. |
| **Emulation** | | |
| `emulate_function` |  | Run a function in Ghidra's P-code emulator with the register and memory inputs you give, until it returns (or a step limit, or an error), and report the result registers, the memory it wrote and any memory you ask to read. |

Listings are paged (`offset`, `limit`) and end with a footer (`-- items 1-1000 of 2400; next
page: offset=1000 --`) whenever there is more. Where a tool takes an address it also accepts a
function or label name. Changes are made at once but saved only by `save_program` (or the
analyst).

## Options

`Edit` > `Tool Options` > `GhidraMCP HTTP Server`:

| Option | Default | |
|---|---|---|
| Server Port | 8080 | First port tried for this tool's endpoint |
| Decompile Timeout | 60 | Seconds |

Everything listens on 127.0.0.1 only, and requests carrying a browser `Origin` or a foreign
`Host` are refused, so a web page cannot drive Ghidra.

## Building

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC
gradle            # builds dist/ghidra_12.2_PUBLIC_<date>_GhidraMCP.zip and dist/ghidra-mcp-bridge.jar
gradle test       # targeting rules against fake instances, and source rules
```

A tool is a method annotated with `@Tool`, its parameters with `@P`, in a class listed in
`ToolRegistry.TOOL_CLASSES`. That one declaration is the whole tool: the MCP schema is generated
from it (and bundled into the bridge jar as `mcp-tools.json`). The MCP server adds the required
`program` argument to every tool.

## Credits

- LaurieWired, original GhidraMCP; the 2.0 rewrite's error codes, pagination, program info,
  call graph and memory-gap reporting inspired the ones here.
- pinksawtooth and DaCodeChick, the handler-based fork this continues.
- bethington/ghidra-mcp: batch variable/comment/label operations, C header import, union and
  field editing, equates, references, code-gap search, P-code emulation and decompiler reuse.

Apache License 2.0.
