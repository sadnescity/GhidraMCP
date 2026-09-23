# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=2.2,<3",
# ]
# ///

import os
import sys
import json
import threading
from concurrent.futures import ThreadPoolExecutor
import requests
import argparse
import logging
from typing import Optional
from urllib.parse import urljoin, urlsplit

from mcp.server.mcpserver import MCPServer

DEFAULT_REQUEST_TIMEOUT = 30
DEFAULT_DISCOVERY_BASE_PORT = 8080
DEFAULT_DISCOVERY_RANGE = 100

logger = logging.getLogger(__name__)

mcp = MCPServer("ghidra-mcp", log_level="INFO")

# Initialize ghidra_request_timeout with default value
ghidra_request_timeout = DEFAULT_REQUEST_TIMEOUT

# Multi-instance state
active_instances: dict[int, dict] = {}  # port -> {"port", "program", "project", "file_id"}
# The chosen target is a PROGRAM, not a port. A port is an allocation detail:
# which game answers on 8080 is decided by boot order and changes between
# restarts. The program is what the caller means, so that is what we hold, and
# the port is re-derived from it whenever it is needed.
current_target: Optional[dict] = None  # {"program", "project", "file_id", "port"}
_instances_lock = threading.Lock()
_discovery_base_port = DEFAULT_DISCOVERY_BASE_PORT
_discovery_port_range = DEFAULT_DISCOVERY_RANGE

def _ask_identity(port: int, timeout: float) -> Optional[dict]:
    """Ask one port which program it is holding. None if it will not say."""
    try:
        resp = requests.get(f"http://127.0.0.1:{port}/instances", timeout=timeout)
        if not resp.ok:
            return None
        for inst in resp.json():
            if inst.get("port") == port:
                return {"port": port,
                        "program": inst.get("program") or None,
                        "project": inst.get("project") or None,
                        "file_id": inst.get("file_id") or None}
    except Exception:
        return None
    return None


def _same_program(a: dict, b: dict) -> bool:
    """Do two identities name the same database?"""
    return (a.get("program"), a.get("project")) == (b.get("program"), b.get("project"))


def _describe(t: dict) -> str:
    return f"{t.get('program') or 'no program'} ({t.get('project') or 'unknown project'})"


def _resolve_base_url(port: Optional[int] = None) -> str:
    """
    Resolve the base URL for a Ghidra instance.
    If port is given, construct URL from it. Otherwise use the chosen target.
    """
    global current_target

    if port is not None:
        return f"http://127.0.0.1:{port}/"
    if current_target is None:
        # Nothing has been chosen, so there is nothing to resolve. Picking one
        # here -- the default port, or the only instance that happens to answer
        # -- is picking by boot order, and boot order is not a choice. That is
        # what sent a session's work into another game's database without a
        # word: the addresses of two programs built from one engine coincide, so
        # nothing in any reply would have shown the mistake.
        listed = ", ".join(
            f"{p} ({i.get('program') or 'no program'})"
            for p, i in sorted(active_instances.items())) or "none discovered yet"
        raise RuntimeError(
            f"No Ghidra instance has been chosen. Call use_instance(port) or "
            f"use_program(name) first -- this bridge will not choose for you, "
            f"because a wrong choice writes into the wrong program and nothing "
            f"in the answer would say so. Instances: {listed}.")

    # Confirm, at the port we last saw it on, that the chosen program is still
    # the one there. Measured at 0.25-0.5 ms on loopback; when the instance is
    # busy this queues behind its work, which is exactly as long as the call
    # itself would have queued.
    here = _ask_identity(current_target["port"], ghidra_request_timeout)
    if here is not None and _same_program(here, current_target):
        return f"http://127.0.0.1:{current_target['port']}/"

    # The port no longer holds what was chosen: it went quiet, or a restart
    # dealt the ports out in a different order. A port is an allocation detail,
    # so look for the program itself rather than giving up or, worse, settling
    # for whoever answers.
    found = [i for i in _discover_instances(ghidra_request_timeout).values()
             if _same_program(i, current_target)]
    if len(found) == 1:
        with _instances_lock:
            current_target = dict(found[0])
        logger.info("%s moved to port %s", _describe(current_target),
                    current_target["port"])
        return f"http://127.0.0.1:{current_target['port']}/"

    was = (f"port {current_target['port']} did not answer" if here is None
           else f"port {current_target['port']} is now holding {_describe(here)}")
    lo, hi = _discovery_base_port, _discovery_base_port + _discovery_port_range - 1
    if not found:
        raise RuntimeError(
            f"{_describe(current_target)}: {was}, and the program is not open on "
            f"any port in {lo}-{hi}. Nothing was sent.")
    ports = ", ".join(str(i["port"]) for i in sorted(found, key=lambda x: x["port"]))
    raise RuntimeError(
        f"{_describe(current_target)}: {was}, and the same program now answers on "
        f"{len(found)} ports ({ports}). Neither is the one that was chosen. "
        f"Nothing was sent -- say which with use_instance(port).")


def _session_tag() -> Optional[str]:
    """A short, stable name for the calling session.

    Ghidra records a name per transaction, in the undo stack and the project
    history, and today it is generic ("Create Function") -- it throws away the
    one fact that was missing for two hours when four functions appeared in a
    database and nobody could say who had made them. Claude Code already puts a
    distinct session id in every bridge's environment, so this costs nothing.
    """
    sid = os.environ.get("CLAUDE_CODE_SESSION_ID")
    return sid.split("-")[0] if sid else None


def _identity_headers(port: Optional[int]) -> dict:
    """What this request believes it is talking to, and on whose behalf.

    The file id goes out only when the target was resolved from the chosen
    program: an explicit port= is a deliberate bypass and must not be stamped
    with somebody else's identity. It is absent entirely against a plugin that
    does not report one, so the two halves can be updated in either order.
    """
    headers = {}
    if port is None and current_target and current_target.get("file_id"):
        headers["X-Ghidra-File-ID"] = current_target["file_id"]
    tag = _session_tag()
    if tag:
        headers["X-Ghidra-Session"] = tag
    return headers


def _raise_if_refused(response) -> None:
    """A 409 is the instance saying the request named a database that is not
    its own. It is not a result to be read among the others: it stops here."""
    if response.status_code == 409:
        raise RuntimeError(f"The Ghidra instance refused the call: "
                           f"{response.text.strip()}")


def safe_get(endpoint: str, params: dict = None, port: int = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(_resolve_base_url(port), endpoint)

    try:
        response = requests.get(url, params=params, timeout=ghidra_request_timeout,
                                headers=_identity_headers(port))
        response.encoding = 'utf-8'
        _raise_if_refused(response)
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except requests.RequestException as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str, port: int = None) -> str:
    # Resolution happens outside the try: a refusal to send is not a failure to
    # send, and returning it as "Request failed: ..." dresses it as a flaky
    # connection -- something a caller retries instead of stopping at.
    url = urljoin(_resolve_base_url(port), endpoint)
    try:
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=ghidra_request_timeout,
                                     headers=_identity_headers(port))
        else:
            response = requests.post(url, data=data.encode("utf-8"),
                                     timeout=ghidra_request_timeout,
                                     headers=_identity_headers(port))
        response.encoding = 'utf-8'
        _raise_if_refused(response)
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except requests.RequestException as e:
        return f"Request failed: {str(e)}"

def _discover_instances(timeout: float = 1.5) -> dict[int, dict]:
    """
    Ask every port in the range what it is holding, and merge the answers.
    """
    discovered: dict[int, dict] = {}

    def _ask(port: int) -> None:
        """Ask one port what it is, and record whatever it names."""
        try:
            resp = requests.get(f"http://127.0.0.1:{port}/instances", timeout=timeout)
            if not resp.ok:
                return
            for inst in resp.json():
                p = inst["port"]
                discovered[p] = {
                    "port": p,
                    "program": inst.get("program") or None,
                    "project": inst.get("project") or None,
                    # Discovery used to drop this, so a target chosen with
                    # use_program carried no identity and the instance had
                    # nothing to refuse on -- the guard was inert on the path a
                    # session is most likely to take.
                    "file_id": inst.get("file_id") or None,
                }
        except Exception:
            return

    # EVERY port in the range, every time, and the results are MERGED.
    #
    # This used to ask one known port, take whatever that instance listed, and
    # return immediately. An instance only ever lists ITSELF -- there is no
    # registration between them -- so a second Ghidra on the next port was
    # invisible for the whole life of the bridge: `list_instances` showed one,
    # `use_instance` on the other was refused as "not found", and every call
    # then fell through to the default port. Two sessions reverse engineering
    # two games lost an afternoon to that, and four functions were created in
    # the wrong database before anyone could see why.
    ports = set(range(_discovery_base_port,
                      _discovery_base_port + _discovery_port_range))
    ports.update(active_instances.keys())

    with ThreadPoolExecutor(max_workers=min(16, len(ports))) as pool:
        list(pool.map(_ask, sorted(ports)))

    return discovered


def _pin_to(url: str) -> str:
    """Pin this bridge to the instance at `url`, by the program found there.

    This is what --ghidra-server means now. It used to be a default to fall
    back on when nothing had been chosen, which is how a call with no target
    ended up in whichever game happened to be on port 8080.
    """
    global current_target
    try:
        port = int(urlsplit(url).port)
    except (TypeError, ValueError):
        return f"--ghidra-server {url!r} names no port; nothing pinned."

    here = _ask_identity(port, ghidra_request_timeout)
    if here is None or here.get("program") is None:
        return (f"No Ghidra instance with a program loaded answered on port "
                f"{port}; nothing pinned. Choose one with use_instance(port).")
    with _instances_lock:
        active_instances[port] = here
        current_target = here
    return f"Pinned to {_describe(here)} on port {port}."


@mcp.tool()
def list_instances() -> list:
    """
    Discover and list all active Ghidra instances.
    Returns information about each running Ghidra CodeBrowser with GhidraMCP loaded,
    including the port number, program name, and project name.
    The currently selected instance (if any) is marked with [ACTIVE].
    Use use_instance(port) to switch between instances.
    """
    global active_instances

    discovered = _discover_instances()
    with _instances_lock:
        active_instances = discovered

    if not active_instances:
        return ["No Ghidra instances found. Ensure GhidraMCP plugin is running in Ghidra."]

    lines = []
    for port, info in sorted(active_instances.items()):
        chosen = current_target is not None and _same_program(info, current_target)
        marker = " [ACTIVE]" if chosen else ""
        program = info.get("program") or "No program loaded"
        project = info.get("project") or "Unknown project"
        lines.append(f"Port {port}: {program} ({project}){marker}")
    return lines


@mcp.tool()
def use_instance(port: int) -> str:
    """
    Choose the Ghidra instance to work in, by the port it answers on.

    What is remembered is the PROGRAM found there, not the port: if the
    instance later moves to another port the bridge follows it, and if that
    port comes to hold a different program every call is refused rather than
    answered by the wrong database.

    Args:
        port: The port number of the Ghidra instance to target.
    """
    global current_target, active_instances

    # Ask the port itself. Discovery is a convenience, not the authority: a
    # port that answers is an instance, whether or not anything advertised it.
    here = _ask_identity(port, ghidra_request_timeout)
    if here is None:
        return (f"No Ghidra instance answered on port {port}. "
                f"Use list_instances() to see what is running.")
    if here.get("program") is None:
        return (f"The Ghidra instance on port {port} has no program loaded, "
                f"so there is nothing to target.")

    with _instances_lock:
        active_instances[port] = here
        current_target = here
    return f"Now targeting {_describe(here)} on port {port}."


@mcp.tool()
def use_program(name: str) -> str:
    """
    Choose the Ghidra instance by the program it holds, rather than by port.

    The port a game answers on is decided by boot order and changes between
    restarts; the program does not. Give the program name as list_instances()
    reports it.

    Args:
        name: The program name, or a unique part of it.
    """
    global current_target, active_instances

    discovered = _discover_instances(ghidra_request_timeout)
    with _instances_lock:
        active_instances = dict(discovered)

    matches = [i for i in discovered.values() if i.get("program") == name]
    if len(matches) != 1:
        listed = ", ".join(
            f"{p} ({i.get('program') or 'no program'})"
            for p, i in sorted(discovered.items())) or "none"
        if not matches:
            return f"No Ghidra instance is holding '{name}'. Running: {listed}."
        ports = ", ".join(str(i["port"]) for i in sorted(matches, key=lambda x: x["port"]))
        return (f"'{name}' is open on {len(matches)} ports ({ports}); say which "
                f"with use_instance(port).")

    with _instances_lock:
        current_target = dict(matches[0])
    return f"Now targeting {_describe(current_target)} on port {current_target['port']}."


@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def create_function(address: str, name: str = "") -> str:
    """
    Create a function at one or more addresses, disassembling first if needed.

    Auto-analysis leaves code that nothing references statically — jump table
    targets, hand-written assembly, raw memory dumps — as undefined bytes,
    which decompile_function and disassemble_function cannot touch because
    they require an existing function.

    Args:
        address: one address, or several separated by commas
                 (e.g. "0x80028f4c" or "0x80028f4c,0x8002903c")
        name: optional name, applied only when a single address is given

    Returns:
        A per-address report, followed by created/already defined/failed counts.
    """
    return safe_post("create_function", {"address": address, "name": name})

@mcp.tool()
def delete_function(address: str) -> str:
    """
    Delete the function defined at one or more addresses.

    The inverse of create_function. Removes the function definition — entry
    point, body, name, parameters, locals — and leaves the instructions
    disassembled, so the region can be re-defined afterwards.

    Only an address that a function STARTS at is deleted. An address that
    merely sits inside one is reported, naming the function it is inside,
    and that function is left alone.

    Args:
        address: one address, or several separated by commas

    Returns:
        A per-address report, followed by deleted/not present/failed counts.
    """
    return safe_post("delete_function", {"address": address})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def create_struct(name: str, category: str = None, size: int = 0, members: list = None) -> str:
    """
    Create a new structure.
    
    Args:
        name: The name of the new structure.
        category: The category path for the structure (e.g., /my_structs). Defaults to root.
        size: The initial size of the structure.
        members: A list of member dictionaries to add to the new struct.
                 Each dict should have 'name', 'type', and optionally 'offset' and 'comment'.
                 The 'type' should be a builtin C datatype or a structure name defined in Ghidra data type manager.
                 Pointers are specified with asterisk, e.g. void*, int* or PCSTR, PVOID for Windows types
                 Example: [{"name": "field1", "type": "int", "offset": 0, "comment": "my field"}]
                 
    Returns:
        A status message indicating success or failure.
    """
    data = {"name": name, "size": str(size)}
    if category:
        data["category"] = category
    if members:
        data["members"] = json.dumps(members)
    return safe_post("create_struct", data)

@mcp.tool()
def add_struct_members(struct_name: str, members: list, category: str = None) -> str:
    """
    Add a member to an existing structure.
    
    Args:
        struct_name: The name of the structure to modify.
        members: A list of member dictionaries to add to the new struct.
                 Each dict should have 'name', 'type', and optionally 'offset' and 'comment'.
                 The 'type' should be a builtin C datatype or a structure name defined in Ghidra data type manager.
                 Pointers are specified with asterisk, e.g. void*, int* or PCSTR, PVOID for Windows types
                 Example: [{"name": "field1", "type": "int", "offset": 0, "comment": "my field"}]
        category: The category path for the structure. Defaults to root.
        
    Returns:
        A status message indicating success or failure.
    """

    data = {"struct_name": struct_name, "members": json.dumps(members)}
    if category:
        data["category"] = category
    return safe_post("add_struct_members", data)

@mcp.tool()
def clear_struct(struct_name: str, category: str = None) -> str:
    """
    Remove all members from a structure.
    
    Args:
        struct_name: The name of the structure to clear.
        category: The category path for the structure. Defaults to root.
        
    Returns:
        A status message indicating success or failure.
    """
    data = {"struct_name": struct_name}
    if category:
        data["category"] = category
    return safe_post("clear_struct", data)

@mcp.tool()
def get_struct(name: str, category: str = None) -> dict:
    """
    Get a struct's definition.
    
    Args:
        name: The name of the structure.
        category: The category path for the structure. Defaults to root.
        
    Returns:
        A dictionary representing the struct, or an error message.
    """
    params = {"name": name}
    if category:
        params["category"] = category

    response_lines = safe_get("get_struct", params)
    response_str = "\n".join(response_lines)

    try:
        # Attempt to parse the JSON response
        return json.loads(response_str)
    except json.JSONDecodeError:
        # If it's not JSON, it's likely an error message
        return {"error": response_str}

@mcp.tool()
def get_data_by_label(label: str) -> str:
    """
    Get information about a data label.

    Args:
        label: Exact symbol / label name to look up in the program.

    Returns:
        A newline-separated string.  
        Each line has:  "<label> -> <address> : <value-representation>"
        If the label is not found, an explanatory message is returned.
    """
    return "\n".join(safe_get("get_data_by_label", {"label": label}))

@mcp.tool()
def get_bytes(address: str, size: int = 1) -> str:
    """
    Read raw bytes from memory and dump them in hex.

    Args:
        address: Start address in hex notation (e.g. "0x1401003A0").
        size:    Number of bytes to read (default: 1).

    Returns:
        A hexdump-style multiline string.  
        Format: "<address>  <16-byte hex sequence…>".  
        On error (invalid address / size ≤ 0) an error message is returned.
    """
    return "\n".join(safe_get("get_bytes", {"address": address, "size": size}))

@mcp.tool()
def search_bytes(bytes_hex: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search the whole program for a specific byte sequence.

    Args:
        bytes_hex: Byte sequence encoded as a hex string
                   (e.g. "DEADBEEF" or "DE AD BE EF").
        offset:    Pagination offset for results (default: 0).
        limit:     Maximum number of hit addresses to return (default: 100).

    Returns:
        A list of addresses (as hex strings) where the sequence was found,
        subject to pagination.  If no hits, an explanatory message list
        such as ["No matches found"] is returned.
    """
    return safe_get(
        "search_bytes",
        {"bytes": bytes_hex, "offset": offset, "limit": limit},
    )

@mcp.tool()
def create_enum(name: str, category: str = None, size: int = 4, values: list = None) -> str:
    """
    Create a new enum.
    
    Args:
        name: The name of the new enum.
        category: The category path for the enum (e.g., /my_enums). Defaults to root.
        size: The size of the enum in bytes (default: 4).
        values: A list of value dictionaries to add to the new enum.
                Each dict should have 'name', 'value', and optionally 'comment'.
                Example: [{"name": "VALUE1", "value": 0, "comment": "First value"}]
                
    Returns:
        A status message indicating success or failure.
    """
    data = {"name": name, "size": str(size)}
    if category:
        data["category"] = category
    if values:
        data["values"] = json.dumps(values)
    return safe_post("create_enum", data)

@mcp.tool()
def add_enum_values(enum_name: str, values: list, category: str = None) -> str:
    """
    Add values to an existing enum.
    
    Args:
        enum_name: The name of the enum to modify.
        values: A list of value dictionaries to add to the enum.
                Each dict should have 'name', 'value', and optionally 'comment'.
                Example: [{"name": "VALUE1", "value": 0, "comment": "First value"}]
        category: The category path for the enum. Defaults to root.
        
    Returns:
        A status message indicating success or failure.
    """
    data = {"enum_name": enum_name, "values": json.dumps(values)}
    if category:
        data["category"] = category
    return safe_post("add_enum_values", data)

@mcp.tool()
def get_enum(name: str, category: str = None) -> dict:
    """
    Get an enum's definition.
    
    Args:
        name: The name of the enum.
        category: The category path for the enum. Defaults to root.
        
    Returns:
        A dictionary representing the enum, or an error message.
    """
    params = {"name": name}
    if category:
        params["category"] = category

    response_lines = safe_get("get_enum", params)
    response_str = "\n".join(response_lines)

    try:
        # Attempt to parse the JSON response
        return json.loads(response_str)
    except json.JSONDecodeError:
        # If it's not JSON, it's likely an error message
        return {"error": response_str}

@mcp.tool()
def set_global_data_type(address: str, data_type: str, length: int = -1, clear_mode: str = "CHECK_FOR_SPACE") -> str:
    """
    Set the data type of a global variable or data at a specific memory address.
    
    Args:
        address: The memory address in hex format (e.g., "0x401000")
        data_type: The name of the data type to apply (e.g., "int", "char*", "MyStruct")
        length: Optional length for dynamic data types (default: -1, let type determine)
        clear_mode: How to handle conflicting data. Options:
                   - "CHECK_FOR_SPACE": Ensure data fits before clearing (default)
                   - "CLEAR_SINGLE_DATA": Always clear single code unit at address
                   - "CLEAR_ALL_UNDEFINED_CONFLICT_DATA": Clear conflicting undefined data
                   - "CLEAR_ALL_DEFAULT_CONFLICT_DATA": Clear conflicting default data
                   - "CLEAR_ALL_CONFLICT_DATA": Clear all conflicting data
                   
    Returns:
        A status message indicating success or failure.
    """
    data = {
        "address": address,
        "data_type": data_type,
        "clear_mode": clear_mode
    }
    if length > 0:
        data["length"] = str(length)
    
    return safe_post("set_global_data_type", data)

@mcp.tool()
def add_class_members(class_name: str, members: list, parent_namespace: str = None) -> str:
    """
    Add members to an existing C++ class.
    
    Args:
        class_name: The name of the class to modify.
        members: A list of member dictionaries to add to the class.
                Each dict should have 'name', 'type', and optionally 'offset' and 'comment'.
                Example: [{"name": "health", "type": "float", "comment": "Player health"}]
        parent_namespace: The parent namespace where the class is located (optional).
                
    Returns:
        A status message indicating success or failure.
    """
    params = {"class_name": class_name, "members": json.dumps(members)}
    if parent_namespace:
        params["parent_namespace"] = parent_namespace

    return safe_post("add_class_members", params)

@mcp.tool()
def remove_class_members(class_name: str, members: list, parent_namespace: str = None) -> str:
    """
    Remove members from an existing C++ class.
    
    Args:
        class_name: The name of the class to modify.
        members: A list of member names to remove from the class.
                Example: ["old_member", "unused_field"]
        parent_namespace: The parent namespace where the class is located (optional).
                
    Returns:
        A status message indicating success or failure.
    """
    params = {"class_name": class_name, "members": json.dumps(members)}
    if parent_namespace:
        params["parent_namespace"] = parent_namespace

    return safe_post("remove_class_members", params)

@mcp.tool()
def remove_enum_values(enum_name: str, values: list, category: str = None) -> str:
    """
    Remove values from an existing enum.
    
    Args:
        enum_name: The name of the enum to modify.
        values: A list of value names to remove from the enum.
                Example: ["OLD_VALUE", "DEPRECATED_OPTION"]
        category: The category path for the enum (optional, defaults to root).
                
    Returns:
        A status message indicating success or failure.
    """
    params = {"enum_name": enum_name, "values": json.dumps(values)}
    if category:
        params["category"] = category

    return safe_post("remove_enum_values", params)

@mcp.tool()
def remove_struct_members(struct_name: str, members: list, category: str = None) -> str:
    """
    Remove members from an existing struct.
    
    Args:
        struct_name: The name of the struct to modify.
        members: A list of member names to remove from the struct.
                Example: ["old_field", "unused_member"]
        category: The category path for the struct (optional, defaults to root).
                
    Returns:
        A status message indicating success or failure.
    """
    params = {"struct_name": struct_name, "members": json.dumps(members)}
    if category:
        params["category"] = category

    return safe_post("remove_struct_members", params)

@mcp.tool()
def set_bytes(address: str, bytes_hex: str) -> str:
    """
    Writes a sequence of bytes to the specified address in the program's memory.

    Args:
        address: Destination address (e.g., "0x140001000")
        bytes_hex: Sequence of space-separated bytes in hexadecimal format (e.g., "90 90 90 90")

    Returns:
        Result of the operation (e.g., "Bytes written successfully" or a detailed error)
    """
    return safe_post("set_bytes", {"address": address, "bytes": bytes_hex})

@mcp.tool()
def add_bookmark(address: str, category: str, comment: str, type: str = "Note") -> str:
    """
    Creates a bookmark at the specified address.

    Args:
        address: The address to create the bookmark at.
        category: The category of the bookmark.
        comment: The comment for the bookmark.
        type: The type of the bookmark. Defaults to "Note".
              Available types are: "Note", "Info", "Warning", "Error", "Analysis".

    Returns:
        A string indicating the result of the operation.
    NOTE: if a bookmark of the same type already exists at the address, it will be replaced.
    """
    # Request JSON-formatted response for consistency with other tools
    return safe_post("add_bookmark", {"address": address, "category": category, "comment": comment, "type": type, "format": "json"})

@mcp.tool()
def get_callee(address: str) -> list:
    """
    Get the functions called by the function at the specified address.
    
    Args:
        address: The address within the function.
        
    Returns:
        A list of called functions.
    """
    lines = safe_get("get_callee", {"address": address})
    # Try to parse JSON array if the bridge returned structured output
    try:
        body = "\n".join(lines).strip()
        if body.startswith("[") and body.endswith("]"):
            parsed = json.loads(body)
            if isinstance(parsed, list):
                return parsed
    except Exception:
        pass
    return lines

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=None,
                        help="Pin this bridge to the Ghidra instance at this URL, "
                             "by the program it holds. There is no default: with "
                             "no pin, a session says which program it means with "
                             "use_program() or use_instance().")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse/streamable-http), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse/streamable-http), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse", "streamable-http", "streamable_http"],
                        help="Transport protocol for MCP, default: stdio (sse is deprecated; use streamable-http)")
    parser.add_argument("--ghidra-timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                        help=f"MCP requests timeout, default: {DEFAULT_REQUEST_TIMEOUT}")
    parser.add_argument("--discovery-base-port", type=int, default=DEFAULT_DISCOVERY_BASE_PORT,
                        help=f"Base port for multi-instance discovery (default: {DEFAULT_DISCOVERY_BASE_PORT})")
    parser.add_argument("--discovery-range", type=int, default=DEFAULT_DISCOVERY_RANGE,
                        help=f"Number of ports to scan from base port (default: {DEFAULT_DISCOVERY_RANGE})")
    args = parser.parse_args()

    global ghidra_request_timeout
    global _discovery_base_port, _discovery_port_range

    if args.ghidra_timeout:
        ghidra_request_timeout = args.ghidra_timeout

    _discovery_base_port = args.discovery_base_port
    _discovery_port_range = args.discovery_range

    # No auto-selection and no background thread. Both were ways of choosing on
    # the caller's behalf, and the only thing either had to choose with was boot
    # order. A session says which program it means, once.
    if args.ghidra_server:
        logger.info("%s", _pin_to(args.ghidra_server))

    transport = args.transport.replace("_", "-")
    if transport in ("sse", "streamable-http"):
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # mcp 2.x: transport settings are arguments to run(), not fields
            # of mcp.settings.
            host = args.mcp_host or "127.0.0.1"
            port = args.mcp_port or 8081

            if transport == "sse":
                logger.warning("SSE transport is deprecated in MCP; prefer streamable-http.")
                logger.info("Starting MCP server on http://%s:%s/sse", host, port)
            else:
                logger.info("Starting MCP server on http://%s:%s/mcp", host, port)
            logger.info(f"Using transport: {transport}")

            mcp.run(transport=transport, host=host, port=port)
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()
