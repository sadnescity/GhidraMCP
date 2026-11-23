package com.lauriewired.tools;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.TreeSet;

import com.lauriewired.core.Ctx;
import com.lauriewired.core.Fmt;
import com.lauriewired.core.P;
import com.lauriewired.core.Page;
import com.lauriewired.core.Tool;
import com.lauriewired.core.ToolError;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

/** Paged inventories of the program. Every list ends with a footer when there is more. */
public final class ListTools {

	private static final String OFFSET = "Index of the first item to return (pagination)";
	private static final String LIMIT = "Maximum number of items to return";

	@Tool(name = "list_functions", description = "List functions as 'name @ address', in address order, "
			+ "optionally filtered by a case-insensitive substring of the name. Paged: a footer gives the "
			+ "total and the next offset.")
	public String listFunctions(Ctx ctx,
			@P(value = "offset", def = "0", description = OFFSET) int offset,
			@P(value = "limit", def = "1000", description = LIMIT) int limit,
			@P(value = "filter", def = P.NULL, description = "Case-insensitive substring of the name") String filter) {
		String needle = needle(filter);
		Page page = new Page(offset, limit);
		for (Function f : ctx.program().getFunctionManager().getFunctions(true)) {
			if (needle == null || f.getName(true).toLowerCase(Locale.ROOT).contains(needle)) {
				page.offer(() -> Fmt.fn(f));
			}
		}
		return page.render(needle == null ? "No functions" : "No function name contains '" + filter + "'");
	}

	@Tool(name = "list_methods", description = "List function names only, in address order (paged). "
			+ "list_functions also gives addresses.")
	public String listMethods(Ctx ctx,
			@P(value = "offset", def = "0", description = OFFSET) int offset,
			@P(value = "limit", def = "100", description = LIMIT) int limit) {
		Page page = new Page(offset, limit);
		for (Function f : ctx.program().getFunctionManager().getFunctions(true)) {
			page.offer(() -> f.getName(true));
		}
		return page.render("No functions");
	}

	@Tool(name = "search_functions_by_name", description = "Find functions whose name contains a "
			+ "substring (case-insensitive), as 'name @ address'.")
	public String searchFunctionsByName(Ctx ctx,
			@P(value = "query", description = "Substring to look for") String query,
			@P(value = "offset", def = "0", description = OFFSET) int offset,
			@P(value = "limit", def = "100", description = LIMIT) int limit) {
		if (query == null || query.isBlank()) {
			throw ToolError.missing("query");
		}
		return listFunctions(ctx, offset, limit, query);
	}

	@Tool(name = "list_classes", description = "List class namespaces (fully qualified), paged.")
	public String listClasses(Ctx ctx,
			@P(value = "offset", def = "0", description = OFFSET) int offset,
			@P(value = "limit", def = "100", description = LIMIT) int limit) {
		TreeSet<String> names = new TreeSet<>();
		Iterator<ghidra.program.model.listing.GhidraClass> it = ctx.program().getSymbolTable().getClassNamespaces();
		while (it.hasNext()) {
			names.add(it.next().getName(true));
		}
		return page(names, offset, limit, "No classes");
	}

	@Tool(name = "list_namespaces", description = "List non-global namespaces (fully qualified), paged.")
	public String listNamespaces(Ctx ctx,
			@P(value = "offset", def = "0", description = OFFSET) int offset,
			@P(value = "limit", def = "100", description = LIMIT) int limit) {
		TreeSet<String> names = new TreeSet<>();
		SymbolTable st = ctx.program().getSymbolTable();
		for (Symbol s : st.getAllSymbols(true)) {
			if (s.getSymbolType() == SymbolType.NAMESPACE || s.getSymbolType() == SymbolType.CLASS
					|| s.getSymbolType() == SymbolType.LIBRARY) {
				names.add(((Namespace) s.getObject()).getName(true));
			}
		}
		return page(names, offset, limit, "No namespaces");
	}

	@Tool(name = "list_segments", description = "List memory blocks: name, range, size, permissions "
			+ "(r/w/x, v=volatile), initialized or not, overlay or not.")
	public String listSegments(Ctx ctx,
			@P(value = "offset", def = "0", description = OFFSET) int offset,
			@P(value = "limit", def = "100", description = LIMIT) int limit) {
		Page page = new Page(offset, limit);
		for (MemoryBlock b : ctx.program().getMemory().getBlocks()) {
			page.offer(() -> b.getName() + " " + Fmt.addr(b.getStart()) + "-" + Fmt.addr(b.getEnd())
					+ String.format(" 0x%x", b.getSize()) + " " + ProgramTools.perms(b)
					+ (b.isInitialized() ? "" : " uninitialized") + (b.isOverlay() ? " overlay" : ""));
		}
		return page.render("No memory blocks");
	}

	@Tool(name = "list_imports", description = "List imported (external) symbols with their library.")
	public String listImports(Ctx ctx,
			@P(value = "offset", def = "0", description = OFFSET) int offset,
			@P(value = "limit", def = "100", description = LIMIT) int limit) {
		Page page = new Page(offset, limit);
		for (Symbol s : ctx.program().getSymbolTable().getExternalSymbols()) {
			page.offer(() -> s.getName() + " (" + s.getParentNamespace().getName(true) + ")");
		}
		return page.render("No imports");
	}

	@Tool(name = "list_exports", description = "List exported symbols / entry points as 'name @ address'.")
	public String listExports(Ctx ctx,
			@P(value = "offset", def = "0", description = OFFSET) int offset,
			@P(value = "limit", def = "100", description = LIMIT) int limit) {
		Program p = ctx.program();
		Page page = new Page(offset, limit);
		AddressIterator it = p.getSymbolTable().getExternalEntryPointIterator();
		while (it.hasNext()) {
			Address a = it.next();
			page.offer(() -> {
				String l = Fmt.label(p, a);
				return (l != null ? l : "(unnamed)") + " @ " + Fmt.addr(a);
			});
		}
		return page.render("No exports");
	}

	@Tool(name = "list_data_items", description = "List defined data: address, label, type, value.")
	public String listDataItems(Ctx ctx,
			@P(value = "offset", def = "0", description = OFFSET) int offset,
			@P(value = "limit", def = "100", description = LIMIT) int limit) {
		Page page = new Page(offset, limit);
		DataIterator it = ctx.program().getListing().getDefinedData(true);
		while (it.hasNext()) {
			Data d = it.next();
			page.offer(() -> dataLine(d));
		}
		return page.render("No defined data");
	}

	static String dataLine(Data d) {
		String label = d.getLabel();
		String value = d.getDefaultValueRepresentation();
		if (value != null && value.length() > 120) {
			value = value.substring(0, 117) + "...";
		}
		return Fmt.addr(d.getAddress()) + "  " + (label != null ? label : "(unnamed)") + "  "
				+ d.getDataType().getDisplayName() + "  " + Fmt.oneLine(value);
	}

	@Tool(name = "list_strings", description = "List defined strings as 'address: \"text\"', optionally "
			+ "filtered by a case-insensitive substring of the text.")
	public String listStrings(Ctx ctx,
			@P(value = "offset", def = "0", description = OFFSET) int offset,
			@P(value = "limit", def = "2000", description = LIMIT) int limit,
			@P(value = "filter", def = P.NULL, description = "Case-insensitive substring of the text") String filter) {
		String needle = needle(filter);
		Page page = new Page(offset, limit);
		DataIterator it = ctx.program().getListing().getDefinedData(true);
		while (it.hasNext()) {
			Data d = it.next();
			if (!d.hasStringValue()) {
				continue;
			}
			Object v = d.getValue();
			String s = v == null ? "" : v.toString();
			if (needle == null || s.toLowerCase(Locale.ROOT).contains(needle)) {
				page.offer(() -> Fmt.addr(d.getAddress()) + ": \"" + escape(s) + "\"");
			}
		}
		return page.render(needle == null ? "No defined strings" : "No string contains '" + filter + "'");
	}

	static String escape(String s) {
		StringBuilder sb = new StringBuilder();
		for (char c : s.toCharArray()) {
			switch (c) {
				case '\n' -> sb.append("\\n");
				case '\r' -> sb.append("\\r");
				case '\t' -> sb.append("\\t");
				case '"' -> sb.append("\\\"");
				case '\\' -> sb.append("\\\\");
				default -> {
					if (c < 0x20 || c == 0x7f) {
						sb.append(String.format("\\x%02x", (int) c));
					}
					else {
						sb.append(c);
					}
				}
			}
		}
		return sb.toString();
	}

	static String needle(String filter) {
		return filter == null || filter.isBlank() ? null : filter.toLowerCase(Locale.ROOT);
	}

	static String page(Iterable<String> items, int offset, int limit, String empty) {
		Page page = new Page(offset, limit);
		for (String s : items) {
			page.add(s);
		}
		return page.render(empty);
	}

	static List<String> list(Iterable<String> it) {
		List<String> l = new ArrayList<>();
		it.forEach(l::add);
		return l;
	}
}
