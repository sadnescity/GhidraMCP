package com.lauriewired.tools;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.lauriewired.core.Ctx;
import com.lauriewired.core.Fmt;
import com.lauriewired.core.P;
import com.lauriewired.core.Tool;
import com.lauriewired.core.ToolError;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

/** Labels, data names and bookmarks. */
public final class SymbolTools {

	@Tool(name = "rename_data", readOnly = false, description = "Name the data (or any location) at an "
			+ "address: renames its primary label, or creates one if it has none. Typically used for "
			+ "globals such as 'g_gold'.")
	public String renameData(Ctx ctx,
			@P(value = "address", description = "Address") String address,
			@P(value = "new_name", description = "New name") String newName) {
		Program p = ctx.program();
		Address a = ctx.addr(address);
		if (newName == null || newName.isBlank()) {
			throw ToolError.missing("new_name");
		}
		if (p.getMemory().getBlock(a) == null) {
			throw ToolError.notFound(Fmt.addr(a) + " is not in any memory block");
		}
		String[] old = new String[1];
		ctx.write("Rename Data", () -> {
			SymbolTable st = p.getSymbolTable();
			Symbol s = st.getPrimarySymbol(a);
			if (s != null && s.getSymbolType() == SymbolType.FUNCTION) {
				throw ToolError.conflict(Fmt.addr(a) + " is the entry of function " + s.getName()
						+ "; use rename_function_by_address");
			}
			if (s != null) {
				old[0] = s.getName();
				s.setName(newName.trim(), SourceType.USER_DEFINED);
			}
			else {
				st.createLabel(a, newName.trim(), SourceType.USER_DEFINED);
			}
			return null;
		});
		return (old[0] != null ? "Renamed " + old[0] + " to " : "Labelled as ") + newName.trim() + " at "
				+ Fmt.addr(a);
	}

	@Tool(name = "create_label", readOnly = false, description = "Create labels (extra names at addresses, "
			+ "e.g. jump targets or table entries). One: address+name. Many in one transaction: labels="
			+ "[{address, name}, ...]. The new label becomes primary when make_primary is true.")
	public String createLabel(Ctx ctx,
			@P(value = "address", def = P.NULL, description = "Address (single label)") String address,
			@P(value = "name", def = P.NULL, description = "Label name (single label)") String name,
			@P(value = "labels", def = P.NULL, description = "List of {address, name} for several labels") JsonArray labels,
			@P(value = "make_primary", def = "true", description = "Make the new label the primary name") boolean makePrimary) {
		Program p = ctx.program();
		record L(Address a, String n) {
		}
		List<L> list = new ArrayList<>();
		if (labels != null) {
			for (JsonElement e : labels) {
				JsonObject o = e.getAsJsonObject();
				if (!o.has("address") || !o.has("name")) {
					throw ToolError.invalid("Each label needs address and name");
				}
				list.add(new L(ctx.addr(o.get("address").getAsString()), o.get("name").getAsString().trim()));
			}
		}
		else {
			if (address == null || name == null) {
				throw ToolError.missing("address and name (or labels)");
			}
			list.add(new L(ctx.addr(address), name.trim()));
		}
		ctx.write("Create Label", () -> {
			SymbolTable st = p.getSymbolTable();
			for (L l : list) {
				Symbol s = st.createLabel(l.a, l.n, SourceType.USER_DEFINED);
				if (makePrimary && !s.isPrimary()) {
					s.setPrimary();
				}
			}
			return null;
		});
		return list.size() == 1 ? "Created label " + list.get(0).n + " at " + Fmt.addr(list.get(0).a)
				: "Created " + list.size() + " labels";
	}

	@Tool(name = "delete_label", readOnly = false, description = "Delete a label at an address by name "
			+ "(function names are not labels: use delete_function).")
	public String deleteLabel(Ctx ctx,
			@P(value = "address", description = "Address") String address,
			@P(value = "name", description = "Label name") String name) {
		Program p = ctx.program();
		Address a = ctx.addr(address);
		ctx.write("Delete Label", () -> {
			Symbol s = p.getSymbolTable().getSymbol(name, a, null);
			if (s == null) {
				for (Symbol c : p.getSymbolTable().getSymbols(a)) {
					if (c.getName().equals(name)) {
						s = c;
					}
				}
			}
			if (s == null || s.getSymbolType() != SymbolType.LABEL) {
				throw ToolError.notFound("No label '" + name + "' at " + Fmt.addr(a));
			}
			s.delete();
			return null;
		});
		return "Deleted label " + name + " at " + Fmt.addr(a);
	}

	@Tool(name = "get_data_by_label", description = "Look up a label: '<label> -> <address> : <type> <value>' "
			+ "for each place it names.")
	public String getDataByLabel(Ctx ctx, @P(value = "label", description = "Exact label name") String label) {
		Program p = ctx.program();
		SymbolIterator it = p.getSymbolTable().getSymbols(label);
		StringBuilder sb = new StringBuilder();
		while (it.hasNext()) {
			Symbol s = it.next();
			Address a = s.getAddress();
			Data d = p.getListing().getDataAt(a);
			sb.append(s.getName(true)).append(" -> ").append(Fmt.addr(a)).append(" : ");
			if (d != null && d.isDefined()) {
				sb.append(d.getDataType().getDisplayName()).append(' ').append(Fmt.oneLine(d.getDefaultValueRepresentation()));
			}
			else if (p.getFunctionManager().getFunctionAt(a) != null) {
				sb.append("function");
			}
			else {
				sb.append("(no data defined)");
			}
			sb.append('\n');
		}
		if (sb.length() == 0) {
			throw ToolError.notFound("No label named '" + label + "'");
		}
		return sb.toString().stripTrailing();
	}

	@Tool(name = "add_bookmark", readOnly = false, description = "Create a bookmark at an address (replacing one "
			+ "of the same type and category there).")
	public String addBookmark(Ctx ctx,
			@P(value = "address", description = "Address") String address,
			@P(value = "category", description = "Bookmark category") String category,
			@P(value = "comment", description = "Bookmark text") String comment,
			@P(value = "type", def = "Note", oneOf = { "Note", "Info", "Warning", "Error", "Analysis" },
					description = "Bookmark type") String type) {
		Program p = ctx.program();
		Address a = ctx.addr(address);
		String t = switch (type.toLowerCase()) {
			case "info" -> BookmarkType.INFO;
			case "warning" -> BookmarkType.WARNING;
			case "error" -> BookmarkType.ERROR;
			case "analysis" -> BookmarkType.ANALYSIS;
			default -> BookmarkType.NOTE;
		};
		ctx.write("Add Bookmark", () -> {
			BookmarkManager bm = p.getBookmarkManager();
			Bookmark b = bm.getBookmark(a, t, category);
			if (b != null) {
				bm.removeBookmark(b);
			}
			bm.setBookmark(a, t, category, comment);
			return null;
		});
		return "Bookmark " + t + "/" + category + " at " + Fmt.addr(a);
	}

	@Tool(name = "list_bookmarks", description = "List bookmarks: 'address type/category: comment', "
			+ "optionally only one type.")
	public String listBookmarks(Ctx ctx,
			@P(value = "type", def = P.NULL, description = "Only this type (Note, Info, Warning, Error, Analysis)") String type,
			@P(value = "offset", def = "0", description = "Pagination offset") int offset,
			@P(value = "limit", def = "200", description = "Pagination limit") int limit) {
		Program p = ctx.program();
		com.lauriewired.core.Page page = new com.lauriewired.core.Page(offset, limit);
		var it = type == null ? p.getBookmarkManager().getBookmarksIterator()
				: p.getBookmarkManager().getBookmarksIterator(type);
		while (it.hasNext()) {
			Bookmark b = it.next();
			page.offer(() -> Fmt.addr(b.getAddress()) + " " + b.getTypeString() + "/" + b.getCategory() + ": "
					+ Fmt.oneLine(b.getComment()));
		}
		return page.render("No bookmarks");
	}
}
