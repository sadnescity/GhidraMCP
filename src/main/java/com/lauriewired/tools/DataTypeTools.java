package com.lauriewired.tools;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.lauriewired.core.Ctx;
import com.lauriewired.core.Fmt;
import com.lauriewired.core.P;
import com.lauriewired.core.Page;
import com.lauriewired.core.Tool;
import com.lauriewired.core.ToolError;
import com.lauriewired.core.ToolRegistry;
import com.lauriewired.core.Types;

import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.Dynamic;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

/** Structures, unions, enums, typedefs, and applying types to memory. */
public final class DataTypeTools {

	private static final String MEMBERS = "List of {\"name\", \"type\" (C type, e.g. \"short\", \"Actor *\", "
			+ "\"char[16]\"), \"offset\"? (byte offset; omit to append), \"comment\"?}. Every type must already "
			+ "exist: unknown types are an error, never guessed.";
	private static final String CATEGORY = "Category path, e.g. /game. Omit for the root (lookups then "
			+ "search every category).";

	// ---------------------------------------------------------------------
	// Structures
	// ---------------------------------------------------------------------

	@Tool(name = "create_struct", readOnly = false, description = "Create a structure, optionally with its "
			+ "members. With size > 0 the struct starts as that many undefined bytes and members with an "
			+ "offset fill them in place.")
	public String createStruct(Ctx ctx,
			@P(value = "name", description = "Struct name") String name,
			@P(value = "category", def = P.NULL, description = CATEGORY) String category,
			@P(value = "size", def = "0", description = "Initial size in bytes (0 = grow as members are added)") int size,
			@P(value = "members", def = P.NULL, description = MEMBERS) JsonArray members) {
		DataTypeManager dtm = ctx.program().getDataTypeManager();
		CategoryPath path = cat(category);
		if (dtm.getDataType(path, name) != null) {
			throw ToolError.conflict("A type named " + name + " already exists in " + path
					+ " (use add_struct_members, or delete_data_type first)");
		}
		List<Members.Member> ms = Members.parse(ctx, members);
		Structure s = ctx.write("Create Struct", () -> {
			StructureDataType sdt = new StructureDataType(path, name, size, dtm);
			for (Members.Member m : ms) {
				Members.place(sdt, m);
			}
			return (Structure) dtm.addDataType(sdt, DataTypeConflictHandler.REPLACE_HANDLER);
		});
		return "Created\n" + Members.render(s);
	}

	@Tool(name = "add_struct_members", readOnly = false, description = "Add members to an existing structure "
			+ "(in one transaction). Members with an offset fill undefined bytes there; others are appended.")
	public String addStructMembers(Ctx ctx,
			@P(value = "struct_name", description = "Struct name") String structName,
			@P(value = "members", description = MEMBERS) JsonArray members,
			@P(value = "category", def = P.NULL, description = CATEGORY) String category) {
		Structure s = struct(ctx, structName, category);
		List<Members.Member> ms = Members.parse(ctx, members);
		ctx.write("Add Struct Members", () -> {
			for (Members.Member m : ms) {
				Members.place(s, m);
			}
			return null;
		});
		return "Added " + ms.size() + " members\n" + Members.render(s);
	}

	@Tool(name = "remove_struct_members", readOnly = false, description = "Remove members from a structure by "
			+ "name. Their bytes become undefined; later fields keep their offsets.")
	public String removeStructMembers(Ctx ctx,
			@P(value = "struct_name", description = "Struct name") String structName,
			@P(value = "members", description = "List of member names") JsonArray members,
			@P(value = "category", def = P.NULL, description = CATEGORY) String category) {
		Structure s = struct(ctx, structName, category);
		List<String> names = strings(members);
		List<String> missing = new ArrayList<>(names);
		ctx.write("Remove Struct Members", () -> {
			for (String n : names) {
				for (DataTypeComponent dc : s.getDefinedComponents()) {
					if (n.equals(dc.getFieldName())) {
						s.clearAtOffset(dc.getOffset());
						missing.remove(n);
						break;
					}
				}
			}
			if (missing.size() == names.size()) {
				throw ToolError.notFound("None of " + names + " is a member of " + s.getName());
			}
			return null;
		});
		return "Removed " + (names.size() - missing.size()) + " members"
				+ (missing.isEmpty() ? "" : " (not found: " + String.join(", ", missing) + ")") + "\n" + Members.render(s);
	}

	@Tool(name = "clear_struct", readOnly = false, description = "Remove every member of a structure, "
			+ "keeping its name (and size 0).")
	public String clearStruct(Ctx ctx,
			@P(value = "struct_name", description = "Struct name") String structName,
			@P(value = "category", def = P.NULL, description = CATEGORY) String category) {
		Structure s = struct(ctx, structName, category);
		ctx.write("Clear Struct", () -> {
			s.deleteAll();
			return null;
		});
		return "Cleared " + s.getPathName();
	}

	@Tool(name = "modify_struct_field", readOnly = false, description = "Change one field of a structure or "
			+ "union in place: rename it, retype it (at the same offset; a larger type takes undefined bytes "
			+ "after it, and fails if a defined field is in the way), and/or set its comment.")
	public String modifyStructField(Ctx ctx,
			@P(value = "struct_name", description = "Struct or union name") String structName,
			@P(value = "field", description = "Current field name, or its offset as 0x..") String field,
			@P(value = "new_name", def = P.NULL, description = "New field name") String newName,
			@P(value = "new_type", def = P.NULL, description = "New C type") String newType,
			@P(value = "comment", def = P.NULL, description = "New comment (empty string clears it)") String comment,
			@P(value = "category", def = P.NULL, description = CATEGORY) String category) {
		Composite c = composite(ctx, structName, category);
		DataTypeComponent dc = component(c, field);
		DataType dt = newType == null ? null : ctx.type(newType);
		if (newName == null && dt == null && comment == null) {
			throw ToolError.invalid("Give new_name, new_type and/or comment");
		}
		ctx.write("Modify Struct Field", () -> {
			DataTypeComponent cur = dc;
			if (dt != null) {
				String keepName = cur.getFieldName();
				String keepComment = cur.getComment();
				if (c instanceof Structure s) {
					int off = cur.getOffset();
					int len = dt.getLength();
					int end = off + len;
					for (DataTypeComponent o : s.getDefinedComponents()) {
						if (o.getOffset() > off && o.getOffset() < end) {
							throw ToolError.conflict("Type " + dt.getDisplayName() + " (" + len + " bytes) at 0x"
									+ Integer.toHexString(off) + " would overlap field '" + o.getFieldName() + "' at 0x"
									+ Integer.toHexString(o.getOffset()));
						}
					}
					if (end > s.getLength()) {
						s.growStructure(end - s.getLength());
					}
					s.clearAtOffset(off);
					cur = s.replaceAtOffset(off, dt, len, keepName, keepComment);
				}
				else {
					Union u = (Union) c;
					int ord = cur.getOrdinal();
					u.delete(ord);
					cur = u.insert(ord, dt, dt.getLength(), keepName, keepComment);
				}
			}
			if (newName != null) {
				cur.setFieldName(newName.trim());
			}
			if (comment != null) {
				cur.setComment(comment.isBlank() ? null : comment);
			}
			return null;
		});
		return Members.render(c);
	}

	@Tool(name = "get_struct", description = "Show a structure (or union) as C, with every field's offset, "
			+ "type, name and comment, and the undefined gaps between them.")
	public String getStruct(Ctx ctx,
			@P(value = "name", description = "Struct name") String name,
			@P(value = "category", def = P.NULL, description = CATEGORY) String category) {
		return Members.render(composite(ctx, name, category));
	}

	@Tool(name = "create_union", readOnly = false, description = "Create a union with its members.")
	public String createUnion(Ctx ctx,
			@P(value = "name", description = "Union name") String name,
			@P(value = "members", description = "List of {name, type, comment?}") JsonArray members,
			@P(value = "category", def = P.NULL, description = CATEGORY) String category) {
		DataTypeManager dtm = ctx.program().getDataTypeManager();
		CategoryPath path = cat(category);
		if (dtm.getDataType(path, name) != null) {
			throw ToolError.conflict("A type named " + name + " already exists in " + path);
		}
		List<Members.Member> ms = Members.parse(ctx, members);
		Union u = ctx.write("Create Union", () -> {
			UnionDataType udt = new UnionDataType(path, name, dtm);
			for (Members.Member m : ms) {
				Members.place(udt, m);
			}
			return (Union) dtm.addDataType(udt, DataTypeConflictHandler.REPLACE_HANDLER);
		});
		return "Created\n" + Members.render(u);
	}

	// ---------------------------------------------------------------------
	// Enums
	// ---------------------------------------------------------------------

	private static final String VALUES = "List of {\"name\", \"value\" (number or \"0x..\" string), \"comment\"?}";

	@Tool(name = "create_enum", readOnly = false, description = "Create an enum, optionally with values.")
	public String createEnum(Ctx ctx,
			@P(value = "name", description = "Enum name") String name,
			@P(value = "category", def = P.NULL, description = CATEGORY) String category,
			@P(value = "size", def = "4", description = "Size in bytes: 1, 2, 4 or 8") int size,
			@P(value = "values", def = P.NULL, description = VALUES) JsonArray values) {
		if (size != 1 && size != 2 && size != 4 && size != 8) {
			throw ToolError.invalid("size must be 1, 2, 4 or 8");
		}
		DataTypeManager dtm = ctx.program().getDataTypeManager();
		CategoryPath path = cat(category);
		if (dtm.getDataType(path, name) != null) {
			throw ToolError.conflict("A type named " + name + " already exists in " + path);
		}
		List<Object[]> vs = enumValues(values);
		Enum e = ctx.write("Create Enum", () -> {
			EnumDataType edt = new EnumDataType(path, name, size, dtm);
			for (Object[] v : vs) {
				edt.add((String) v[0], (Long) v[1], (String) v[2]);
			}
			return (Enum) dtm.addDataType(edt, DataTypeConflictHandler.REPLACE_HANDLER);
		});
		return "Created\n" + renderEnum(e);
	}

	@Tool(name = "add_enum_values", readOnly = false, description = "Add values to an existing enum.")
	public String addEnumValues(Ctx ctx,
			@P(value = "enum_name", description = "Enum name") String enumName,
			@P(value = "values", description = VALUES) JsonArray values,
			@P(value = "category", def = P.NULL, description = CATEGORY) String category) {
		Enum e = enumType(ctx, enumName, category);
		List<Object[]> vs = enumValues(values);
		ctx.write("Add Enum Values", () -> {
			for (Object[] v : vs) {
				if (e.contains((String) v[0])) {
					throw ToolError.conflict(e.getName() + " already has a value named " + v[0]);
				}
				e.add((String) v[0], (Long) v[1], (String) v[2]);
			}
			return null;
		});
		return renderEnum(e);
	}

	@Tool(name = "remove_enum_values", readOnly = false, description = "Remove values from an enum by name.")
	public String removeEnumValues(Ctx ctx,
			@P(value = "enum_name", description = "Enum name") String enumName,
			@P(value = "values", description = "List of value names") JsonArray values,
			@P(value = "category", def = P.NULL, description = CATEGORY) String category) {
		Enum e = enumType(ctx, enumName, category);
		List<String> names = strings(values);
		List<String> missing = new ArrayList<>();
		ctx.write("Remove Enum Values", () -> {
			for (String n : names) {
				if (e.contains(n)) {
					e.remove(n);
				}
				else {
					missing.add(n);
				}
			}
			if (missing.size() == names.size()) {
				throw ToolError.notFound("None of " + names + " is in " + e.getName());
			}
			return null;
		});
		return (missing.isEmpty() ? "" : "Not found: " + String.join(", ", missing) + "\n") + renderEnum(e);
	}

	@Tool(name = "get_enum", description = "Show an enum: its values (hex and decimal) and comments.")
	public String getEnum(Ctx ctx,
			@P(value = "name", description = "Enum name") String name,
			@P(value = "category", def = P.NULL, description = CATEGORY) String category) {
		return renderEnum(enumType(ctx, name, category));
	}

	private static String renderEnum(Enum e) {
		StringBuilder sb = new StringBuilder("enum ").append(e.getName()).append("  // ")
				.append(e.getCategoryPath().getPath()).append(", size ").append(e.getLength()).append("\n{\n");
		long[] vals = e.getValues();
		java.util.Arrays.sort(vals);
		for (long v : vals) {
			for (String n : e.getNames()) {
				if (e.getValue(n) == v) {
					sb.append("  ").append(n).append(" = 0x").append(Long.toHexString(v)).append(" (").append(v).append(')');
					String c = e.getComment(n);
					if (c != null && !c.isBlank()) {
						sb.append("  // ").append(Fmt.oneLine(c));
					}
					sb.append('\n');
				}
			}
		}
		return sb.append('}').toString();
	}

	private static List<Object[]> enumValues(JsonArray values) {
		List<Object[]> out = new ArrayList<>();
		if (values == null) {
			return out;
		}
		for (JsonElement el : values) {
			JsonObject o = el.getAsJsonObject();
			if (!o.has("name") || !o.has("value")) {
				throw ToolError.invalid("Each enum value needs name and value");
			}
			JsonElement v = o.get("value");
			long val = v.getAsJsonPrimitive().isString() ? ToolRegistry.parseLong(v.getAsString()) : v.getAsLong();
			String comment = o.has("comment") && !o.get("comment").isJsonNull() ? o.get("comment").getAsString() : null;
			out.add(new Object[] { o.get("name").getAsString(), val, comment });
		}
		return out;
	}

	// ---------------------------------------------------------------------
	// Any type
	// ---------------------------------------------------------------------

	@Tool(name = "create_typedef", readOnly = false, description = "Create a typedef: a new name for an "
			+ "existing type, e.g. name='ActorPtr' base_type='Actor *'.")
	public String createTypedef(Ctx ctx,
			@P(value = "name", description = "New type name") String name,
			@P(value = "base_type", description = "Existing C type") String baseType,
			@P(value = "category", def = P.NULL, description = CATEGORY) String category) {
		DataTypeManager dtm = ctx.program().getDataTypeManager();
		CategoryPath path = cat(category);
		if (dtm.getDataType(path, name) != null) {
			throw ToolError.conflict("A type named " + name + " already exists in " + path);
		}
		DataType base = ctx.type(baseType);
		DataType t = ctx.write("Create Typedef", () -> dtm.addDataType(new TypedefDataType(path, name, base, dtm),
				DataTypeConflictHandler.REPLACE_HANDLER));
		return "Created typedef " + t.getPathName() + " = " + base.getDisplayName();
	}

	@Tool(name = "import_c_types", readOnly = false, description = "Parse C declarations (structs, unions, "
			+ "enums, typedefs, function pointer typedefs) with Ghidra's C parser and add them to the "
			+ "program. The fastest way to define many types, or types that refer to each other. Pass the "
			+ "source TEXT, not a path. Reports the types added or changed and any parser messages.")
	public String importCTypes(Ctx ctx,
			@P(value = "source", description = "C source text") String source) {
		if (source == null || source.isBlank()) {
			throw ToolError.missing("source");
		}
		Program p = ctx.program();
		DataTypeManager dtm = p.getDataTypeManager();
		Set<String> before = new HashSet<>();
		dtm.getAllDataTypes().forEachRemaining(d -> before.add(d.getPathName()));
		String[] messages = new String[1];
		ctx.write("Import C Types", () -> {
			CParser parser = new CParser(dtm, true, new DataTypeManager[] { dtm });
			try {
				parser.parse(source);
			}
			catch (Exception e) {
				messages[0] = parser.getParseMessages();
				throw ToolError.invalid("C parse error: " + Ctx.describe(e)
						+ (messages[0] != null && !messages[0].isBlank() ? "\n" + messages[0].strip() : ""));
			}
			messages[0] = parser.getParseMessages();
			return null;
		});
		List<String> added = new ArrayList<>();
		dtm.getAllDataTypes().forEachRemaining(d -> {
			// Pointers, arrays and built-ins come along as a side effect; only declared types matter.
			if (!before.contains(d.getPathName()) && !(d instanceof Pointer) && !(d instanceof Array)
					&& !(d instanceof ghidra.program.model.data.BuiltInDataType)) {
				added.add(d.getPathName());
			}
		});
		StringBuilder sb = new StringBuilder();
		sb.append(added.isEmpty() ? "No new types (existing types with the same names may have been updated)"
				: "Added " + added.size() + " types: " + String.join(", ", added));
		if (messages[0] != null && !messages[0].isBlank()) {
			String m = messages[0].strip();
			sb.append("\nParser messages:\n").append(m.length() > 4000 ? m.substring(0, 4000) + "..." : m);
		}
		return sb.toString();
	}

	@Tool(name = "list_data_types", description = "List the program's data types as 'path  kind  size', "
			+ "optionally filtered by a substring of the name, a category prefix and/or a kind.")
	public String listDataTypes(Ctx ctx,
			@P(value = "filter", def = P.NULL, description = "Case-insensitive substring of the name") String filter,
			@P(value = "category", def = P.NULL, description = "Only types under this category path") String category,
			@P(value = "kind", def = "any", oneOf = { "any", "struct", "union", "enum", "typedef", "function",
					"pointer", "array", "other" }, description = "Only this kind (pointers and arrays are listed only when asked for)") String kind,
			@P(value = "offset", def = "0", description = "Pagination offset") int offset,
			@P(value = "limit", def = "200", description = "Pagination limit") int limit) {
		String needle = filter == null ? null : filter.toLowerCase(Locale.ROOT);
		Page page = new Page(offset, limit);
		List<DataType> all = new ArrayList<>();
		ctx.program().getDataTypeManager().getAllDataTypes().forEachRemaining(all::add);
		all.sort((a, b) -> a.getPathName().compareToIgnoreCase(b.getPathName()));
		for (DataType d : all) {
			if (needle != null && !d.getName().toLowerCase(Locale.ROOT).contains(needle)) {
				continue;
			}
			if (category != null && !d.getCategoryPath().getPath().startsWith(category)) {
				continue;
			}
			String k = kind(d);
			if (kind.equals("any") ? (k.equals("pointer") || k.equals("array")) : !kind.equals(k)) {
				continue;
			}
			page.offer(() -> d.getPathName() + "  " + k + "  " + (d.getLength() > 0 ? d.getLength() : "-"));
		}
		return page.render("No matching data types");
	}

	private static String kind(DataType d) {
		if (d instanceof Structure) {
			return "struct";
		}
		if (d instanceof Union) {
			return "union";
		}
		if (d instanceof Enum) {
			return "enum";
		}
		if (d instanceof TypeDef) {
			return "typedef";
		}
		if (d instanceof FunctionDefinition) {
			return "function";
		}
		if (d instanceof Pointer) {
			return "pointer";
		}
		if (d instanceof Array) {
			return "array";
		}
		return "other";
	}

	@Tool(name = "rename_data_type", readOnly = false, description = "Rename a data type in place; every use "
			+ "of it follows.")
	public String renameDataType(Ctx ctx,
			@P(value = "name", description = "Current name") String name,
			@P(value = "new_name", description = "New name") String newName,
			@P(value = "category", def = P.NULL, description = CATEGORY) String category) {
		DataType d = existing(ctx, name, category);
		String old = d.getPathName();
		ctx.write("Rename Data Type", () -> {
			d.setName(newName.trim());
			return null;
		});
		return "Renamed " + old + " to " + d.getPathName();
	}

	@Tool(name = "delete_data_type", readOnly = false, description = "Delete a data type. Data and variables "
			+ "using it become undefined, so check get_xrefs/usage first.")
	public String deleteDataType(Ctx ctx,
			@P(value = "name", description = "Type name") String name,
			@P(value = "category", def = P.NULL, description = CATEGORY) String category) {
		DataType d = existing(ctx, name, category);
		String path = d.getPathName();
		DataTypeManager dtm = ctx.program().getDataTypeManager();
		ctx.write("Delete Data Type", () -> {
			if (!dtm.remove(d)) {
				throw ToolError.failed("Ghidra refused to delete " + path);
			}
			return null;
		});
		return "Deleted " + path;
	}

	// ---------------------------------------------------------------------
	// Applying types to memory
	// ---------------------------------------------------------------------

	@Tool(name = "set_global_data_type", readOnly = false, description = "Apply a data type at an address "
			+ "(define a global): e.g. 'int', 'Actor', 'char[16]', 'Actor[8]', 'string' (length found from "
			+ "the terminating zero). clear_mode decides what happens to data already there.")
	public String setGlobalDataType(Ctx ctx,
			@P(value = "address", description = "Address or symbol") String address,
			@P(value = "data_type", description = "C type") String dataType,
			@P(value = "length", def = "-1", description = "Length for variable-size types (strings); -1 = automatic") int length,
			@P(value = "clear_mode", def = "CHECK_FOR_SPACE", oneOf = { "CHECK_FOR_SPACE", "CLEAR_SINGLE_DATA",
					"CLEAR_ALL_UNDEFINED_CONFLICT_DATA", "CLEAR_ALL_DEFAULT_CONFLICT_DATA", "CLEAR_ALL_CONFLICT_DATA" },
					description = "CHECK_FOR_SPACE fails if defined data is in the way; CLEAR_ALL_CONFLICT_DATA "
							+ "replaces whatever is there") String clearMode) {
		Program p = ctx.program();
		Address a = ctx.addr(address);
		DataType dt = ctx.type(dataType);
		ClearDataMode mode = ClearDataMode.valueOf(clearMode.toUpperCase(Locale.ROOT));
		Data d = ctx.write("Set Global Data Type", () -> {
			int len = length;
			if (dt instanceof Dynamic && len <= 0) {
				Memory mem = p.getMemory();
				Address scan = a;
				int n = 0;
				while (mem.getByte(scan) != 0 && n < 65536) {
					scan = scan.add(1);
					n++;
				}
				len = n + 1;
			}
			try {
				return DataUtilities.createData(p, a, dt, len, mode);
			}
			catch (ghidra.program.model.util.CodeUnitInsertionException e) {
				throw ToolError.conflict("Could not define " + dt.getDisplayName() + " at " + Fmt.addr(a) + ": "
						+ e.getMessage() + ". Use clear_mode=CLEAR_ALL_CONFLICT_DATA to replace what is there.");
			}
		});
		return "Defined " + d.getDataType().getDisplayName() + " at " + Fmt.addr(a) + " (" + d.getLength()
				+ " bytes)" + (d.getLabel() != null ? " named " + d.getLabel() : "");
	}

	@Tool(name = "clear_data", readOnly = false, description = "Undefine the data (or instructions) covering "
			+ "an address range, making the bytes undefined again.")
	public String clearData(Ctx ctx,
			@P(value = "address", description = "Start address") String address,
			@P(value = "length", def = "1", description = "Number of bytes") int length) {
		Program p = ctx.program();
		Address a = ctx.addr(address);
		if (length < 1) {
			throw ToolError.invalid("length must be >= 1");
		}
		Address end = a.add(length - 1L);
		ctx.write("Clear Data", () -> {
			p.getListing().clearCodeUnits(a, end, false);
			return null;
		});
		return "Cleared " + Fmt.addr(a) + "-" + Fmt.addr(end);
	}

	// ---------------------------------------------------------------------
	// Helpers
	// ---------------------------------------------------------------------

	static CategoryPath cat(String category) {
		if (category == null || category.isBlank()) {
			return CategoryPath.ROOT;
		}
		return new CategoryPath(category.startsWith("/") ? category : "/" + category);
	}

	static DataType existing(Ctx ctx, String name, String category) {
		if (name == null || name.isBlank()) {
			throw ToolError.missing("name");
		}
		DataType d = Types.find(ctx.program().getDataTypeManager(), name.trim(), category);
		if (d == null) {
			throw ToolError.notFound("No data type named " + name + (category != null ? " in " + category : "")
					+ " (list_data_types lists them)");
		}
		return d;
	}

	static Structure struct(Ctx ctx, String name, String category) {
		DataType d = existing(ctx, name, category);
		if (!(d instanceof Structure s)) {
			throw ToolError.invalid(d.getPathName() + " is not a structure");
		}
		return s;
	}

	static Composite composite(Ctx ctx, String name, String category) {
		DataType d = existing(ctx, name, category);
		if (!(d instanceof Composite c)) {
			throw ToolError.invalid(d.getPathName() + " is not a structure or union");
		}
		return c;
	}

	static Enum enumType(Ctx ctx, String name, String category) {
		DataType d = existing(ctx, name, category);
		if (!(d instanceof Enum e)) {
			throw ToolError.invalid(d.getPathName() + " is not an enum");
		}
		return e;
	}

	static DataTypeComponent component(Composite c, String field) {
		String f = field.trim();
		if (f.startsWith("0x") || f.startsWith("0X")) {
			int off = (int) ToolRegistry.parseLong(f);
			if (c instanceof Structure s) {
				DataTypeComponent dc = s.getComponentContaining(off);
				if (dc != null && dc.getOffset() == off) {
					return dc;
				}
			}
			throw ToolError.notFound("No field starts at offset " + f + " in " + c.getName());
		}
		for (DataTypeComponent dc : c.getDefinedComponents()) {
			if (f.equals(dc.getFieldName())) {
				return dc;
			}
		}
		throw ToolError.notFound("No field named '" + f + "' in " + c.getName());
	}

	static List<String> strings(JsonArray arr) {
		if (arr == null || arr.size() == 0) {
			throw ToolError.missing("names");
		}
		List<String> out = new ArrayList<>();
		for (JsonElement e : arr) {
			out.add(e.isJsonPrimitive() ? e.getAsString() : e.getAsJsonObject().get("name").getAsString());
		}
		return out;
	}

	static Iterator<DataType> all(DataTypeManager dtm) {
		return dtm.getAllDataTypes();
	}
}
