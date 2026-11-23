package com.lauriewired.core;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;

import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

/**
 * Resolves C-style type names.
 *
 * <p>The old resolver fell back to {@code int} for any name it did not know,
 * with only a log line to say so: a struct field declared as {@code Actor*}
 * before {@code Actor} existed quietly became an int, and the decompiler then
 * showed arithmetic where there was a pointer. A name that resolves to nothing
 * is now an error that says what was not found and what nearly matched.
 */
public final class Types {

	private Types() {
	}

	private static final Map<String, String> ALIASES = Map.ofEntries(
		Map.entry("unsigned int", "uint"), Map.entry("unsigned", "uint"),
		Map.entry("unsigned short", "ushort"), Map.entry("unsigned char", "uchar"),
		Map.entry("unsigned long", "ulong"), Map.entry("unsigned long long", "ulonglong"),
		Map.entry("signed char", "schar"), Map.entry("long long", "longlong"),
		Map.entry("signed int", "int"), Map.entry("signed short", "short"),
		Map.entry("signed long", "long"),
		Map.entry("u8", "uchar"), Map.entry("s8", "char"), Map.entry("u16", "ushort"),
		Map.entry("s16", "short"), Map.entry("u32", "uint"), Map.entry("s32", "int"),
		Map.entry("u64", "ulonglong"), Map.entry("s64", "longlong"),
		Map.entry("uint8_t", "uchar"), Map.entry("int8_t", "char"),
		Map.entry("uint16_t", "ushort"), Map.entry("int16_t", "short"),
		Map.entry("uint32_t", "uint"), Map.entry("int32_t", "int"),
		Map.entry("uint64_t", "ulonglong"), Map.entry("int64_t", "longlong"),
		Map.entry("dword", "uint"), Map.entry("word", "ushort"), Map.entry("qword", "ulonglong"),
		Map.entry("boolean", "bool"), Map.entry("_bool", "bool"));

	/** Resolves a type name, or throws NOT_FOUND naming the closest matches. */
	public static DataType resolve(PluginTool tool, Program program, String typeName) {
		if (typeName == null || typeName.isBlank()) {
			throw ToolError.missing("type");
		}
		String name = normalize(typeName);
		DataTypeManager dtm = program.getDataTypeManager();
		List<DataTypeManager> managers = managers(tool, dtm);

		DataType dt = parse(managers, name);
		if (dt == null) {
			String aliased = alias(name);
			if (aliased != null) {
				dt = parse(managers, aliased);
			}
		}
		if (dt == null) {
			dt = byNameAnywhere(dtm, name);
		}
		if (dt != null) {
			return dt;
		}
		throw ToolError.notFound("Data type not found: '" + typeName.trim() + "'." + suggestions(dtm, name)
				+ " Create it first (create_struct, create_enum, import_c_types), or use a built-in"
				+ " such as int, uint, short, ushort, char, uchar, undefined4, void*.");
	}

	/** Finds a data type by name and optional category, the way get_struct/get_enum need it. */
	public static DataType find(DataTypeManager dtm, String name, String category) {
		if (category != null && !category.isBlank()) {
			return dtm.getDataType(new CategoryPath(category), name);
		}
		DataType root = dtm.getDataType(CategoryPath.ROOT, name);
		if (root != null) {
			return root;
		}
		List<DataType> hits = new ArrayList<>();
		dtm.findDataTypes(name, hits);
		if (hits.size() > 1) {
			StringBuilder sb = new StringBuilder();
			for (DataType d : hits) {
				sb.append(sb.length() == 0 ? "" : ", ").append(d.getPathName());
			}
			throw ToolError.ambiguous("'" + name + "' exists in " + hits.size() + " categories: " + sb
					+ ". Pass category.");
		}
		return hits.isEmpty() ? null : hits.get(0);
	}

	private static String normalize(String s) {
		String n = s.trim().replaceAll("\\s+", " ");
		n = n.replaceAll("\\s*\\*", "*");
		for (String kw : new String[] { "struct ", "union ", "enum ", "const ", "volatile " }) {
			while (n.startsWith(kw)) {
				n = n.substring(kw.length()).trim();
			}
		}
		return n;
	}

	/** The alias for the base name, with the pointer/array suffix carried over. */
	private static String alias(String name) {
		int cut = indexOfSuffix(name);
		String base = name.substring(0, cut).trim();
		String suffix = name.substring(cut);
		String a = ALIASES.get(base.toLowerCase(Locale.ROOT));
		return a == null ? null : a + suffix;
	}

	private static int indexOfSuffix(String name) {
		int star = name.indexOf('*');
		int br = name.indexOf('[');
		int cut = name.length();
		if (star >= 0) {
			cut = Math.min(cut, star);
		}
		if (br >= 0) {
			cut = Math.min(cut, br);
		}
		return cut;
	}

	private static List<DataTypeManager> managers(PluginTool tool, DataTypeManager programDtm) {
		List<DataTypeManager> list = new ArrayList<>();
		list.add(programDtm);
		if (tool != null) {
			DataTypeManagerService svc = tool.getService(DataTypeManagerService.class);
			if (svc != null) {
				for (DataTypeManager m : svc.getDataTypeManagers()) {
					if (m != programDtm) {
						list.add(m);
					}
				}
			}
		}
		return list;
	}

	private static DataType parse(List<DataTypeManager> managers, String name) {
		for (DataTypeManager m : managers) {
			try {
				DataType dt = new DataTypeParser(m, m, null, AllowedDataTypes.ALL).parse(name);
				if (dt != null) {
					return dt;
				}
			}
			catch (Exception e) {
				// try the next manager
			}
		}
		return null;
	}

	/** A type in any category, matched exactly, then without regard to case. */
	private static DataType byNameAnywhere(DataTypeManager dtm, String name) {
		if (name.contains("*") || name.contains("[")) {
			return null;
		}
		DataType ci = null;
		Iterator<DataType> it = dtm.getAllDataTypes();
		while (it.hasNext()) {
			DataType d = it.next();
			if (d.getName().equals(name)) {
				return d;
			}
			if (ci == null && d.getName().equalsIgnoreCase(name)) {
				ci = d;
			}
		}
		return ci;
	}

	private static String suggestions(DataTypeManager dtm, String name) {
		String base = name.substring(0, indexOfSuffix(name)).trim().toLowerCase(Locale.ROOT);
		if (base.length() < 2) {
			return "";
		}
		TreeSet<String> near = new TreeSet<>();
		Iterator<DataType> it = dtm.getAllDataTypes();
		while (it.hasNext() && near.size() < 8) {
			DataType d = it.next();
			String dn = d.getName().toLowerCase(Locale.ROOT);
			if (dn.contains(base) || base.contains(dn) && dn.length() > 3) {
				near.add(d.getPathName());
			}
		}
		return near.isEmpty() ? "" : " Similar names in this program: " + String.join(", ", near) + ".";
	}
}
