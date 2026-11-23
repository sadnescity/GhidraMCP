package com.lauriewired.tools;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.lauriewired.core.Ctx;
import com.lauriewired.core.P;
import com.lauriewired.core.Tool;
import com.lauriewired.core.ToolError;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

/** C++ classes: a class namespace plus the structure Ghidra associates with it. */
public final class ClassTools {

	private static final String MEMBERS = "List of {\"name\", \"type\", \"offset\"?, \"comment\"?}";

	@Tool(name = "create_class", readOnly = false, description = "Create a C++ class: a class namespace and "
			+ "its structure (in /classes/...), optionally with data members.")
	public String createClass(Ctx ctx,
			@P(value = "name", description = "Class name") String name,
			@P(value = "parent_namespace", def = P.NULL, description = "Parent namespace, if any") String parentNamespace,
			@P(value = "members", def = P.NULL, description = MEMBERS) JsonArray members) {
		Program p = ctx.program();
		Namespace parent = parent(p, parentNamespace);
		List<Members.Member> ms = Members.parse(ctx, members);
		Structure s = ctx.write("Create Class", () -> {
			GhidraClass cls = p.getSymbolTable().createClass(parent, name, SourceType.USER_DEFINED);
			DataTypeManager dtm = p.getDataTypeManager();
			StructureDataType sdt = new StructureDataType(category(cls), name, 0, dtm);
			for (Members.Member m : ms) {
				Members.place(sdt, m);
			}
			return (Structure) dtm.addDataType(sdt, DataTypeConflictHandler.DEFAULT_HANDLER);
		});
		return "Created class " + name + "\n" + Members.render(s);
	}

	@Tool(name = "add_class_members", readOnly = false, description = "Add data members to a class's structure.")
	public String addClassMembers(Ctx ctx,
			@P(value = "class_name", description = "Class name") String className,
			@P(value = "members", description = MEMBERS) JsonArray members,
			@P(value = "parent_namespace", def = P.NULL, description = "Parent namespace, if any") String parentNamespace) {
		Structure s = classStruct(ctx, className, parentNamespace);
		List<Members.Member> ms = Members.parse(ctx, members);
		ctx.write("Add Class Members", () -> {
			for (Members.Member m : ms) {
				for (DataTypeComponent dc : s.getDefinedComponents()) {
					if (m.name() != null && m.name().equals(dc.getFieldName())) {
						throw ToolError.conflict(className + " already has a member " + m.name());
					}
				}
				Members.place(s, m);
			}
			return null;
		});
		return Members.render(s);
	}

	@Tool(name = "remove_class_members", readOnly = false, description = "Remove data members from a class's "
			+ "structure by name.")
	public String removeClassMembers(Ctx ctx,
			@P(value = "class_name", description = "Class name") String className,
			@P(value = "members", description = "List of member names") JsonArray members,
			@P(value = "parent_namespace", def = P.NULL, description = "Parent namespace, if any") String parentNamespace) {
		Structure s = classStruct(ctx, className, parentNamespace);
		List<String> names = DataTypeTools.strings(members);
		List<String> missing = new ArrayList<>(names);
		ctx.write("Remove Class Members", () -> {
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
				throw ToolError.notFound("None of " + names + " is a member of " + className);
			}
			return null;
		});
		return (missing.isEmpty() ? "" : "Not found: " + String.join(", ", missing) + "\n") + Members.render(s);
	}

	private static Namespace parent(Program p, String parentNamespace) {
		if (parentNamespace == null || parentNamespace.isBlank()) {
			return p.getGlobalNamespace();
		}
		Namespace ns = p.getSymbolTable().getNamespace(parentNamespace, p.getGlobalNamespace());
		if (ns == null) {
			throw ToolError.notFound("No namespace named " + parentNamespace);
		}
		return ns;
	}

	private static Structure classStruct(Ctx ctx, String className, String parentNamespace) {
		Program p = ctx.program();
		Namespace parent = parent(p, parentNamespace);
		SymbolTable st = p.getSymbolTable();
		GhidraClass cls = null;
		for (Symbol s : st.getSymbols(className, parent)) {
			if (s.getSymbolType() == SymbolType.CLASS) {
				cls = (GhidraClass) s.getObject();
			}
		}
		if (cls == null) {
			throw ToolError.notFound("No class named " + className);
		}
		Structure s = DataTypeUtilities.findExistingClassStruct(p.getDataTypeManager(), cls);
		if (s == null) {
			throw ToolError.notFound("Class " + className + " has no structure");
		}
		return s;
	}

	private static CategoryPath category(GhidraClass cls) {
		List<String> parts = new ArrayList<>();
		for (Namespace n = cls; n != null && !n.isGlobal(); n = n.getParentNamespace()) {
			parts.add(0, n.getName());
		}
		return new CategoryPath("/classes/" + String.join("/", parts));
	}
}
