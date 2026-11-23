package com.lauriewired.tools;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.lauriewired.core.Ctx;
import com.lauriewired.core.Fmt;
import com.lauriewired.core.P;
import com.lauriewired.core.Tool;
import com.lauriewired.core.ToolError;

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;

/** A function's parameters and locals, as the decompiler sees them. */
public final class VariableTools {

	@Tool(name = "list_variables", description = "List a function's parameters and local variables as the "
			+ "decompiler shows them: name, type, storage, and whether the name/type was set by a user. "
			+ "Use it before rename_variable / set_local_variable_type / set_variables.")
	public String listVariables(Ctx ctx,
			@P(value = "function_address", description = "Address inside the function, or its name") String functionAddress) {
		Function f = ctx.fnAt(functionAddress);
		HighFunction hf = ctx.high(f);
		LocalSymbolMap map = hf.getLocalSymbolMap();
		StringBuilder sb = new StringBuilder(Fmt.fn(f)).append('\n');
		List<HighSymbol> params = new ArrayList<>();
		List<HighSymbol> locals = new ArrayList<>();
		Iterator<HighSymbol> it = map.getSymbols();
		while (it.hasNext()) {
			HighSymbol s = it.next();
			(s.isParameter() ? params : locals).add(s);
		}
		params.sort((a, b) -> Integer.compare(a.getCategoryIndex(), b.getCategoryIndex()));
		sb.append(params.isEmpty() ? "Parameters: none\n" : "Parameters:\n");
		for (HighSymbol s : params) {
			sb.append("  ").append(line(s)).append('\n');
		}
		sb.append(locals.isEmpty() ? "Locals: none" : "Locals:\n");
		for (HighSymbol s : locals) {
			sb.append("  ").append(line(s)).append('\n');
		}
		return sb.toString().stripTrailing();
	}

	private static String line(HighSymbol s) {
		String storage;
		try {
			storage = String.valueOf(s.getStorage());
		}
		catch (Exception e) {
			storage = "?";
		}
		boolean user = s.getSymbol() != null && s.getSymbol().getSource() == SourceType.USER_DEFINED;
		return (s.getDataType() != null ? s.getDataType().getDisplayName() : "?") + " " + s.getName()
				+ "  [" + storage + "]" + (user ? " (user)" : "");
	}

	@Tool(name = "rename_variable", readOnly = false, description = "Rename a parameter or local variable "
			+ "of a function, as shown in the decompiler. Give the function by address (preferred) or "
			+ "name.")
	public String renameVariable(Ctx ctx,
			@P(value = "function_name", def = P.NULL, description = "Function name (or use function_address)") String functionName,
			@P(value = "old_name", description = "Current variable name, as in the decompiler") String oldName,
			@P(value = "new_name", description = "New variable name") String newName,
			@P(value = "function_address", def = P.NULL, description = "Address inside the function") String functionAddress) {
		Function f = ctx.fn(functionAddress, functionName);
		JsonArray one = new JsonArray();
		JsonObject o = new JsonObject();
		o.addProperty("name", oldName);
		o.addProperty("new_name", newName);
		one.add(o);
		apply(ctx, f, one);
		return "Renamed " + oldName + " to " + newName + " in " + Fmt.fn(f);
	}

	@Tool(name = "set_local_variable_type", readOnly = false, description = "Set the type of a parameter or "
			+ "local variable, as shown in the decompiler (e.g. 'Actor *', 'short', 'uint[4]').")
	public String setLocalVariableType(Ctx ctx,
			@P(value = "function_address", description = "Address inside the function, or its name") String functionAddress,
			@P(value = "variable_name", description = "Variable name, as in the decompiler") String variableName,
			@P(value = "new_type", description = "C type name") String newType) {
		Function f = ctx.fnAt(functionAddress);
		JsonArray one = new JsonArray();
		JsonObject o = new JsonObject();
		o.addProperty("name", variableName);
		o.addProperty("type", newType);
		one.add(o);
		apply(ctx, f, one);
		return "Set type of " + variableName + " to " + newType + " in " + Fmt.fn(f);
	}

	@Tool(name = "set_variables", readOnly = false, description = "Rename and/or retype several variables of "
			+ "one function in a single decompile and a single transaction (all or nothing). Each entry: "
			+ "{\"name\": current name, \"new_name\": optional, \"type\": optional C type}. Far cheaper "
			+ "than one call per variable when annotating a whole function.")
	public String setVariables(Ctx ctx,
			@P(value = "function_address", description = "Address inside the function, or its name") String functionAddress,
			@P(value = "variables", description = "List of {name, new_name?, type?}") JsonArray variables) {
		Function f = ctx.fnAt(functionAddress);
		List<String> done = apply(ctx, f, variables);
		return "Updated " + done.size() + " variables in " + Fmt.fn(f) + ":\n  " + String.join("\n  ", done);
	}

	private record Change(String name, String newName, DataType type) {
	}

	/** Applies every change in one transaction, after checking all of them. */
	private static List<String> apply(Ctx ctx, Function f, JsonArray entries) {
		if (entries == null || entries.size() == 0) {
			throw ToolError.missing("variables");
		}
		List<Change> changes = new ArrayList<>();
		for (JsonElement e : entries) {
			if (!e.isJsonObject()) {
				throw ToolError.invalid("Each variable must be an object {name, new_name?, type?}");
			}
			JsonObject o = e.getAsJsonObject();
			String name = str(o, "name");
			if (name == null) {
				name = str(o, "old_name");
			}
			if (name == null) {
				throw ToolError.missing("name (in variables)");
			}
			String newName = str(o, "new_name");
			String type = str(o, "type");
			if (type == null) {
				type = str(o, "new_type");
			}
			if (newName == null && type == null) {
				throw ToolError.invalid("Variable '" + name + "': give new_name, type, or both");
			}
			changes.add(new Change(name, newName, type == null ? null : ctx.type(type)));
		}

		HighFunction hf = ctx.high(f);
		Map<String, HighSymbol> byName = new LinkedHashMap<>();
		Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
		while (it.hasNext()) {
			HighSymbol s = it.next();
			byName.putIfAbsent(s.getName(), s);
		}
		Map<String, Variable> dbOnly = new HashMap<>();
		for (Variable v : f.getAllVariables()) {
			if (!byName.containsKey(v.getName())) {
				dbOnly.put(v.getName(), v);
			}
		}

		// Check everything before changing anything.
		List<String> taken = new ArrayList<>(byName.keySet());
		boolean needParams = false;
		for (Change c : changes) {
			HighSymbol s = byName.get(c.name);
			if (s == null && !dbOnly.containsKey(c.name)) {
				throw ToolError.notFound("No variable '" + c.name + "' in " + f.getName()
						+ ". Variables: " + String.join(", ", byName.keySet()));
			}
			if (c.newName != null && !c.newName.equals(c.name)) {
				if (taken.contains(c.newName)) {
					throw ToolError.conflict("A variable named '" + c.newName + "' already exists in " + f.getName());
				}
				taken.remove(c.name);
				taken.add(c.newName);
			}
			if (s != null && checkFullCommit(s, hf)) {
				needParams = true;
			}
		}

		boolean commitParams = needParams;
		List<String> done = new ArrayList<>();
		ctx.write("Set Variables", () -> {
			if (commitParams) {
				HighFunctionDBUtil.commitParamsToDatabase(hf, false, ReturnCommitOption.NO_COMMIT,
						f.getSignatureSource());
			}
			for (Change c : changes) {
				HighSymbol s = byName.get(c.name);
				if (s != null) {
					HighFunctionDBUtil.updateDBVariable(s, c.newName, c.type, SourceType.USER_DEFINED);
				}
				else {
					Variable v = dbOnly.get(c.name);
					if (c.type != null) {
						v.setDataType(c.type, SourceType.USER_DEFINED);
					}
					if (c.newName != null) {
						v.setName(c.newName, SourceType.USER_DEFINED);
					}
				}
				done.add(c.name + (c.newName != null ? " -> " + c.newName : "")
						+ (c.type != null ? " : " + c.type.getDisplayName() : ""));
			}
			return null;
		});
		return done;
	}

	private static String str(JsonObject o, String k) {
		JsonElement e = o.get(k);
		if (e == null || e.isJsonNull()) {
			return null;
		}
		String s = e.getAsString().trim();
		return s.isEmpty() ? null : s;
	}

	/**
	 * From Ghidra's AbstractDecompilerAction.checkFullCommit (protected there):
	 * true when the decompiler's idea of the parameters differs from the
	 * database's, in which case they must be committed before one is changed.
	 */
	static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}
		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}
		return false;
	}
}
