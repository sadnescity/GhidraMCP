package com.lauriewired.core;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

/**
 * Every tool, read from the {@link Tool} annotations of the classes listed in
 * {@link #TOOL_CLASSES}, with its JSON schema and a way to call it.
 */
public final class ToolRegistry {

	/** The classes whose @Tool methods make up the catalog, in catalog order. */
	public static final List<String> TOOL_CLASSES = List.of(
		"com.lauriewired.tools.ProgramTools",
		"com.lauriewired.tools.ListTools",
		"com.lauriewired.tools.FunctionTools",
		"com.lauriewired.tools.VariableTools",
		"com.lauriewired.tools.XrefTools",
		"com.lauriewired.tools.CommentTools",
		"com.lauriewired.tools.SymbolTools",
		"com.lauriewired.tools.DataTypeTools",
		"com.lauriewired.tools.ClassTools",
		"com.lauriewired.tools.MemoryTools",
		"com.lauriewired.tools.SearchTools",
		"com.lauriewired.tools.ReferenceTools",
		"com.lauriewired.tools.EmulationTools");

	/** One tool: its declaration, the method behind it, and the object to call it on. */
	public record Entry(Tool tool, Method method, Object target) {
	}

	private final Map<String, Entry> tools = new LinkedHashMap<>();

	public ToolRegistry() {
		for (String cn : TOOL_CLASSES) {
			try {
				Class<?> c = Class.forName(cn);
				Object target = c.getDeclaredConstructor().newInstance();
				// Reflection gives no stable order; sort by name so the catalog is deterministic.
				List<Method> methods = new ArrayList<>(Arrays.asList(c.getMethods()));
				methods.sort((a, b) -> a.getName().compareTo(b.getName()));
				for (Method m : methods) {
					Tool t = m.getAnnotation(Tool.class);
					if (t == null) {
						continue;
					}
					check(m);
					if (tools.put(t.name(), new Entry(t, m, target)) != null) {
						throw new IllegalStateException("Duplicate tool name " + t.name());
					}
				}
			}
			catch (ReflectiveOperationException e) {
				throw new IllegalStateException("Cannot load tool class " + cn, e);
			}
		}
	}

	private static void check(Method m) {
		Parameter[] ps = m.getParameters();
		if (ps.length == 0 || ps[0].getType() != Ctx.class) {
			throw new IllegalStateException(m + ": first parameter must be Ctx");
		}
		for (int i = 1; i < ps.length; i++) {
			if (ps[i].getAnnotation(P.class) == null) {
				throw new IllegalStateException(m + ": parameter " + i + " lacks @P");
			}
			Class<?> ty = ps[i].getType();
			if (ty != String.class && ty != int.class && ty != long.class && ty != boolean.class
					&& ty != JsonArray.class && ty != JsonObject.class) {
				throw new IllegalStateException(m + ": unsupported parameter type " + ty);
			}
		}
		if (m.getReturnType() != String.class) {
			throw new IllegalStateException(m + ": a tool returns String");
		}
	}

	public Map<String, Entry> all() {
		return tools;
	}

	public Entry get(String name) {
		return tools.get(name);
	}

	// ---------------------------------------------------------------------
	// Schema
	// ---------------------------------------------------------------------

	/** The MCP tool list: name, description, inputSchema, annotations. */
	public JsonArray schema() {
		JsonArray out = new JsonArray();
		for (Entry e : tools.values()) {
			out.add(schema(e));
		}
		return out;
	}

	private static JsonObject schema(Entry e) {
		JsonObject tool = new JsonObject();
		tool.addProperty("name", e.tool().name());
		tool.addProperty("description", e.tool().description());
		JsonObject input = new JsonObject();
		input.addProperty("type", "object");
		JsonObject props = new JsonObject();
		JsonArray required = new JsonArray();
		Parameter[] ps = e.method().getParameters();
		for (int i = 1; i < ps.length; i++) {
			P p = ps[i].getAnnotation(P.class);
			JsonObject prop = new JsonObject();
			Class<?> ty = ps[i].getType();
			prop.addProperty("type", jsonType(ty));
			if (!p.description().isEmpty()) {
				prop.addProperty("description", p.description());
			}
			if (p.oneOf().length > 0) {
				JsonArray en = new JsonArray();
				for (String v : p.oneOf()) {
					en.add(v);
				}
				prop.add("enum", en);
			}
			if (P.REQUIRED.equals(p.def())) {
				required.add(p.value());
			}
			else if (!P.NULL.equals(p.def())) {
				prop.add("default", defaultJson(ty, p.def()));
			}
			props.add(p.value(), prop);
		}
		input.add("properties", props);
		if (required.size() > 0) {
			input.add("required", required);
		}
		input.addProperty("additionalProperties", false);
		tool.add("inputSchema", input);
		JsonObject ann = new JsonObject();
		ann.addProperty("readOnlyHint", e.tool().readOnly());
		if (!e.tool().readOnly()) {
			ann.addProperty("destructiveHint", false);
		}
		ann.addProperty("openWorldHint", false);
		tool.add("annotations", ann);
		return tool;
	}

	private static String jsonType(Class<?> ty) {
		if (ty == int.class || ty == long.class) {
			return "integer";
		}
		if (ty == boolean.class) {
			return "boolean";
		}
		if (ty == JsonArray.class) {
			return "array";
		}
		if (ty == JsonObject.class) {
			return "object";
		}
		return "string";
	}

	private static JsonElement defaultJson(Class<?> ty, String def) {
		if (ty == int.class || ty == long.class) {
			return new JsonPrimitive(Long.parseLong(def));
		}
		if (ty == boolean.class) {
			return new JsonPrimitive(Boolean.parseBoolean(def));
		}
		if (ty == JsonArray.class || ty == JsonObject.class) {
			return JsonParser.parseString(def);
		}
		return new JsonPrimitive(def);
	}

	// ---------------------------------------------------------------------
	// Invocation
	// ---------------------------------------------------------------------

	/** Calls a tool. Throws ToolError for anything the caller should see as an error. */
	public String invoke(String name, JsonObject args, Ctx ctx) {
		Entry e = tools.get(name);
		if (e == null) {
			throw new ToolError("UNKNOWN_TOOL", "No tool named '" + name + "'");
		}
		if (args == null) {
			args = new JsonObject();
		}
		Parameter[] ps = e.method().getParameters();
		Object[] values = new Object[ps.length];
		values[0] = ctx;
		List<String> known = new ArrayList<>();
		for (int i = 1; i < ps.length; i++) {
			known.add(ps[i].getAnnotation(P.class).value());
		}
		// A misspelt name first: "missing 'address'" would hide that 'adress' was sent.
		for (String k : args.keySet()) {
			if (!known.contains(k)) {
				throw ToolError.invalid("Unknown parameter '" + k + "' for " + name
						+ ". Parameters: " + (known.isEmpty() ? "none" : String.join(", ", known)));
			}
		}
		for (int i = 1; i < ps.length; i++) {
			P p = ps[i].getAnnotation(P.class);
			values[i] = coerce(p, ps[i].getType(), args.get(p.value()));
		}
		ctx.program();
		try {
			return (String) e.method().invoke(e.target(), values);
		}
		catch (InvocationTargetException ite) {
			Throwable c = ite.getCause();
			if (c instanceof ToolError te) {
				throw te;
			}
			throw new ToolError("INTERNAL_ERROR", name + " failed: " + c.getClass().getSimpleName()
					+ (c.getMessage() != null ? ": " + c.getMessage() : ""), c);
		}
		catch (IllegalAccessException iae) {
			throw new ToolError("INTERNAL_ERROR", iae.toString(), iae);
		}
	}

	private static Object coerce(P p, Class<?> ty, JsonElement v) {
		boolean absent = v == null || v.isJsonNull();
		if (absent) {
			if (P.REQUIRED.equals(p.def())) {
				throw ToolError.missing(p.value());
			}
			if (P.NULL.equals(p.def())) {
				if (ty == int.class || ty == long.class || ty == boolean.class) {
					throw new IllegalStateException("primitive parameter " + p.value() + " needs a default");
				}
				return null;
			}
			return fromText(p, ty, p.def());
		}
		try {
			if (ty == String.class) {
				String s = v.isJsonPrimitive() ? v.getAsString() : v.toString();
				checkOneOf(p, s);
				return s;
			}
			if (ty == int.class) {
				return v.isJsonPrimitive() && v.getAsJsonPrimitive().isString()
						? (int) parseLong(v.getAsString()) : v.getAsInt();
			}
			if (ty == long.class) {
				return v.isJsonPrimitive() && v.getAsJsonPrimitive().isString()
						? parseLong(v.getAsString()) : v.getAsLong();
			}
			if (ty == boolean.class) {
				if (v.isJsonPrimitive() && v.getAsJsonPrimitive().isString()) {
					return Boolean.parseBoolean(v.getAsString().trim());
				}
				return v.getAsBoolean();
			}
			if (ty == JsonArray.class) {
				// Some clients send a JSON array as a string; accept both.
				if (v.isJsonPrimitive()) {
					return JsonParser.parseString(v.getAsString()).getAsJsonArray();
				}
				return v.getAsJsonArray();
			}
			if (ty == JsonObject.class) {
				if (v.isJsonPrimitive()) {
					return JsonParser.parseString(v.getAsString()).getAsJsonObject();
				}
				return v.getAsJsonObject();
			}
		}
		catch (ToolError te) {
			throw te;
		}
		catch (RuntimeException ex) {
			throw ToolError.invalid("Parameter '" + p.value() + "' must be " + jsonType(ty)
					+ " (got " + v + ")");
		}
		throw new IllegalStateException("unreachable");
	}

	private static Object fromText(P p, Class<?> ty, String text) {
		if (ty == int.class) {
			return Integer.parseInt(text);
		}
		if (ty == long.class) {
			return Long.parseLong(text);
		}
		if (ty == boolean.class) {
			return Boolean.parseBoolean(text);
		}
		if (ty == JsonArray.class) {
			return JsonParser.parseString(text).getAsJsonArray();
		}
		if (ty == JsonObject.class) {
			return JsonParser.parseString(text).getAsJsonObject();
		}
		return text;
	}

	private static void checkOneOf(P p, String s) {
		if (p.oneOf().length == 0) {
			return;
		}
		for (String o : p.oneOf()) {
			if (o.equalsIgnoreCase(s)) {
				return;
			}
		}
		throw ToolError.invalid("Parameter '" + p.value() + "' must be one of "
				+ String.join(", ", p.oneOf()) + " (got '" + s + "')");
	}

	/** Parses decimal or 0x-prefixed hex. */
	public static long parseLong(String s) {
		String t = s.trim().replace("_", "");
		boolean neg = t.startsWith("-");
		if (neg) {
			t = t.substring(1);
		}
		long v = t.startsWith("0x") || t.startsWith("0X") ? Long.parseUnsignedLong(t.substring(2), 16)
				: Long.parseLong(t);
		return neg ? -v : v;
	}
}
