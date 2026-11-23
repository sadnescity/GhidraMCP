package com.lauriewired.mcp;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Supplier;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * The MCP protocol, independent of transport: JSON-RPC in, JSON-RPC out.
 *
 * <p>Dual-era, as MCP 2026-07-28 defines it. A request whose {@code _meta}
 * carries {@code io.modelcontextprotocol/protocolVersion} is served
 * statelessly under the modern revision ({@code server/discover},
 * {@code resultType}, cache hints, {@code subscriptions/listen}). An
 * {@code initialize} request selects the legacy, handshake-based revisions
 * (2025-11-25 and the two before it) for this process, for clients that do
 * not speak the modern one yet.
 *
 * <p>Either way there is no per-client state: every tool that works on a
 * program takes that program as a required {@code program} argument. The
 * management tool (list_instances) is answered here; every other tool is
 * declared by the Ghidra plugin's @Tool methods, its schema comes from the
 * catalog generated from them at build time (or served live by an instance),
 * and its calls are forwarded to the instance holding the named program.
 */
public final class McpServer {

	public static final String NAME = "ghidra-mcp";
	public static final String VERSION = "4.0.0";
	/** Revisions served statelessly, newest first. */
	static final List<String> MODERN = List.of("2026-07-28");
	/** Handshake revisions answered to an initialize request, newest first. */
	static final List<String> LEGACY = List.of("2025-11-25", "2025-06-18");

	static final String META_VERSION = "io.modelcontextprotocol/protocolVersion";
	static final String META_CLIENT_CAPS = "io.modelcontextprotocol/clientCapabilities";
	static final String META_SERVER_INFO = "io.modelcontextprotocol/serverInfo";
	static final String META_SUBSCRIPTION = "io.modelcontextprotocol/subscriptionId";

	static final int INVALID_PARAMS = -32602;
	static final int METHOD_NOT_FOUND = -32601;
	static final int UNSUPPORTED_PROTOCOL_VERSION = -32022;

	/** How long a client may cache tools/list once it is known to match the running extension. */
	static final long TOOLS_TTL_MS = 3_600_000;

	static final String INSTRUCTIONS = """
			Tools for reverse engineering programs open in Ghidra. Several Ghidra instances, and several \
			programs per instance, may be open at once, so every tool takes a required program="..." \
			argument naming the program it works on: call list_instances first and pass the program \
			exactly as it shows it. Nothing is remembered between calls and nothing is chosen for you. \
			Addresses are hex ("0x80012345"); most tools also accept a function or label name where an \
			address is expected. List tools are paged and end with a footer giving the total and the next \
			offset. Errors come back as errors with a [CODE]; read the message, it says what to do. Changes \
			are made in Ghidra at once but are saved only by save_program (or the analyst).""";

	private final Router router;
	private final Supplier<JsonArray> catalogSource;
	private final String clientTag;
	/** Writes a notification to the client. */
	private final Consumer<JsonObject> notifier;

	private volatile JsonArray catalog;
	private volatile boolean catalogChecked;
	/** Set once an initialize request selected the legacy revisions for this process. */
	private volatile boolean legacy;
	/** Open subscriptions/listen streams that asked for tools/list_changed, by request id. */
	private final Map<String, JsonElement> toolSubscriptions = new ConcurrentHashMap<>();

	/**
	 * @param catalogSource the tool schemas (normally the catalog bundled in the jar)
	 * @param clientTag names this client in Ghidra's undo history; may be null
	 * @param notifier sends a notification to the client; may be null when nothing listens
	 */
	public McpServer(Router router, Supplier<JsonArray> catalogSource, String clientTag,
			Consumer<JsonObject> notifier) {
		this.router = router;
		this.catalogSource = catalogSource;
		this.clientTag = clientTag;
		this.notifier = notifier != null ? notifier : n -> {
		};
	}

	/** The catalog bundled into the jar at build time, or null if this build has none. */
	public static JsonArray bundledCatalog() {
		try (InputStream in = McpServer.class.getResourceAsStream("/mcp-tools.json")) {
			if (in == null) {
				return null;
			}
			return JsonParser.parseReader(new InputStreamReader(in, StandardCharsets.UTF_8)).getAsJsonArray();
		}
		catch (Exception e) {
			return null;
		}
	}

	private JsonArray instanceTools() {
		JsonArray c = catalog;
		if (c == null || c.isEmpty()) {
			c = catalogSource.get();
			if (c != null && !c.isEmpty()) {
				catalog = c;
			}
		}
		return c == null ? new JsonArray() : c;
	}

	// ---------------------------------------------------------------------
	// Dispatch
	// ---------------------------------------------------------------------

	/**
	 * Handles one message. Returns the response to send, or null when there is
	 * none (a notification, or a subscriptions/listen request, whose response
	 * only comes when the subscription ends).
	 */
	public JsonObject handle(JsonObject msg) {
		JsonElement id = msg.get("id");
		String method = msg.has("method") && msg.get("method").isJsonPrimitive() ? msg.get("method").getAsString()
				: null;
		if (method == null) {
			return null; // a response from the client; this server never sends requests
		}
		JsonObject params = msg.has("params") && msg.get("params").isJsonObject() ? msg.getAsJsonObject("params")
				: new JsonObject();
		if (id == null || id.isJsonNull()) {
			if ("notifications/cancelled".equals(method) && params.has("requestId")) {
				toolSubscriptions.remove(params.get("requestId").toString());
			}
			return null; // notifications/initialized, notifications/cancelled, ...
		}
		try {
			JsonObject meta = params.has("_meta") && params.get("_meta").isJsonObject()
					? params.getAsJsonObject("_meta") : null;
			if (meta != null && meta.has(META_VERSION)) {
				return modern(id, method, params, meta);
			}
			if ("initialize".equals(method)) {
				legacy = true;
				return ok(id, initialize(params), false);
			}
			if (legacy) {
				return switch (method) {
					case "ping" -> ok(id, new JsonObject(), false);
					case "tools/list" -> ok(id, toolsList(), false);
					case "tools/call" -> ok(id, toolsCall(params), false);
					default -> error(id, METHOD_NOT_FOUND, "Method not found: " + method);
				};
			}
			return error(id, INVALID_PARAMS, "Missing _meta[\"" + META_VERSION + "\"]: this server speaks MCP "
					+ MODERN.get(0) + " (and, after an initialize request, " + String.join(", ", LEGACY) + ").");
		}
		catch (IllegalArgumentException e) {
			return error(id, INVALID_PARAMS, e.getMessage());
		}
		catch (Exception e) {
			return error(id, -32603, "Internal error: " + e);
		}
	}

	private JsonObject modern(JsonElement id, String method, JsonObject params, JsonObject meta) {
		JsonElement v = meta.get(META_VERSION);
		String version = v.isJsonPrimitive() ? v.getAsString() : null;
		if (version == null || !MODERN.contains(version)) {
			JsonObject data = new JsonObject();
			JsonArray supported = new JsonArray();
			MODERN.forEach(supported::add);
			data.add("supported", supported);
			data.add("requested", v);
			JsonObject resp = error(id, UNSUPPORTED_PROTOCOL_VERSION, "Unsupported protocol version");
			resp.getAsJsonObject("error").add("data", data);
			return resp;
		}
		if (!meta.has(META_CLIENT_CAPS) || !meta.get(META_CLIENT_CAPS).isJsonObject()) {
			return error(id, INVALID_PARAMS, "Missing _meta[\"" + META_CLIENT_CAPS + "\"]");
		}
		return switch (method) {
			case "server/discover" -> ok(id, discover(), true);
			case "tools/list" -> {
				if (params.has("cursor") && !params.get("cursor").isJsonNull()) {
					yield error(id, INVALID_PARAMS, "Invalid cursor: this server returns every tool in one page");
				}
				JsonObject r = toolsList();
				r.addProperty("ttlMs", catalogChecked ? TOOLS_TTL_MS : 0);
				r.addProperty("cacheScope", "public");
				yield ok(id, r, true);
			}
			case "tools/call" -> ok(id, toolsCall(params), true);
			case "subscriptions/listen" -> listen(id, params);
			default -> error(id, METHOD_NOT_FOUND, "Method not found: " + method);
		};
	}

	/** A successful response; modern results carry resultType and identify the server. */
	private static JsonObject ok(JsonElement id, JsonObject result, boolean modern) {
		if (modern) {
			result.addProperty("resultType", "complete");
			JsonObject meta = result.has("_meta") ? result.getAsJsonObject("_meta") : new JsonObject();
			meta.add(META_SERVER_INFO, serverInfo());
			result.add("_meta", meta);
		}
		JsonObject resp = new JsonObject();
		resp.addProperty("jsonrpc", "2.0");
		resp.add("id", id);
		resp.add("result", result);
		return resp;
	}

	static JsonObject error(JsonElement id, int code, String message) {
		JsonObject err = new JsonObject();
		err.addProperty("code", code);
		err.addProperty("message", message);
		JsonObject resp = new JsonObject();
		resp.addProperty("jsonrpc", "2.0");
		resp.add("id", id == null ? JsonNull.INSTANCE : id);
		resp.add("error", err);
		return resp;
	}

	private static JsonObject serverInfo() {
		JsonObject info = new JsonObject();
		info.addProperty("name", NAME);
		info.addProperty("version", VERSION);
		return info;
	}

	private static JsonObject capabilities() {
		JsonObject caps = new JsonObject();
		JsonObject tools = new JsonObject();
		tools.addProperty("listChanged", true);
		caps.add("tools", tools);
		return caps;
	}

	// ---------------------------------------------------------------------
	// Methods
	// ---------------------------------------------------------------------

	private JsonObject discover() {
		JsonObject r = new JsonObject();
		JsonArray versions = new JsonArray();
		MODERN.forEach(versions::add);
		r.add("supportedVersions", versions);
		r.add("capabilities", capabilities());
		r.addProperty("instructions", INSTRUCTIONS);
		r.addProperty("ttlMs", TOOLS_TTL_MS);
		r.addProperty("cacheScope", "public");
		return r;
	}

	private JsonObject initialize(JsonObject params) {
		String asked = params.has("protocolVersion") ? params.get("protocolVersion").getAsString() : LEGACY.get(0);
		JsonObject r = new JsonObject();
		r.addProperty("protocolVersion", LEGACY.contains(asked) ? asked : LEGACY.get(0));
		r.add("capabilities", capabilities());
		r.add("serverInfo", serverInfo());
		r.addProperty("instructions", INSTRUCTIONS);
		return r;
	}

	/** subscriptions/listen: acknowledged at once; the response only comes when the stream ends. */
	private JsonObject listen(JsonElement id, JsonObject params) {
		JsonObject asked = params.has("notifications") && params.get("notifications").isJsonObject()
				? params.getAsJsonObject("notifications") : new JsonObject();
		JsonObject honored = new JsonObject();
		boolean tools = asked.has("toolsListChanged") && asked.get("toolsListChanged").getAsBoolean();
		if (tools) {
			honored.addProperty("toolsListChanged", true);
		}
		JsonObject p = new JsonObject();
		JsonObject meta = new JsonObject();
		meta.add(META_SUBSCRIPTION, id);
		p.add("_meta", meta);
		p.add("notifications", honored);
		notifier.accept(notification("notifications/subscriptions/acknowledged", p));
		if (tools) {
			toolSubscriptions.put(id.toString(), id);
		}
		return null;
	}

	/** Ends every open subscription gracefully (the server is shutting down). */
	public void closeSubscriptions(Consumer<JsonObject> out) {
		for (JsonElement id : toolSubscriptions.values()) {
			JsonObject r = new JsonObject();
			JsonObject meta = new JsonObject();
			meta.add(META_SUBSCRIPTION, id);
			r.add("_meta", meta);
			out.accept(ok(id, r, true));
		}
		toolSubscriptions.clear();
	}

	private static JsonObject notification(String method, JsonObject params) {
		JsonObject n = new JsonObject();
		n.addProperty("jsonrpc", "2.0");
		n.addProperty("method", method);
		if (params != null) {
			n.add("params", params);
		}
		return n;
	}

	/**
	 * Called by the transport after it has answered a tools/call: the first
	 * time an instance answers, compare the tool list with the extension's.
	 * If the jar and the installed extension come from different builds the
	 * live list wins and listening clients are told. Never throws.
	 */
	public void afterCall() {
		if (catalogChecked) {
			return;
		}
		try {
			JsonArray live = router.fetchCatalog();
			if (live == null || live.isEmpty()) {
				return; // no Ghidra yet; try again after the next call
			}
			catalogChecked = true;
			if (!live.equals(instanceTools())) {
				catalog = live;
				for (JsonElement id : toolSubscriptions.values()) {
					JsonObject p = new JsonObject();
					JsonObject meta = new JsonObject();
					meta.add(META_SUBSCRIPTION, id);
					p.add("_meta", meta);
					notifier.accept(notification("notifications/tools/list_changed", p));
				}
				if (legacy) {
					notifier.accept(notification("notifications/tools/list_changed", null));
				}
			}
		}
		catch (Exception e) {
			// best effort: the bundled catalog stays
		}
	}

	// ---------------------------------------------------------------------
	// Tools
	// ---------------------------------------------------------------------

	private JsonObject toolsList() {
		JsonArray out = new JsonArray();
		JsonObject listInstances = new JsonObject();
		listInstances.addProperty("name", "list_instances");
		listInstances.addProperty("description", "List every running Ghidra instance with the GhidraMCP plugin and "
				+ "every program open in each, with the program=\"...\" value that names it. Start here.");
		JsonObject input = new JsonObject();
		input.addProperty("type", "object");
		input.add("properties", new JsonObject());
		input.addProperty("additionalProperties", false);
		listInstances.add("inputSchema", input);
		JsonObject ann = new JsonObject();
		ann.addProperty("readOnlyHint", true);
		ann.addProperty("openWorldHint", false);
		listInstances.add("annotations", ann);
		out.add(listInstances);

		for (JsonElement e : instanceTools()) {
			JsonObject t = e.getAsJsonObject().deepCopy();
			JsonObject in = t.getAsJsonObject("inputSchema");
			JsonObject old = in.has("properties") ? in.getAsJsonObject("properties") : new JsonObject();
			JsonObject props = new JsonObject();
			JsonObject program = new JsonObject();
			program.addProperty("type", "string");
			program.addProperty("description", "The program to work on, exactly as list_instances shows it");
			props.add("program", program);
			old.entrySet().forEach(p -> props.add(p.getKey(), p.getValue()));
			in.add("properties", props);
			JsonArray required = new JsonArray();
			required.add("program");
			if (in.has("required")) {
				in.getAsJsonArray("required").forEach(required::add);
			}
			in.add("required", required);
			out.add(t);
		}
		JsonObject r = new JsonObject();
		r.add("tools", out);
		return r;
	}

	private JsonObject toolsCall(JsonObject params) {
		if (!params.has("name") || !params.get("name").isJsonPrimitive()) {
			throw new IllegalArgumentException("tools/call needs a tool name");
		}
		String name = params.get("name").getAsString();
		JsonObject args = params.has("arguments") && params.get("arguments").isJsonObject()
				? params.getAsJsonObject("arguments").deepCopy() : new JsonObject();
		if ("list_instances".equals(name)) {
			return text(false, router.listInstances());
		}
		if (!declared(name)) {
			throw new IllegalArgumentException("Unknown tool: " + name);
		}
		try {
			JsonElement p = args.remove("program");
			if (p == null || p.isJsonNull() || !p.isJsonPrimitive() || p.getAsString().isBlank()) {
				return text(true, "[MISSING_PARAMETER] " + name + " needs program=\"...\": the program to work on, "
						+ "exactly as list_instances shows it. Nothing is chosen for you, because a wrong choice "
						+ "writes into the wrong program and nothing in the answer would say so.");
			}
			Target t = router.resolve(p.getAsString());
			Router.Result r = router.call(t, clientTag, name, args);
			return text(!r.ok(), r.ok() ? r.text() : "[" + (r.code() != null ? r.code() : "ERROR") + "] " + r.text());
		}
		catch (RouterError e) {
			return text(true, "[" + e.code() + "] " + e.getMessage());
		}
	}

	private boolean declared(String name) {
		for (JsonElement e : instanceTools()) {
			if (e.getAsJsonObject().get("name").getAsString().equals(name)) {
				return true;
			}
		}
		return false;
	}

	static JsonObject text(boolean isError, String text) {
		JsonObject c = new JsonObject();
		c.addProperty("type", "text");
		c.addProperty("text", text);
		JsonArray content = new JsonArray();
		content.add(c);
		JsonObject r = new JsonObject();
		r.add("content", content);
		r.addProperty("isError", isError);
		return r;
	}
}
