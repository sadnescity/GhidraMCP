package com.lauriewired.core;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Supplier;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * One Ghidra tool's endpoint on loopback: says what it holds (/instances,
 * /health), lists its tools (/mcp/tools) and runs them (/mcp/call).
 *
 * <p>Tool calls are run one at a time, on one thread: the decompiler cache and
 * Ghidra's own decompiler interface are not thread-safe, and one analyst's
 * Ghidra has no use for two concurrent writes anyway. The questions the bridge
 * asks to find programs (/instances, /health, /mcp/tools) are answered on
 * other threads, so an instance busy with a long call still says what it has
 * open: one that went quiet would look absent to the bridge, and a name it
 * shares with another instance would then look unique.
 */
public final class InstanceServer {

	/** Version of this endpoint's protocol, reported on /instances and /health. */
	public static final String VERSION = "4.0.0";
	/** The database a call is for. Required: a call never falls back to the program in front. */
	public static final String FILE_ID_HEADER = "X-Ghidra-File-ID";
	/** Names the MCP client in the undo history. */
	public static final String CLIENT_HEADER = "X-Ghidra-Session";
	private static final Set<String> LOCAL_HOSTS = Set.of("127.0.0.1", "localhost", "[::1]", "::1");

	private final PluginTool tool;
	private final ToolRegistry registry;
	private final Services services;
	private final Supplier<Program> current;
	private HttpServer server;
	/** Answers HTTP requests; a tool call waits on one of these for its turn on {@link #calls}. */
	private ExecutorService http;
	/** Runs the tool calls, one at a time. */
	private volatile ExecutorService calls;
	private int port = -1;

	public InstanceServer(PluginTool tool, ToolRegistry registry, Services services, Supplier<Program> current) {
		this.tool = tool;
		this.registry = registry;
		this.services = services;
		this.current = current;
	}

	public int port() {
		return port;
	}

	/** Starts on the first free port at or above basePort. */
	public synchronized int start(int basePort, int scan) throws IOException {
		IOException last = null;
		for (int p = basePort; p < basePort + scan; p++) {
			try {
				if (!free(p)) {
					continue;
				}
				HttpServer s = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), p), 0);
				s.createContext("/", this::dispatch);
				http = Executors.newFixedThreadPool(4, r -> {
					Thread t = new Thread(r, "GhidraMCP-http-" + r.hashCode());
					t.setDaemon(true);
					return t;
				});
				calls = Executors.newSingleThreadExecutor(r -> {
					Thread t = new Thread(r, "GhidraMCP-calls-" + r.hashCode());
					t.setDaemon(true);
					return t;
				});
				s.setExecutor(http);
				s.start();
				server = s;
				port = p;
				return p;
			}
			catch (IOException e) {
				last = e;
			}
		}
		throw new IOException("No free port in " + basePort + "-" + (basePort + scan - 1), last);
	}

	private static boolean free(int p) {
		try (ServerSocket ss = new ServerSocket()) {
			ss.setReuseAddress(true);
			ss.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), p));
			return true;
		}
		catch (IOException e) {
			return false;
		}
	}

	public synchronized void stop() {
		if (server != null) {
			server.stop(0);
			server = null;
		}
		if (calls != null) {
			calls.shutdownNow();
			calls = null;
		}
		if (http != null) {
			http.shutdownNow();
			http = null;
		}
		port = -1;
	}

	// ---------------------------------------------------------------------

	private void dispatch(HttpExchange ex) throws IOException {
		try {
			if (ex.getRequestHeaders().containsKey("Origin")
					|| !hostAllowed(ex.getRequestHeaders().getFirst("Host"))) {
				// A browser page must not be able to drive the analyst's Ghidra.
				send(ex, 403, "text/plain", "Cross-origin requests are not allowed");
				return;
			}
			String path = ex.getRequestURI().getPath();
			switch (path) {
				case "/instances" -> send(ex, 200, "application/json", instances().toString());
				case "/health" -> send(ex, 200, "application/json", health().toString());
				case "/mcp/tools" -> send(ex, 200, "application/json", registry.schema().toString());
				case "/mcp/call" -> call(ex);
				default -> send(ex, 404, "text/plain", "Unknown endpoint " + path
						+ ". This plugin speaks MCP through /mcp/call; update any old bridge.");
			}
		}
		catch (IOException e) {
			// The bridge stopped waiting (its call timed out or was cancelled).
			Msg.info(this, "GhidraMCP: the client went away before the reply (" + e.getMessage() + ")");
		}
		catch (Throwable t) {
			Msg.error(this, "GhidraMCP request failed", t);
			send(ex, 500, "application/json", failure("INTERNAL_ERROR", t.toString()).toString());
		}
	}

	/** Only loopback names: a DNS-rebinding page arrives with its own host name. */
	static boolean hostAllowed(String host) {
		if (host == null) {
			return true;
		}
		String h = host;
		int colon = h.lastIndexOf(':');
		if (colon > 0 && h.indexOf(']') < colon) {
			h = h.substring(0, colon);
		}
		return LOCAL_HOSTS.contains(h.toLowerCase());
	}

	/** A tool call's answer and the HTTP status it goes back with. */
	private record Reply(int status, JsonObject body) {
	}

	private void call(HttpExchange ex) throws IOException {
		if (!"POST".equals(ex.getRequestMethod())) {
			send(ex, 405, "text/plain", "POST only");
			return;
		}
		JsonObject req = JsonParser.parseString(new String(ex.getRequestBody().readAllBytes(),
				StandardCharsets.UTF_8)).getAsJsonObject();
		String name = req.get("tool").getAsString();
		JsonObject args = req.has("args") && req.get("args").isJsonObject() ? req.getAsJsonObject("args") : new JsonObject();
		String fileId = ex.getRequestHeaders().getFirst(FILE_ID_HEADER);
		String session = ex.getRequestHeaders().getFirst(CLIENT_HEADER);

		if (fileId == null || fileId.isEmpty()) {
			send(ex, 400, "application/json", failure("NO_PROGRAM",
					"The call names no program (" + FILE_ID_HEADER + "). Nothing was done.").toString());
			return;
		}
		ExecutorService runner = calls;
		Reply reply;
		try {
			if (runner == null) {
				throw new RejectedExecutionException();
			}
			Future<Reply> f = runner.submit(() -> run(name, args, fileId, session));
			reply = f.get();
		}
		catch (InterruptedException | RejectedExecutionException e) {
			send(ex, 503, "application/json", failure("UNAVAILABLE",
					"This Ghidra tool is closing; " + name + " may not have run.").toString());
			return;
		}
		catch (ExecutionException e) {
			Throwable cause = e.getCause() != null ? e.getCause() : e;
			Msg.error(this, "GhidraMCP tool " + name + " failed", cause);
			send(ex, 500, "application/json", failure("INTERNAL_ERROR", cause.toString()).toString());
			return;
		}
		send(ex, reply.status(), "application/json", reply.body().toString());
	}

	/** One tool call, on the call thread. */
	private Reply run(String name, JsonObject args, String fileId, String session) {
		Program program = openProgram(fileId);
		// Held for the call, so closing the program in the UI meanwhile does not
		// destroy it under the tool; it closes when the call releases it.
		if (program != null && !program.addConsumer(this)) {
			program = null;
		}
		if (program == null) {
			Msg.warn(this, "Refused a call for file id " + fileId + " on port " + port);
			return new Reply(409, failure("NOT_HERE", "This Ghidra instance (port " + port + ", project "
					+ projectName() + ") does not have file id " + fileId + " open; it has: " + openList()
					+ ". Nothing was done."));
		}
		try {
			Ctx ctx = new Ctx(tool, program, session, services);
			String text = registry.invoke(name, args, ctx);
			JsonObject r = new JsonObject();
			r.addProperty("ok", true);
			r.addProperty("text", text == null ? "" : text);
			return new Reply(200, r);
		}
		catch (ToolError e) {
			if ("INTERNAL_ERROR".equals(e.code())) {
				Msg.error(this, "GhidraMCP tool " + name + " failed", e.getCause() != null ? e.getCause() : e);
			}
			return new Reply(200, failure(e.code(), e.getMessage()));
		}
		finally {
			program.release(this);
		}
	}

	private static JsonObject failure(String code, String text) {
		JsonObject r = new JsonObject();
		r.addProperty("ok", false);
		r.addProperty("code", code);
		r.addProperty("text", text);
		return r;
	}

	private Program[] open() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		return pm == null ? new Program[0] : pm.getAllOpenPrograms();
	}

	private Program openProgram(String fileId) {
		for (Program p : open()) {
			DomainFile df = p.getDomainFile();
			if (df != null && fileId.equals(df.getFileID())) {
				return p;
			}
		}
		return null;
	}

	private String openList() {
		StringBuilder sb = new StringBuilder();
		for (Program p : open()) {
			sb.append(sb.length() == 0 ? "" : ", ").append(name(p));
		}
		return sb.length() == 0 ? "nothing" : sb.toString();
	}

	private String projectName() {
		return tool.getProject() != null ? tool.getProject().getName() : null;
	}

	/** This instance as discovery sees it: its port, project, program in front, and every open program. */
	public JsonArray instances() {
		JsonObject me = new JsonObject();
		me.addProperty("port", port);
		me.addProperty("project", projectName());
		Program cur = current.get();
		me.addProperty("program", cur != null ? name(cur) : null);
		me.addProperty("file_id", cur != null && cur.getDomainFile() != null ? cur.getDomainFile().getFileID() : null);
		JsonArray progs = new JsonArray();
		for (Program p : open()) {
			JsonObject o = new JsonObject();
			o.addProperty("name", name(p));
			o.addProperty("file_id", p.getDomainFile() != null ? p.getDomainFile().getFileID() : null);
			o.addProperty("path", p.getDomainFile() != null ? p.getDomainFile().getPathname() : null);
			progs.add(o);
		}
		me.add("programs", progs);
		me.addProperty("pid", ProcessHandle.current().pid());
		me.addProperty("version", VERSION);
		JsonArray arr = new JsonArray();
		arr.add(me);
		return arr;
	}

	private static String name(Program p) {
		return p.getDomainFile() != null ? p.getDomainFile().getName() : p.getName();
	}

	private JsonObject health() {
		JsonObject h = new JsonObject();
		h.addProperty("status", "ok");
		h.addProperty("version", VERSION);
		h.addProperty("port", port);
		h.addProperty("tools", registry.all().size());
		return h;
	}

	private static void send(HttpExchange ex, int status, String type, String body) throws IOException {
		byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
		ex.getResponseHeaders().set("Content-Type", type + "; charset=utf-8");
		ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
		if (bytes.length > 0) {
			try (OutputStream os = ex.getResponseBody()) {
				os.write(bytes);
			}
		}
		else {
			ex.close();
		}
	}
}
