package com.lauriewired.mcp;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * The MCP server on stdin/stdout: {@code java -jar ghidra-mcp-bridge.jar}.
 * Needs only a JDK -- no Python, no SDK. The client starts it, so it is up
 * whether or not Ghidra is, and finds Ghidra whenever it opens.
 */
public final class StdioMain {

	private StdioMain() {
	}

	public static void main(String[] args) throws Exception {
		int base = 8080;
		int range = 100;
		int timeout = 120;
		for (int i = 0; i < args.length; i++) {
			switch (args[i]) {
				case "--discovery-base-port" -> base = Integer.parseInt(args[++i]);
				case "--discovery-range" -> range = Integer.parseInt(args[++i]);
				case "--ghidra-timeout" -> timeout = Integer.parseInt(args[++i]);
				case "--version" -> {
					System.out.println(McpServer.NAME + " " + McpServer.VERSION + " (MCP " + McpServer.MODERN.get(0)
							+ "; legacy " + String.join(", ", McpServer.LEGACY) + ")");
					return;
				}
				default -> {
					System.err.println("Unknown argument " + args[i] + ". Options: --discovery-base-port N, "
							+ "--discovery-range N, --ghidra-timeout SECONDS, --version");
					System.exit(2);
				}
			}
		}
		// stdout carries the protocol: nothing else may write to it.
		PrintStream protocolOut = System.out;
		System.setOut(System.err);
		Writer out = new OutputStreamWriter(protocolOut, StandardCharsets.UTF_8);
		Object lock = new Object();

		Router router = new Router(base, range, Duration.ofSeconds(timeout));
		JsonArray bundled = McpServer.bundledCatalog();
		// Names this client in Ghidra's undo history, e.g. "rename_function [3f2a9c1e]".
		String sid = System.getenv("CLAUDE_CODE_SESSION_ID");
		McpServer server = new McpServer(router, () -> bundled != null ? bundled : router.fetchCatalog(),
				sid != null ? sid.split("-")[0] : null, n -> send(out, lock, n));

		// Tool calls run concurrently (a long decompile does not hold up a
		// listing); each Ghidra instance still serializes its own work. Everything
		// else -- discover, tools/list, list_instances, subscriptions -- has its own
		// threads, so it is answered even while every call waits on a slow Ghidra.
		ExecutorService calls = Executors.newFixedThreadPool(4, daemon("GhidraMCP-call"));
		ExecutorService control = Executors.newCachedThreadPool(daemon("GhidraMCP-control"));
		Map<String, Request> inFlight = new ConcurrentHashMap<>();

		BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
		String line;
		while ((line = in.readLine()) != null) {
			if (line.isBlank()) {
				continue;
			}
			try {
				dispatch(line, server, out, lock, calls, control, inFlight);
			}
			catch (RuntimeException e) {
				// One bad message must not take the server down with it.
				System.err.println("Ignored a message that could not be handled: " + e);
			}
		}
		// The client closed stdin: finish what is running, end subscriptions, exit.
		calls.shutdown();
		control.shutdown();
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
		calls.awaitTermination(5, TimeUnit.SECONDS);
		control.awaitTermination(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
		server.closeSubscriptions(r -> send(out, lock, r));
		System.exit(0);
	}

	/** One request being worked on. Cancelled means: send nothing more for it. */
	static final class Request {
		volatile boolean cancelled;
		volatile Future<?> future;
	}

	private static java.util.concurrent.ThreadFactory daemon(String name) {
		return r -> {
			Thread t = new Thread(r, name);
			t.setDaemon(true);
			return t;
		};
	}

	static void dispatch(String line, McpServer server, Writer out, Object lock, ExecutorService calls,
			ExecutorService control, Map<String, Request> inFlight) {
		JsonElement parsed;
		try {
			parsed = JsonParser.parseString(line);
		}
		catch (Exception e) {
			send(out, lock, McpServer.error(JsonNull.INSTANCE, -32700, "Parse error"));
			return;
		}
		if (!parsed.isJsonObject()) {
			send(out, lock, McpServer.error(JsonNull.INSTANCE, -32600, "Invalid request"));
			return;
		}
		JsonObject msg = parsed.getAsJsonObject();
		JsonElement id = msg.get("id");
		String method = msg.has("method") && msg.get("method").isJsonPrimitive()
				? msg.get("method").getAsString() : "";
		JsonObject params = msg.has("params") && msg.get("params").isJsonObject() ? msg.getAsJsonObject("params")
				: null;
		if (id == null || id.isJsonNull()) {
			if ("notifications/cancelled".equals(method) && params != null && params.has("requestId")) {
				// No further message may be sent for a cancelled request.
				String key = params.get("requestId").toString();
				Request r = inFlight.remove(key);
				if (r != null) {
					r.cancelled = true;
					Future<?> f = r.future;
					if (f != null) {
						f.cancel(true);
					}
				}
			}
			server.handle(msg);
			return;
		}
		String key = id.toString();
		boolean toolCall = "tools/call".equals(method);
		boolean longCall = toolCall && !(params != null && params.get("name") instanceof JsonElement n
				&& n.isJsonPrimitive() && "list_instances".equals(n.getAsString()));
		Request req = new Request();
		inFlight.put(key, req);
		req.future = (longCall ? calls : control).submit(() -> {
			try {
				JsonObject resp = server.handle(msg);
				if (resp != null && !req.cancelled) {
					send(out, lock, resp);
				}
				if (toolCall) {
					server.afterCall();
				}
			}
			finally {
				inFlight.remove(key, req);
			}
		});
	}

	static void send(Writer out, Object lock, JsonObject msg) {
		synchronized (lock) {
			try {
				out.write(msg.toString());
				out.write('\n');
				out.flush();
			}
			catch (Exception e) {
				System.err.println("Could not write a message: " + e);
			}
		}
	}
}
