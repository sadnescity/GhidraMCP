package com.lauriewired.mcp;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Finds Ghidra instances and sends each call to the program it names. These
 * rules come from losing work to their absence:
 *
 * <ul>
 * <li><b>The target is a program, never a port.</b> Which game answers on
 * 8080 is decided by boot order and changes between restarts.</li>
 * <li><b>Every call names its program.</b> Nothing is remembered between
 * calls (MCP 2026-07-28 is stateless, and one server process may serve
 * several conversations or subagents at once), so no call can be sent to a
 * program because someone else chose it earlier.</li>
 * <li><b>Nothing is chosen implicitly.</b> No default, no auto-selection when
 * only one program is open, and a name open in two places is refused rather
 * than guessed: two programs built from one engine share addresses, so a call
 * answered by the wrong database returns a plausible answer and a write lands
 * silently in the wrong game.</li>
 * <li><b>The program is looked up on every port at every call</b>, so an
 * instance that restarted on another port is simply found there. A port that
 * does not answer in time is not taken as empty: the program might be open
 * there too, so the call is refused until it answers.</li>
 * <li><b>Every call names the database</b> it means (X-Ghidra-File-ID), so the
 * instance itself refuses anything it does not have open, even if the
 * program closed between the lookup and the call.</li>
 * </ul>
 */
public final class Router {

	public static final String FILE_ID_HEADER = "X-Ghidra-File-ID";
	public static final String CLIENT_HEADER = "X-Ghidra-Session";
	public static final String CALL_ID_HEADER = "X-Ghidra-Call-ID";

	private final int basePort;
	private final int range;
	private final Duration callTimeout;
	private final HttpClient http;
	private final ExecutorService pool = Executors.newFixedThreadPool(16, r -> {
		Thread t = new Thread(r, "GhidraMCP-discovery");
		t.setDaemon(true);
		return t;
	});

	public Router(int basePort, int range, Duration callTimeout) {
		this.basePort = basePort;
		this.range = range;
		this.callTimeout = callTimeout;
		this.http = HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(2))
				.proxy(java.net.ProxySelector.of(null))
				.version(HttpClient.Version.HTTP_1_1)
				.build();
	}

	// ---------------------------------------------------------------------
	// Discovery
	// ---------------------------------------------------------------------

	static final Duration SCAN_TIMEOUT = Duration.ofMillis(1500);

	/** Thrown by {@link #ask} when a port accepted the connection but did not answer in time. */
	static final class Silent extends Exception {
		Silent() {
			super(null, null, false, false);
		}
	}

	/**
	 * Ask one port what it is. Null if nothing answers there as a GhidraMCP
	 * instance (nothing listening, or something else that answers); {@link Silent}
	 * if it does not answer in time, which may be a Ghidra that is stuck.
	 */
	Instance ask(int port, Duration timeout) throws Silent, InterruptedException {
		try {
			HttpRequest req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/instances"))
					.timeout(timeout).GET().build();
			HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
			if (resp.statusCode() != 200) {
				return null;
			}
			JsonElement body = JsonParser.parseString(resp.body());
			JsonArray arr = body.isJsonArray() ? body.getAsJsonArray() : new JsonArray();
			for (JsonElement e : arr) {
				Instance i = Instance.fromJson(e.getAsJsonObject());
				if (i.port() == port) {
					return i;
				}
			}
		}
		catch (java.net.http.HttpTimeoutException e) {
			throw new Silent();
		}
		catch (InterruptedException e) {
			throw e;
		}
		catch (Exception e) {
			// nothing usable there
		}
		return null;
	}

	/** What a scan found: the instances that answered, and the ports that did not answer in time. */
	public record Scan(Map<Integer, Instance> found, List<Integer> silent) {
	}

	/**
	 * Ask EVERY port in the range, in parallel, and merge the answers.
	 *
	 * @throws RouterError CANCELLED if interrupted: a partial scan must not be used.
	 */
	public Scan scan() {
		Map<Integer, Future<Instance>> futures = new TreeMap<>();
		for (int p = basePort; p < basePort + range; p++) {
			int port = p;
			futures.put(port, pool.submit(() -> ask(port, SCAN_TIMEOUT)));
		}
		Map<Integer, Instance> found = new TreeMap<>();
		List<Integer> silent = new ArrayList<>();
		for (Map.Entry<Integer, Future<Instance>> e : futures.entrySet()) {
			try {
				Instance i = e.getValue().get();
				if (i != null) {
					found.put(e.getKey(), i);
				}
			}
			catch (InterruptedException ex) {
				futures.values().forEach(f -> f.cancel(true));
				Thread.currentThread().interrupt();
				throw new RouterError("CANCELLED", "Cancelled while looking for Ghidra. Nothing was sent.");
			}
			catch (ExecutionException ex) {
				if (ex.getCause() instanceof Silent) {
					silent.add(e.getKey());
				}
			}
		}
		return new Scan(found, silent);
	}

	/** The instances that answered a scan. */
	public Map<Integer, Instance> discover() {
		return scan().found();
	}

	/** One open program, where it is, and the shortest name that picks it out. */
	record Open(Instance instance, Instance.Program program, String id) {
		Target target() {
			return new Target(instance.port(), program.name(), instance.project(), program.fileId());
		}
	}

	/**
	 * Every open program, each with the identifier a call should pass: its name
	 * when that is unique, otherwise project:path, otherwise (two projects of
	 * the same name) its file id. Two copies of one project open in two Ghidra
	 * processes share even the file id, and stay ambiguous.
	 */
	static List<Open> open(Map<Integer, Instance> found) {
		// One database open in two windows of the same Ghidra is one program:
		// keep the window that has it in front, else the lowest port.
		Map<String, Instance> where = new LinkedHashMap<>();
		Map<String, Instance.Program> what = new LinkedHashMap<>();
		int unshared = 0;
		for (Instance i : found.values()) {
			for (Instance.Program p : i.programs()) {
				String key = i.pid() < 0 ? "?" + unshared++
						: i.pid() + "\0" + i.project() + "\0" + (p.fileId() != null ? p.fileId() : qualified(i, p));
				Instance seen = where.get(key);
				if (seen == null || (!inFront(seen, what.get(key)) && inFront(i, p))) {
					where.put(key, i);
					what.put(key, p);
				}
			}
		}
		Map<String, Integer> names = new HashMap<>();
		Map<String, Integer> paths = new HashMap<>();
		Map<String, Integer> fileIds = new HashMap<>();
		for (String key : where.keySet()) {
			Instance.Program p = what.get(key);
			names.merge(String.valueOf(p.name()), 1, Integer::sum);
			paths.merge(qualified(where.get(key), p), 1, Integer::sum);
			fileIds.merge(String.valueOf(p.fileId()), 1, Integer::sum);
		}
		List<Open> out = new ArrayList<>();
		for (String key : where.keySet()) {
			Instance i = where.get(key);
			Instance.Program p = what.get(key);
			String id = names.get(String.valueOf(p.name())) == 1 ? p.name()
					: paths.get(qualified(i, p)) == 1 || p.fileId() == null || fileIds.get(p.fileId()) > 1
							? qualified(i, p) : p.fileId();
			out.add(new Open(i, p, id));
		}
		out.sort((a, b) -> Integer.compare(a.instance().port(), b.instance().port()));
		return out;
	}

	private static boolean inFront(Instance i, Instance.Program p) {
		return p.name() != null && p.name().equals(i.current());
	}

	static String qualified(Instance i, Instance.Program p) {
		return i.project() + ":" + (p.path() != null ? p.path() : "/" + p.name());
	}

	static String listing(List<Open> open) {
		if (open.isEmpty()) {
			return "none";
		}
		StringBuilder sb = new StringBuilder();
		for (Open o : open) {
			sb.append(sb.length() == 0 ? "" : ", ").append('"').append(o.id()).append('"');
		}
		return sb.toString();
	}

	/** list_instances */
	public String listInstances() {
		Scan scan = scan();
		Map<Integer, Instance> found = scan.found();
		String silent = scan.silent().isEmpty() ? ""
				: "\nPort(s) " + joined(scan.silent()) + " did not answer within " + SCAN_TIMEOUT.toMillis()
						+ " ms (a Ghidra that is stuck, or another program on the port). While that lasts every "
						+ "call is refused, because the program it names might also be open there.";
		if (found.isEmpty()) {
			return "No Ghidra instance found on ports " + basePort + "-" + (basePort + range - 1)
					+ ". Start Ghidra, open a program in the CodeBrowser and make sure the GhidraMCP plugin is enabled."
					+ silent;
		}
		List<Open> open = open(found);
		Map<String, Integer> idCount = new HashMap<>();
		open.forEach(o -> idCount.merge(o.id(), 1, Integer::sum));
		Map<Integer, List<Open>> byPort = new LinkedHashMap<>();
		for (Open o : open) {
			byPort.computeIfAbsent(o.instance().port(), k -> new ArrayList<>()).add(o);
		}
		StringBuilder sb = new StringBuilder();
		boolean twins = false;
		for (Instance i : found.values()) {
			sb.append("Port ").append(i.port()).append(", project ").append(i.project()).append(":\n");
			List<Open> here = byPort.getOrDefault(i.port(), List.of());
			if (here.isEmpty()) {
				sb.append(i.programs().isEmpty() ? "  (no program open)\n"
						: "  (another window of the same Ghidra; its programs are listed there)\n");
			}
			for (Open o : here) {
				sb.append("  program=\"").append(o.id()).append('"');
				if (o.program().name() != null && o.program().name().equals(i.current())) {
					sb.append("  (in front)");
				}
				if (idCount.get(o.id()) > 1) {
					sb.append("  -- open twice, cannot be used");
					twins = true;
				}
				sb.append('\n');
			}
		}
		sb.append("Pass program=\"...\" exactly as shown on every call.");
		if (twins) {
			sb.append(" A program marked \"open twice\" is the same database open in two copies of one project "
					+ "(two Ghidra processes); close one of them to use it.");
		}
		return sb.append(silent).toString();
	}

	private static String joined(List<Integer> ports) {
		return String.join(", ", ports.stream().map(String::valueOf).toList());
	}

	/**
	 * The one open program a call names: by the identifier list_instances shows
	 * (name, or project:path), or by file id. Refuses rather than guesses.
	 */
	public Target resolve(String program) {
		Scan scan = scan();
		Map<Integer, Instance> found = scan.found();
		List<Open> open = open(found);
		List<Open> matches = new ArrayList<>();
		for (Open o : open) {
			Instance.Program p = o.program();
			if (program.equals(o.id()) || program.equals(p.name()) || program.equals(qualified(o.instance(), p))
					|| program.equals(p.fileId())) {
				matches.add(o);
			}
		}
		if (matches.size() <= 1 && !scan.silent().isEmpty()) {
			throw new RouterError("BUSY", "Port(s) " + joined(scan.silent()) + " did not answer within "
					+ SCAN_TIMEOUT.toMillis() + " ms, so it cannot be ruled out that '" + program
					+ "' is open there too. Nothing was sent. Retry; if it persists, that Ghidra is stuck or "
					+ "another program holds the port.");
		}
		if (matches.isEmpty()) {
			if (found.isEmpty()) {
				throw new RouterError("NO_GHIDRA", "No Ghidra instance is running on ports " + basePort + "-"
						+ (basePort + range - 1) + ", so '" + program + "' is not open anywhere. Nothing was sent.");
			}
			throw new RouterError("PROGRAM_NOT_FOUND", "No Ghidra instance has '" + program
					+ "' open. Nothing was sent. Open programs: " + listing(open) + ".");
		}
		if (matches.size() > 1) {
			List<String> ids = new ArrayList<>();
			boolean twins = false;
			for (Open o : matches) {
				String q = "\"" + o.id() + "\"";
				twins |= ids.contains(q);
				ids.add(q);
			}
			throw new RouterError("AMBIGUOUS", "'" + program + "' is open " + matches.size() + " times: "
					+ String.join(", ", ids) + " (ports " + String.join(", ",
							matches.stream().map(o -> "" + o.instance().port()).toList()) + "). Nothing was sent. "
					+ (twins ? "The same database is open in two copies of one project; close one of them."
							: "Pass one of these as program=."));
		}
		return matches.get(0).target();
	}

	// ---------------------------------------------------------------------
	// Sending
	// ---------------------------------------------------------------------

	/** The result of one forwarded tool call. */
	public record Result(boolean ok, String code, String text) {
	}

	/** Sends a tool call to the target's instance and returns what it answered. */
	public Result call(Target t, String clientTag, String tool, JsonObject args) {
		JsonObject body = new JsonObject();
		body.addProperty("tool", tool);
		body.add("args", args);
		HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + t.port() + "/mcp/call"))
				.timeout(callTimeout)
				.header("Content-Type", "application/json; charset=utf-8")
				.POST(HttpRequest.BodyPublishers.ofString(body.toString()));
		if (t.fileId() != null) {
			rb.header(FILE_ID_HEADER, t.fileId());
		}
		if (clientTag != null && !clientTag.isEmpty()) {
			rb.header(CLIENT_HEADER, clientTag);
		}
		String callId = java.util.UUID.randomUUID().toString();
		rb.header(CALL_ID_HEADER, callId);
		HttpResponse<String> resp;
		try {
			resp = http.send(rb.build(), HttpResponse.BodyHandlers.ofString());
		}
		catch (java.net.http.HttpTimeoutException e) {
			cancelInGhidra(t.port(), callId);
			throw new RouterError("TIMEOUT", "Ghidra did not answer " + tool + " within "
					+ callTimeout.toSeconds() + " s, so it was asked to stop. Long reads and emulation stop; "
					+ "a write may still complete, so check before repeating it.");
		}
		catch (InterruptedException e) {
			cancelInGhidra(t.port(), callId);
			Thread.currentThread().interrupt();
			throw new RouterError("CANCELLED", "Cancelled; Ghidra was asked to stop " + tool
					+ " (a write may still complete).");
		}
		catch (Exception e) {
			throw new RouterError("UNREACHABLE", "Could not reach Ghidra on port " + t.port() + ": " + e);
		}
		JsonObject r;
		try {
			r = JsonParser.parseString(resp.body()).getAsJsonObject();
		}
		catch (Exception e) {
			if (resp.statusCode() == 404) {
				throw new RouterError("OLD_PLUGIN", "The GhidraMCP plugin on port " + t.port()
						+ " does not speak this protocol: update the Ghidra extension.");
			}
			throw new RouterError("BAD_RESPONSE", "HTTP " + resp.statusCode() + ": " + resp.body());
		}
		boolean ok = r.has("ok") && r.get("ok").getAsBoolean();
		String code = r.has("code") && !r.get("code").isJsonNull() ? r.get("code").getAsString() : null;
		String text = r.has("text") && !r.get("text").isJsonNull() ? r.get("text").getAsString() : "";
		return new Result(ok, code, text);
	}

	/**
	 * Tells the instance to stop a call the client gave up on (or to skip it
	 * if it is still queued). Fire and forget: the answer is not awaited.
	 */
	void cancelInGhidra(int port, String callId) {
		try {
			HttpRequest req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/mcp/cancel"))
					.timeout(Duration.ofSeconds(2))
					.header(CALL_ID_HEADER, callId)
					.POST(HttpRequest.BodyPublishers.noBody())
					.build();
			http.sendAsync(req, HttpResponse.BodyHandlers.discarding());
		}
		catch (Exception e) {
			// The instance is gone or busy closing; nothing left to stop.
		}
	}

	/** The tool schemas from any reachable instance, or an empty list. */
	public JsonArray fetchCatalog() {
		for (Instance i : discover().values()) {
			try {
				HttpRequest req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + i.port() + "/mcp/tools"))
						.timeout(Duration.ofSeconds(3)).GET().build();
				HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
				if (resp.statusCode() == 200) {
					return JsonParser.parseString(resp.body()).getAsJsonArray();
				}
			}
			catch (Exception e) {
				// try the next
			}
		}
		return new JsonArray();
	}
}
