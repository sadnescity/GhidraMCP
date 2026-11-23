package com.lauriewired.mcp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * The targeting rules and the MCP protocol, against fake Ghidra instances on
 * a private port range far from the real ones (8080+): a router that regained
 * a habit of choosing for itself still could not reach a real database from a
 * test.
 */
public class McpServerTest {

	static final String CATALOG = "[{\"name\":\"decompile_function\",\"description\":\"d\","
			+ "\"inputSchema\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},"
			+ "\"required\":[\"name\"]}}]";

	/** A fake Ghidra: answers /instances and /mcp/tools, records /mcp/call. */
	static final class Fake {
		final int port;
		final String project;
		final List<String[]> programs = new CopyOnWriteArrayList<>(); // {name, fileId}
		final List<Map<String, String>> calls = new CopyOnWriteArrayList<>();
		volatile String catalog = CATALOG;
		volatile boolean silent;
		volatile boolean refuse;
		volatile long pid = -1;
		final CountDownLatch release = new CountDownLatch(1);
		final HttpServer server;

		Fake(int port, String project, String... nameAndIds) throws IOException {
			this.port = port;
			this.project = project;
			for (int i = 0; i < nameAndIds.length; i += 2) {
				programs.add(new String[] { nameAndIds[i], nameAndIds[i + 1] });
			}
			server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
			server.createContext("/", this::handle);
			server.setExecutor(Executors.newCachedThreadPool());
			server.start();
		}

		void handle(HttpExchange ex) throws IOException {
			String path = ex.getRequestURI().getPath();
			byte[] body = ex.getRequestBody().readAllBytes();
			if (silent) {
				try {
					release.await();
				}
				catch (InterruptedException e) {
					return;
				}
			}
			if (path.equals("/instances")) {
				JsonObject me = new JsonObject();
				me.addProperty("port", port);
				me.addProperty("project", project);
				me.addProperty("program", programs.isEmpty() ? null : programs.get(0)[0]);
				JsonArray ps = new JsonArray();
				for (String[] p : programs) {
					JsonObject o = new JsonObject();
					o.addProperty("name", p[0]);
					o.addProperty("file_id", p[1]);
					o.addProperty("path", "/" + p[0]);
					ps.add(o);
				}
				me.add("programs", ps);
				if (pid >= 0) {
					me.addProperty("pid", pid);
				}
				JsonArray arr = new JsonArray();
				arr.add(me);
				reply(ex, 200, arr.toString());
				return;
			}
			if (path.equals("/mcp/tools")) {
				reply(ex, 200, catalog);
				return;
			}
			if (path.equals("/mcp/call")) {
				JsonObject req = JsonParser.parseString(new String(body, StandardCharsets.UTF_8)).getAsJsonObject();
				String fid = ex.getRequestHeaders().getFirst(Router.FILE_ID_HEADER);
				Map<String, String> rec = new ConcurrentHashMap<>();
				rec.put("tool", req.get("tool").getAsString());
				rec.put("args", req.get("args").toString());
				if (fid != null) {
					rec.put("file_id", fid);
				}
				String client = ex.getRequestHeaders().getFirst(Router.CLIENT_HEADER);
				if (client != null) {
					rec.put("client", client);
				}
				calls.add(rec);
				boolean mine = !refuse && fid != null && programs.stream().anyMatch(p -> p[1].equals(fid));
				JsonObject r = new JsonObject();
				r.addProperty("ok", mine);
				if (!mine) {
					r.addProperty("code", "NOT_HERE");
				}
				r.addProperty("text", mine ? "answer from " + port + " for " + fid : "not here");
				reply(ex, mine ? 200 : 409, r.toString());
				return;
			}
			reply(ex, 404, "{}");
		}

		static void reply(HttpExchange ex, int status, String s) throws IOException {
			byte[] b = s.getBytes(StandardCharsets.UTF_8);
			ex.sendResponseHeaders(status, b.length);
			try (OutputStream os = ex.getResponseBody()) {
				os.write(b);
			}
		}

		void stop() {
			release.countDown();
			server.stop(0);
		}
	}

	private int base;
	private final List<Fake> fakes = new ArrayList<>();
	private final List<JsonObject> notes = new CopyOnWriteArrayList<>();
	private McpServer server;
	private Router router;
	private int nextId;

	@Before
	public void setUp() throws IOException {
		base = freeBlock(4);
		router = new Router(base, 4, Duration.ofSeconds(3));
		JsonArray catalog = JsonParser.parseString(CATALOG).getAsJsonArray();
		server = new McpServer(router, () -> catalog, "sess1234", notes::add);
	}

	@After
	public void tearDown() {
		fakes.forEach(Fake::stop);
	}

	private Fake fake(int offset, String project, String... nameAndIds) throws IOException {
		Fake f = new Fake(base + offset, project, nameAndIds);
		fakes.add(f);
		return f;
	}

	private static int freeBlock(int size) {
		for (int b = 18180; b < 18900; b += size) {
			boolean ok = true;
			for (int i = 0; i < size && ok; i++) {
				try (ServerSocket s = new ServerSocket()) {
					s.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), b + i));
				}
				catch (IOException e) {
					ok = false;
				}
			}
			if (ok) {
				return b;
			}
		}
		throw new IllegalStateException("no free port block");
	}

	// ---------------------------------------------------------------------
	// Helpers: modern (2026-07-28) requests
	// ---------------------------------------------------------------------

	private static JsonObject meta(String version) {
		JsonObject m = new JsonObject();
		m.addProperty(McpServer.META_VERSION, version);
		m.add(McpServer.META_CLIENT_CAPS, new JsonObject());
		return m;
	}

	private JsonObject request(String method, JsonObject params) {
		JsonObject msg = new JsonObject();
		msg.addProperty("jsonrpc", "2.0");
		msg.addProperty("id", ++nextId);
		msg.addProperty("method", method);
		msg.add("params", params);
		return msg;
	}

	private JsonObject modern(String method, JsonObject params) {
		params.add("_meta", meta("2026-07-28"));
		return server.handle(request(method, params));
	}

	private JsonObject call(String tool, String argsJson) {
		JsonObject params = new JsonObject();
		params.addProperty("name", tool);
		params.add("arguments", JsonParser.parseString(argsJson));
		return modern("tools/call", params).getAsJsonObject("result");
	}

	private static String text(JsonObject result) {
		return result.getAsJsonArray("content").get(0).getAsJsonObject().get("text").getAsString();
	}

	private static boolean isError(JsonObject result) {
		return result.get("isError").getAsBoolean();
	}

	private static int errorCode(JsonObject response) {
		return response.getAsJsonObject("error").get("code").getAsInt();
	}

	// ---------------------------------------------------------------------
	// Targeting
	// ---------------------------------------------------------------------

	@Test
	public void aCallWithoutAProgramIsRefusedAndNothingIsSent() throws IOException {
		Fake a = fake(0, "proj", "GAME_A", "fa");
		JsonObject r = call("decompile_function", "{\"name\":\"main\"}");
		assertTrue(isError(r));
		assertTrue(text(r), text(r).startsWith("[MISSING_PARAMETER]"));
		assertTrue(a.calls.isEmpty());
	}

	@Test
	public void theCallReachesTheNamedProgramAndNoOther() throws IOException {
		Fake a = fake(0, "proj", "GAME_A", "fa");
		Fake b = fake(1, "proj", "GAME_B", "fb");
		JsonObject r = call("decompile_function", "{\"program\":\"GAME_B\",\"name\":\"main\"}");
		assertFalse(text(r), isError(r));
		assertTrue(a.calls.isEmpty());
		assertEquals(1, b.calls.size());
		assertEquals("fb", b.calls.get(0).get("file_id"));
		assertEquals("sess1234", b.calls.get(0).get("client"));
		assertFalse("program= is consumed by the router", b.calls.get(0).get("args").contains("program"));
	}

	@Test
	public void nothingIsRememberedBetweenCalls() throws IOException {
		Fake a = fake(0, "proj", "GAME_A", "fa");
		call("decompile_function", "{\"program\":\"GAME_A\",\"name\":\"main\"}");
		JsonObject r = call("decompile_function", "{\"name\":\"main\"}");
		assertTrue(isError(r));
		assertEquals(1, a.calls.size());
	}

	@Test
	public void aSilentInstanceIsNeverReplacedByAnother() throws IOException {
		Fake a = fake(0, "proj", "GAME_A", "fa");
		Fake b = fake(1, "proj", "GAME_B", "fb");
		a.silent = true;
		JsonObject r = call("decompile_function", "{\"program\":\"GAME_A\",\"name\":\"main\"}");
		assertTrue(isError(r));
		assertTrue(text(r), text(r).startsWith("[BUSY]"));
		assertTrue(b.calls.isEmpty());
		assertTrue(a.calls.isEmpty());
	}

	@Test
	public void aSilentInstanceCannotHideAnAmbiguity() throws IOException {
		// GAME_A is open in both; with A quiet, B's copy would look unique.
		Fake a = fake(0, "proj", "GAME_A", "fa");
		Fake b = fake(1, "proj2", "GAME_A", "fa2");
		a.silent = true;
		JsonObject r = call("decompile_function", "{\"program\":\"GAME_A\",\"name\":\"main\"}");
		assertTrue(text(r), text(r).startsWith("[BUSY]"));
		assertTrue(b.calls.isEmpty());
		assertTrue(text(call("list_instances", "{}")).contains("did not answer"));
	}

	@Test
	public void aCallCancelledWhileLookingSendsNothing() throws Exception {
		Fake a = fake(0, "proj", "GAME_A", "fa");
		Fake b = fake(1, "proj", "GAME_B", "fb");
		a.silent = true;
		AtomicReference<String> code = new AtomicReference<>("none");
		Thread t = new Thread(() -> {
			try {
				router.resolve("GAME_B");
				code.set("resolved");
			}
			catch (RouterError e) {
				code.set(e.code());
			}
		});
		t.start();
		Thread.sleep(300);
		t.interrupt();
		t.join(5000);
		assertEquals("CANCELLED", code.get());
		assertTrue(b.calls.isEmpty());
	}

	@Test
	public void twoProjectsWithTheSameNameAreToldApartByFileId() throws IOException {
		Fake a = fake(0, "proj", "GAME_A", "fa");
		Fake b = fake(1, "proj", "GAME_A", "fb");
		String list = text(call("list_instances", "{}"));
		assertFalse(list, list.contains("open twice"));
		assertTrue(list, list.contains("program=\"fa\"") && list.contains("program=\"fb\""));
		JsonObject r = call("decompile_function", "{\"program\":\"GAME_A\",\"name\":\"main\"}");
		assertTrue(text(r), text(r).startsWith("[AMBIGUOUS]") && text(r).contains("\"fb\""));
		assertFalse(isError(call("decompile_function", "{\"program\":\"fb\",\"name\":\"main\"}")));
		assertTrue(a.calls.isEmpty());
		assertEquals(1, b.calls.size());
	}

	@Test
	public void theProgramIsFoundWhenItsInstanceRestartsOnAnotherPort() throws IOException {
		Fake a = fake(0, "proj", "GAME_A", "fa");
		call("decompile_function", "{\"program\":\"GAME_A\",\"name\":\"main\"}");
		a.stop();
		fakes.remove(a);
		Fake moved = fake(2, "proj", "GAME_A", "fa");
		JsonObject r = call("decompile_function", "{\"program\":\"GAME_A\",\"name\":\"main\"}");
		assertFalse(text(r), isError(r));
		assertEquals(1, moved.calls.size());
	}

	@Test
	public void aPortThatNowHoldsAnotherProgramIsNotUsed() throws IOException {
		Fake a = fake(0, "proj", "GAME_A", "fa");
		call("decompile_function", "{\"program\":\"GAME_A\",\"name\":\"main\"}");
		a.stop();
		fakes.remove(a);
		Fake other = fake(0, "proj", "GAME_B", "fb");
		JsonObject r = call("decompile_function", "{\"program\":\"GAME_A\",\"name\":\"main\"}");
		assertTrue(isError(r));
		assertTrue(other.calls.isEmpty());
	}

	@Test
	public void aNameOpenInTwoProjectsIsAnAmbiguityNotACoinToss() throws IOException {
		Fake a = fake(0, "proj", "GAME_A", "fa");
		Fake b = fake(1, "proj2", "GAME_A", "fa2");
		JsonObject r = call("decompile_function", "{\"program\":\"GAME_A\",\"name\":\"main\"}");
		assertTrue(isError(r));
		assertTrue(text(r), text(r).startsWith("[AMBIGUOUS]"));
		assertTrue(text(r), text(r).contains("\"proj2:/GAME_A\""));
		assertTrue(a.calls.isEmpty() && b.calls.isEmpty());
		assertFalse(isError(call("decompile_function", "{\"program\":\"proj2:/GAME_A\",\"name\":\"main\"}")));
		assertTrue(a.calls.isEmpty());
		assertEquals(1, b.calls.size());
	}

	@Test
	public void twoCopiesOfOneProjectAreRefused() throws IOException {
		Fake a = fake(0, "proj", "GAME_A", "fa");
		Fake b = fake(1, "proj", "GAME_A", "fa");
		for (String p : new String[] { "GAME_A", "proj:/GAME_A", "fa" }) {
			JsonObject r = call("decompile_function", "{\"program\":\"" + p + "\",\"name\":\"main\"}");
			assertTrue(isError(r));
			assertTrue(text(r), text(r).contains("close one"));
		}
		assertTrue(a.calls.isEmpty() && b.calls.isEmpty());
		assertTrue(text(call("list_instances", "{}")).contains("open twice"));
	}

	@Test
	public void oneProgramInTwoWindowsOfOneGhidraIsOneProgram() throws IOException {
		Fake a = fake(0, "proj", "MAIN.EXE", "fm", "GAME_A", "fa");
		Fake b = fake(1, "proj", "GAME_A", "fa");
		a.pid = 4242;
		b.pid = 4242;
		for (String p : new String[] { "GAME_A", "proj:/GAME_A", "fa" }) {
			assertFalse(text(call("decompile_function", "{\"program\":\"" + p + "\",\"name\":\"main\"}")),
					isError(call("decompile_function", "{\"program\":\"" + p + "\",\"name\":\"main\"}")));
		}
		// The window that has it in front is used.
		assertTrue(a.calls.isEmpty());
		String list = text(call("list_instances", "{}"));
		assertFalse(list, list.contains("open twice"));
		assertTrue(list, list.contains("program=\"GAME_A\"  (in front)"));
		assertTrue(list, list.contains("program=\"MAIN.EXE\""));
	}

	@Test
	public void twoGhidraProcessesWithCopiesOfOneProjectAreStillRefused() throws IOException {
		Fake a = fake(0, "proj", "GAME_A", "fa");
		Fake b = fake(1, "proj", "GAME_A", "fa");
		a.pid = 100;
		b.pid = 200;
		assertTrue(text(call("decompile_function", "{\"program\":\"GAME_A\",\"name\":\"main\"}")).contains("close one"));
		assertTrue(a.calls.isEmpty() && b.calls.isEmpty());
	}

	@Test
	public void aProgramThatIsNotInFrontCanBeUsed() throws IOException {
		Fake a = fake(0, "proj", "MAIN.EXE", "fm", "OVERLAY.BIN", "fo");
		call("decompile_function", "{\"program\":\"OVERLAY.BIN\",\"name\":\"main\"}");
		assertEquals("fo", a.calls.get(0).get("file_id"));
	}

	@Test
	public void aRefusalByTheInstanceIsAnError() throws IOException {
		Fake a = fake(0, "proj", "GAME_A", "fa");
		a.refuse = true;
		JsonObject r = call("decompile_function", "{\"program\":\"GAME_A\",\"name\":\"main\"}");
		assertTrue(isError(r));
		assertTrue(text(r), text(r).startsWith("[NOT_HERE]"));
	}

	@Test
	public void noGhidraIsSaidPlainly() {
		JsonObject r = call("decompile_function", "{\"program\":\"GAME_A\",\"name\":\"main\"}");
		assertTrue(text(r), text(r).startsWith("[NO_GHIDRA]"));
	}

	@Test
	public void listInstancesGivesTheValueToPassForEveryProgram() throws IOException {
		fake(0, "proj", "MAIN.EXE", "fm", "OVERLAY.BIN", "fo");
		fake(1, "proj2", "MAIN.EXE", "fm2");
		String t = text(call("list_instances", "{}"));
		assertTrue(t, t.contains("program=\"OVERLAY.BIN\""));
		assertTrue(t, t.contains("program=\"proj:/MAIN.EXE\"  (in front)"));
		assertTrue(t, t.contains("program=\"proj2:/MAIN.EXE\""));
	}

	// ---------------------------------------------------------------------
	// Protocol: modern (2026-07-28)
	// ---------------------------------------------------------------------

	// ---------------------------------------------------------------------
	// The stdio loop
	// ---------------------------------------------------------------------

	private String waitFor(StringWriter out, String needle) throws InterruptedException {
		for (int i = 0; i < 100 && !out.toString().contains(needle); i++) {
			Thread.sleep(20);
		}
		return out.toString();
	}

	private JsonObject modernRequest(String method, JsonObject params, int id) {
		params.add("_meta", meta("2026-07-28"));
		JsonObject msg = request(method, params);
		msg.addProperty("id", id);
		return msg;
	}

	@Test
	public void aMalformedCancellationDoesNotStopTheServer() throws Exception {
		StringWriter out = new StringWriter();
		ExecutorService pool = Executors.newCachedThreadPool();
		Map<String, StdioMain.Request> inFlight = new ConcurrentHashMap<>();
		for (String bad : new String[] { "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":null}",
				"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":[1]}",
				"{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":{}}}" }) {
			StdioMain.dispatch(bad, server, out, new Object(), pool, pool, inFlight);
		}
		StdioMain.dispatch(modernRequest("server/discover", new JsonObject(), 77).toString(), server, out,
				new Object(), pool, pool, inFlight);
		assertTrue(waitFor(out, "\"id\":77").contains("\"id\":77"));
		pool.shutdownNow();
	}

	@Test
	public void aCancelledIdCanBeReused() throws Exception {
		StringWriter out = new StringWriter();
		ExecutorService pool = Executors.newCachedThreadPool();
		Map<String, StdioMain.Request> inFlight = new ConcurrentHashMap<>();
		// A cancellation for a request that already finished (or never existed).
		StdioMain.dispatch("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":9}}",
				server, out, new Object(), pool, pool, inFlight);
		StdioMain.dispatch(modernRequest("server/discover", new JsonObject(), 9).toString(), server, out,
				new Object(), pool, pool, inFlight);
		assertTrue(waitFor(out, "\"id\":9").contains("\"id\":9"));
		Thread.sleep(50);
		assertTrue(inFlight.isEmpty());
		pool.shutdownNow();
	}

	@Test
	public void aCancelledCallIsNotAnswered() throws Exception {
		Fake a = fake(0, "proj", "GAME_A", "fa");
		a.silent = true;
		StringWriter out = new StringWriter();
		ExecutorService pool = Executors.newCachedThreadPool();
		Map<String, StdioMain.Request> inFlight = new ConcurrentHashMap<>();
		JsonObject p = new JsonObject();
		p.addProperty("name", "decompile_function");
		p.add("arguments", JsonParser.parseString("{\"program\":\"GAME_A\",\"name\":\"main\"}"));
		StdioMain.dispatch(modernRequest("tools/call", p, 31).toString(), server, out, new Object(), pool, pool,
				inFlight);
		Thread.sleep(200);
		StdioMain.dispatch("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":31}}",
				server, out, new Object(), pool, pool, inFlight);
		pool.shutdown();
		assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
		assertFalse(out.toString(), out.toString().contains("\"id\":31"));
		assertTrue(inFlight.isEmpty());
		assertTrue(a.calls.isEmpty());
	}

	@Test
	public void discoveryIsAnsweredWhileEveryCallWorkerIsBusy() throws Exception {
		StringWriter out = new StringWriter();
		ExecutorService calls = Executors.newFixedThreadPool(1);
		ExecutorService control = Executors.newCachedThreadPool();
		CountDownLatch hold = new CountDownLatch(1);
		calls.submit(() -> {
			hold.await();
			return null;
		});
		Map<String, StdioMain.Request> inFlight = new ConcurrentHashMap<>();
		StdioMain.dispatch(modernRequest("server/discover", new JsonObject(), 41).toString(), server, out,
				new Object(), calls, control, inFlight);
		JsonObject li = new JsonObject();
		li.addProperty("name", "list_instances");
		li.add("arguments", new JsonObject());
		StdioMain.dispatch(modernRequest("tools/call", li, 42).toString(), server, out, new Object(), calls, control,
				inFlight);
		String o = waitFor(out, "\"id\":42");
		assertTrue(o, o.contains("\"id\":41") && o.contains("\"id\":42"));
		hold.countDown();
		calls.shutdownNow();
		control.shutdownNow();
	}

	@Test
	public void discoverDescribesTheServer() {
		JsonObject r = modern("server/discover", new JsonObject()).getAsJsonObject("result");
		assertEquals("complete", r.get("resultType").getAsString());
		assertEquals("2026-07-28", r.getAsJsonArray("supportedVersions").get(0).getAsString());
		assertTrue(r.getAsJsonObject("capabilities").getAsJsonObject("tools").get("listChanged").getAsBoolean());
		assertEquals("ghidra-mcp", r.getAsJsonObject("_meta").getAsJsonObject(McpServer.META_SERVER_INFO)
				.get("name").getAsString());
		assertTrue(r.has("instructions") && r.has("ttlMs") && r.has("cacheScope"));
	}

	@Test
	public void anUnsupportedVersionIsAnsweredWithTheSupportedOnes() {
		JsonObject params = new JsonObject();
		params.add("_meta", meta("1900-01-01"));
		JsonObject resp = server.handle(request("tools/list", params));
		assertEquals(McpServer.UNSUPPORTED_PROTOCOL_VERSION, errorCode(resp));
		JsonObject data = resp.getAsJsonObject("error").getAsJsonObject("data");
		assertEquals("2026-07-28", data.getAsJsonArray("supported").get(0).getAsString());
		assertEquals("1900-01-01", data.get("requested").getAsString());
	}

	@Test
	public void aRequestWithoutRequiredMetaIsMalformed() {
		JsonObject params = new JsonObject();
		JsonObject m = new JsonObject();
		m.addProperty(McpServer.META_VERSION, "2026-07-28");
		params.add("_meta", m);
		assertEquals(McpServer.INVALID_PARAMS, errorCode(server.handle(request("tools/list", params))));
		assertEquals(McpServer.INVALID_PARAMS, errorCode(server.handle(request("tools/list", new JsonObject()))));
	}

	@Test
	public void toolsListRequiresTheProgramAndCarriesCacheHints() {
		JsonObject r = modern("tools/list", new JsonObject()).getAsJsonObject("result");
		assertEquals("complete", r.get("resultType").getAsString());
		assertEquals(0, r.get("ttlMs").getAsLong());
		assertEquals("public", r.get("cacheScope").getAsString());
		JsonObject dec = null;
		for (var e : r.getAsJsonArray("tools")) {
			if (e.getAsJsonObject().get("name").getAsString().equals("decompile_function")) {
				dec = e.getAsJsonObject();
			}
		}
		JsonObject in = dec.getAsJsonObject("inputSchema");
		assertEquals("program", in.getAsJsonObject("properties").keySet().iterator().next());
		assertEquals("[\"program\",\"name\"]", in.getAsJsonArray("required").toString());
		assertEquals(2, r.getAsJsonArray("tools").size());
	}

	@Test
	public void anUnknownToolIsAProtocolError() {
		JsonObject params = new JsonObject();
		params.addProperty("name", "no_such_tool");
		assertEquals(McpServer.INVALID_PARAMS, errorCode(modern("tools/call", params)));
	}

	@Test
	public void pingIsGoneInTheModernRevision() {
		assertEquals(McpServer.METHOD_NOT_FOUND, errorCode(modern("ping", new JsonObject())));
	}

	@Test
	public void aChangedToolListReachesListenersOnly() throws IOException {
		JsonObject filter = new JsonObject();
		JsonObject n = new JsonObject();
		n.addProperty("toolsListChanged", true);
		filter.add("notifications", n);
		JsonObject listen = request("subscriptions/listen", filter);
		listen.getAsJsonObject("params").add("_meta", meta("2026-07-28"));
		assertNull("the listen response comes only when the stream ends", server.handle(listen));
		assertEquals(1, notes.size());
		JsonObject ack = notes.get(0);
		assertEquals("notifications/subscriptions/acknowledged", ack.get("method").getAsString());
		assertEquals(listen.get("id"), ack.getAsJsonObject("params").getAsJsonObject("_meta")
				.get(McpServer.META_SUBSCRIPTION));

		Fake a = fake(0, "proj", "GAME_A", "fa");
		a.catalog = "[{\"name\":\"decompile_function\",\"description\":\"newer\",\"inputSchema\":{\"type\":\"object\"}}]";
		server.afterCall();
		assertEquals(2, notes.size());
		JsonObject changed = notes.get(1);
		assertEquals("notifications/tools/list_changed", changed.get("method").getAsString());
		assertEquals(listen.get("id"), changed.getAsJsonObject("params").getAsJsonObject("_meta")
				.get(McpServer.META_SUBSCRIPTION));
		JsonObject r = modern("tools/list", new JsonObject()).getAsJsonObject("result");
		assertEquals(McpServer.TOOLS_TTL_MS, r.get("ttlMs").getAsLong());
		assertTrue(r.toString().contains("newer"));
	}

	@Test
	public void aCancelledSubscriptionHearsNothingMore() throws IOException {
		JsonObject filter = new JsonObject();
		JsonObject n = new JsonObject();
		n.addProperty("toolsListChanged", true);
		filter.add("notifications", n);
		JsonObject listen = request("subscriptions/listen", filter);
		listen.getAsJsonObject("params").add("_meta", meta("2026-07-28"));
		server.handle(listen);
		JsonObject cancel = JsonParser.parseString("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\","
				+ "\"params\":{\"requestId\":" + listen.get("id") + "}}").getAsJsonObject();
		assertNull(server.handle(cancel));
		Fake a = fake(0, "proj", "GAME_A", "fa");
		a.catalog = "[{\"name\":\"other\",\"inputSchema\":{\"type\":\"object\"}}]";
		server.afterCall();
		assertEquals("only the acknowledgment", 1, notes.size());
	}

	// ---------------------------------------------------------------------
	// Protocol: legacy (initialize handshake)
	// ---------------------------------------------------------------------

	@Test
	public void aLegacyClientIsServedAfterInitialize() throws IOException {
		JsonObject init = JsonParser.parseString("{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},"
				+ "\"clientInfo\":{\"name\":\"old\",\"version\":\"1\"}}").getAsJsonObject();
		JsonObject r = server.handle(request("initialize", init)).getAsJsonObject("result");
		assertEquals("2025-06-18", r.get("protocolVersion").getAsString());
		assertEquals("ghidra-mcp", r.getAsJsonObject("serverInfo").get("name").getAsString());
		JsonObject list = server.handle(request("tools/list", new JsonObject())).getAsJsonObject("result");
		assertFalse("legacy results carry no resultType", list.has("resultType"));
		assertEquals(2, list.getAsJsonArray("tools").size());
		assertTrue(server.handle(request("ping", new JsonObject())).has("result"));

		Fake a = fake(0, "proj", "GAME_A", "fa");
		JsonObject params = JsonParser.parseString("{\"name\":\"decompile_function\","
				+ "\"arguments\":{\"program\":\"GAME_A\",\"name\":\"main\"}}").getAsJsonObject();
		JsonObject res = server.handle(request("tools/call", params)).getAsJsonObject("result");
		assertFalse(text(res), isError(res));
		assertEquals(1, a.calls.size());
	}

	@Test
	public void anUnknownLegacyVersionIsAnsweredWithTheNewestLegacyOne() {
		JsonObject init = JsonParser.parseString("{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{}}")
				.getAsJsonObject();
		JsonObject r = server.handle(request("initialize", init)).getAsJsonObject("result");
		assertEquals("2025-11-25", r.get("protocolVersion").getAsString());
	}
}
