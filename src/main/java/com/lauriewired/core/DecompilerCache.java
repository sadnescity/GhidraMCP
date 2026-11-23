package com.lauriewired.core;

import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * One open decompiler per program, kept between calls.
 *
 * <p>Opening a {@link DecompInterface} starts a native process and loads the
 * language into it: about a quarter of a second, against a few milliseconds
 * for the decompilation of a typical function once it is open. Opening one per
 * call made every decompile pay that start-up. The interface flushes its own
 * cache after each function, so nothing learned from one function carries
 * into the next, and a database change between two calls is seen by the
 * second.
 *
 * <p>Not thread-safe, like the interface: every call reaches it from the
 * plugin's single request thread. An interface whose decompilation does not
 * complete -- a timeout, a crash -- is disposed, and the next call opens a
 * fresh one, so a half-dead process never decides a later answer. Every
 * interface is disposed when its program closes or the plugin goes away; one
 * that is dropped instead leaves its process running for the life of the JVM.
 */
public final class DecompilerCache {

	private final Plugin owner;
	private final Map<Program, DecompInterface> open = new IdentityHashMap<>();
	private volatile int timeoutSeconds;
	/** The decompile in progress, so closing the tool can stop it instead of waiting it out. */
	private volatile TaskMonitor running;

	public DecompilerCache(Plugin owner, int timeoutSeconds) {
		this.owner = owner;
		this.timeoutSeconds = timeoutSeconds;
	}

	public void setTimeoutSeconds(int seconds) {
		this.timeoutSeconds = Math.max(1, seconds);
	}

	public int timeoutSeconds() {
		return timeoutSeconds;
	}

	public synchronized DecompileResults decompile(Ctx ctx, Function f) {
		Program program = f.getProgram();
		pruneClosed();
		DecompInterface decomp = open.get(program);
		if (decomp == null) {
			decomp = openFor(ctx, program);
			open.put(program, decomp);
		}
		DecompileResults r;
		TaskMonitor monitor = new TaskMonitorAdapter(true);
		running = monitor;
		try {
			r = decomp.decompileFunction(f, timeoutSeconds, monitor);
		}
		catch (Exception e) {
			dispose(program);
			throw new ToolError("DECOMPILE_FAILED",
					"Decompilation of " + f.getName() + " failed: " + Ctx.describe(e), e);
		}
		finally {
			running = null;
		}
		if (r == null || !r.decompileCompleted()) {
			dispose(program);
			String why = r == null ? "no result" : r.getErrorMessage();
			if (why == null || why.isBlank()) {
				why = "the decompiler gave no reason (timeout is " + timeoutSeconds + " s)";
			}
			throw new ToolError("DECOMPILE_FAILED",
					"Decompilation of " + f.getName() + " failed: " + why.trim());
		}
		return r;
	}

	private DecompInterface openFor(Ctx ctx, Program program) {
		DecompInterface decomp = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		try {
			// The options the analyst set for the Decompiler window, so the
			// model reads what the analyst would see.
			if (ctx != null && ctx.tool != null) {
				ToolOptions fieldOpts = ctx.tool.getOptions("Listing Fields");
				ToolOptions toolOpts = ctx.tool.getOptions("Decompiler");
				options.grabFromToolAndProgram(fieldOpts, toolOpts, program);
			}
		}
		catch (Exception e) {
			Msg.warn(this, "Using default decompiler options: " + Ctx.describe(e));
		}
		decomp.setOptions(options);
		decomp.toggleCCode(true);
		decomp.toggleSyntaxTree(true);
		decomp.setSimplificationStyle("decompile");
		if (!decomp.openProgram(program)) {
			String why = decomp.getLastMessage();
			decomp.dispose();
			throw new ToolError("DECOMPILE_FAILED", "The decompiler would not open "
					+ program.getName() + ": " + (why == null || why.isBlank() ? "no reason given" : why));
		}
		return decomp;
	}

	private void pruneClosed() {
		Iterator<Map.Entry<Program, DecompInterface>> it = open.entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry<Program, DecompInterface> e = it.next();
			if (e.getKey().isClosed()) {
				safeDispose(e.getValue());
				it.remove();
			}
		}
	}

	public synchronized void dispose(Program program) {
		DecompInterface d = open.remove(program);
		if (d != null) {
			safeDispose(d);
		}
	}

	/** Stops a decompile in progress first, so closing the tool does not wait up to the timeout. */
	public void disposeAll() {
		TaskMonitor m = running;
		if (m != null) {
			m.cancel();
		}
		synchronized (this) {
			for (DecompInterface d : open.values()) {
				safeDispose(d);
			}
			open.clear();
		}
	}

	private static void safeDispose(DecompInterface d) {
		try {
			d.dispose();
		}
		catch (Exception ignored) {
			// A dead process can throw on disposal; it is gone either way.
		}
	}
}
