package com.lauriewired.core;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import com.lauriewired.util.Transactions;

import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Everything a tool needs for one call: the program it acts on, the tool that
 * holds it, and the session that asked. Also the shared helpers that make
 * every tool parse addresses, find functions, resolve types and write to the
 * database the same way -- and fail the same way.
 */
public final class Ctx {

	/** A write performed inside a transaction. */
	@FunctionalInterface
	public interface Write<T> {
		T run() throws Exception;
	}

	public final PluginTool tool;
	private final Program program;
	private final String sessionTag;
	private final Services services;
	private final TaskMonitor monitor;

	public Ctx(PluginTool tool, Program program, String sessionTag, Services services) {
		this(tool, program, sessionTag, services, new TaskMonitorAdapter(true));
	}

	/** @param monitor cancelled when the client gives up on the call */
	public Ctx(PluginTool tool, Program program, String sessionTag, Services services, TaskMonitor monitor) {
		this.tool = tool;
		this.program = program;
		this.sessionTag = sessionTag == null ? "" : sessionTag;
		this.services = services;
		this.monitor = monitor;
	}

	/**
	 * Cancelled when the client gives up on this call (it was cancelled, or
	 * timed out). Long-running tools pass it to Ghidra or poll it.
	 */
	public TaskMonitor monitor() {
		return monitor;
	}

	/** Stops a long-running tool once the client has given up on it. */
	public void checkCancelled() {
		if (monitor.isCancelled()) {
			throw ToolError.cancelled();
		}
	}

	/** The program this call acts on. Never null for a tool that needs one. */
	public Program program() {
		if (program == null) {
			throw ToolError.noProgram();
		}
		return program;
	}

	/** The program, or null if none: for tools that also work without one. */
	public Program programOrNull() {
		return program;
	}

	public Services services() {
		return services;
	}

	// ---------------------------------------------------------------------
	// Addresses
	// ---------------------------------------------------------------------

	/**
	 * Parses an address. Accepts "0x80010000", "80010000", "ram:80010000",
	 * an overlay "OVL::80100000", or -- when the text is not an address -- the
	 * name of a label or function that names exactly one address.
	 */
	public Address addr(String text) {
		Program p = program();
		if (text == null || text.isBlank()) {
			throw ToolError.missing("address");
		}
		String t = text.trim();
		Address a = null;
		try {
			a = p.getAddressFactory().getAddress(t);
		}
		catch (Exception e) {
			a = null;
		}
		if (a != null) {
			return a;
		}
		// Not an address: perhaps a symbol name.
		List<Symbol> hits = new ArrayList<>();
		SymbolIterator it = p.getSymbolTable().getSymbols(t);
		while (it.hasNext()) {
			Symbol s = it.next();
			if (s.getAddress() != null && s.getAddress().isMemoryAddress()) {
				hits.add(s);
			}
		}
		if (hits.size() == 1) {
			return hits.get(0).getAddress();
		}
		if (hits.size() > 1) {
			StringBuilder sb = new StringBuilder();
			for (Symbol s : hits) {
				sb.append(sb.length() == 0 ? "" : ", ").append(s.getName(true)).append(" @ ")
						.append(s.getAddress());
			}
			throw ToolError.ambiguous("'" + t + "' is not an address, and names " + hits.size()
					+ " symbols: " + sb + ". Pass the address instead.");
		}
		throw ToolError.badAddress(t);
	}

	// ---------------------------------------------------------------------
	// Functions
	// ---------------------------------------------------------------------

	/** The function starting at, or else containing, the address. */
	public Function fnAt(Address a) {
		FunctionManager fm = program().getFunctionManager();
		Function f = fm.getFunctionAt(a);
		if (f == null) {
			f = fm.getFunctionContaining(a);
		}
		if (f == null) {
			throw ToolError.functionNotFound("at or containing " + a
					+ " (create one with create_function, or use disassemble/get_listing)");
		}
		return f;
	}

	/** The function at or containing the address given as text. */
	public Function fnAt(String address) {
		return fnAt(addr(address));
	}

	/** The one function with this simple or namespace-qualified name. */
	public Function fnByName(String name) {
		if (name == null || name.isBlank()) {
			throw ToolError.missing("name");
		}
		String n = name.trim();
		List<Function> matches = new ArrayList<>();
		for (Function f : program().getFunctionManager().getFunctions(true)) {
			if (f.getName().equals(n) || f.getName(true).equals(n)) {
				matches.add(f);
			}
		}
		if (matches.isEmpty()) {
			// External functions are not in the iterator above.
			for (Function f : program().getFunctionManager().getExternalFunctions()) {
				if (f.getName().equals(n) || f.getName(true).equals(n)) {
					matches.add(f);
				}
			}
		}
		if (matches.isEmpty()) {
			throw ToolError.functionNotFound("named '" + n + "' (search_functions_by_name finds partial names)");
		}
		if (matches.size() > 1) {
			StringBuilder sb = new StringBuilder();
			for (Function f : matches) {
				sb.append(sb.length() == 0 ? "" : ", ").append(f.getName(true)).append(" @ ")
						.append(f.getEntryPoint());
			}
			throw ToolError.ambiguous("'" + n + "' names " + matches.size()
					+ " functions: " + sb + ". Use the address instead.");
		}
		return matches.get(0);
	}

	/**
	 * A function given either by address or by name. Exactly one of the two
	 * is expected; the address wins if both are given.
	 */
	public Function fn(String address, String name) {
		if (address != null && !address.isBlank()) {
			return fnAt(address);
		}
		if (name != null && !name.isBlank()) {
			return fnByName(name);
		}
		throw ToolError.missing("function_address (or function_name)");
	}

	// ---------------------------------------------------------------------
	// Data types
	// ---------------------------------------------------------------------

	/** Resolves a C-style type name, or fails: never silently substitutes another type. */
	public DataType type(String name) {
		return Types.resolve(tool, program(), name);
	}

	// ---------------------------------------------------------------------
	// Decompiler
	// ---------------------------------------------------------------------

	/** Decompiles, or throws DECOMPILE_FAILED with the decompiler's own reason. */
	public DecompileResults decompile(Function f) {
		return services.decompilers().decompile(this, f);
	}

	/** The high function of a completed decompilation. */
	public HighFunction high(Function f) {
		DecompileResults r = decompile(f);
		HighFunction hf = r.getHighFunction();
		if (hf == null || hf.getLocalSymbolMap() == null) {
			throw new ToolError("DECOMPILE_FAILED",
					"The decompiler produced no high function for " + f.getName());
		}
		return hf;
	}

	// ---------------------------------------------------------------------
	// Writes
	// ---------------------------------------------------------------------

	/** The transaction name recorded in the undo stack, naming the session. */
	public String txName(String what) {
		return Transactions.name(what, sessionTag);
	}

	/**
	 * Runs a change inside one transaction on the Swing thread. The change is
	 * committed only if it returns normally; any exception rolls it back and is
	 * reported with a code.
	 */
	public <T> T write(String what, Write<T> action) {
		Program p = program();
		AtomicReference<T> result = new AtomicReference<>();
		AtomicReference<RuntimeException> failure = new AtomicReference<>();
		Runnable r = () -> {
			int tx = p.startTransaction(txName(what));
			boolean commit = false;
			try {
				result.set(action.run());
				commit = true;
			}
			catch (ToolError e) {
				failure.set(e);
			}
			catch (DuplicateNameException e) {
				failure.set(ToolError.conflict(e.getMessage()));
			}
			catch (InvalidInputException e) {
				failure.set(ToolError.invalid(e.getMessage()));
			}
			catch (IllegalArgumentException e) {
				failure.set(ToolError.invalid(String.valueOf(e.getMessage())));
			}
			catch (Exception e) {
				failure.set(ToolError.failed(what + " failed: " + describe(e), e));
			}
			finally {
				p.endTransaction(tx, commit);
			}
		};
		onSwing(r);
		if (failure.get() != null) {
			throw failure.get();
		}
		return result.get();
	}

	/** Runs on the Swing thread and waits. */
	public static void onSwing(Runnable r) {
		if (SwingUtilities.isEventDispatchThread()) {
			r.run();
			return;
		}
		try {
			SwingUtilities.invokeAndWait(r);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw ToolError.failed("Interrupted while waiting for the Swing thread");
		}
		catch (InvocationTargetException e) {
			Throwable c = e.getCause() != null ? e.getCause() : e;
			if (c instanceof RuntimeException re) {
				throw re;
			}
			throw ToolError.failed(describe(c), c);
		}
	}

	/** An exception as a short sentence: its message, or its class if it has none. */
	public static String describe(Throwable t) {
		String m = t.getMessage();
		return (m == null || m.isBlank()) ? t.getClass().getSimpleName() : m;
	}
}
