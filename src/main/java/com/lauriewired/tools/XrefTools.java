package com.lauriewired.tools;

import java.util.LinkedHashSet;
import java.util.Set;

import com.lauriewired.core.Ctx;
import com.lauriewired.core.Fmt;
import com.lauriewired.core.P;
import com.lauriewired.core.Page;
import com.lauriewired.core.Tool;
import com.lauriewired.core.ToolError;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TaskMonitor;

/** Cross-references and the call graph. */
public final class XrefTools {

	@Tool(name = "get_xrefs_to", description = "List references TO an address (or symbol): "
			+ "'from-address (in function) TYPE'. Paged.")
	public String getXrefsTo(Ctx ctx,
			@P(value = "address", description = "Target address or symbol name") String address,
			@P(value = "offset", def = "0", description = "Index of the first reference") int offset,
			@P(value = "limit", def = "100", description = "Maximum references to return") int limit) {
		return xrefsTo(ctx, ctx.addr(address), offset, limit);
	}

	static String xrefsTo(Ctx ctx, Address a, int offset, int limit) {
		Program p = ctx.program();
		Page page = new Page(offset, limit);
		ReferenceIterator it = p.getReferenceManager().getReferencesTo(a);
		while (it.hasNext()) {
			Reference r = it.next();
			page.offer(() -> Fmt.where(p, r.getFromAddress()) + " " + r.getReferenceType().getName());
		}
		return page.render("No references to " + Fmt.addr(a));
	}

	@Tool(name = "get_xrefs_from", description = "List references FROM an instruction or data address: "
			+ "'to-address (name) TYPE'. Paged.")
	public String getXrefsFrom(Ctx ctx,
			@P(value = "address", description = "Source address") String address,
			@P(value = "offset", def = "0", description = "Index of the first reference") int offset,
			@P(value = "limit", def = "100", description = "Maximum references to return") int limit) {
		Program p = ctx.program();
		Address a = ctx.addr(address);
		Page page = new Page(offset, limit);
		for (Reference r : p.getReferenceManager().getReferencesFrom(a)) {
			Address to = r.getToAddress();
			page.offer(() -> {
				String n = Fmt.label(p, to);
				return Fmt.addr(to) + (n != null ? " (" + n + ")" : "") + " " + r.getReferenceType().getName()
						+ (r.getOperandIndex() >= 0 ? " op" + r.getOperandIndex() : "");
			});
		}
		return page.render("No references from " + Fmt.addr(a));
	}

	@Tool(name = "get_function_xrefs", description = "List references to a function's entry point, by name "
			+ "or (preferably) address. Paged.")
	public String getFunctionXrefs(Ctx ctx,
			@P(value = "name", def = P.NULL, description = "Function name") String name,
			@P(value = "offset", def = "0", description = "Index of the first reference") int offset,
			@P(value = "limit", def = "100", description = "Maximum references to return") int limit,
			@P(value = "address", def = P.NULL, description = "Address inside the function") String address) {
		Function f = ctx.fn(address, name);
		return Fmt.fn(f) + "\n" + xrefsTo(ctx, f.getEntryPoint(), offset, limit);
	}

	@Tool(name = "get_function_calls", description = "One level of the call graph around a function. "
			+ "Callers: call sites that reach it, with the calling function. Callees: every call made from "
			+ "its body, including calls through pointers and unresolved indirect calls (marked indirect), "
			+ "with thunks resolved. offset/limit apply to each list.")
	public String getFunctionCalls(Ctx ctx,
			@P(value = "address", description = "Address inside the function, or its name") String address,
			@P(value = "direction", def = "both", oneOf = { "both", "callers", "callees" },
					description = "Which side of the call graph") String direction,
			@P(value = "offset", def = "0", description = "Index of the first entry in each list") int offset,
			@P(value = "limit", def = "200", description = "Maximum entries per list") int limit) {
		Program p = ctx.program();
		Function f = ctx.fnAt(address);
		String dir = direction.toLowerCase();
		StringBuilder sb = new StringBuilder(Fmt.fn(f)).append('\n');
		if (!dir.equals("callees")) {
			Page page = new Page(offset, limit);
			FunctionManager fm = p.getFunctionManager();
			ReferenceIterator it = p.getReferenceManager().getReferencesTo(f.getEntryPoint());
			while (it.hasNext()) {
				Reference r = it.next();
				if (!r.getReferenceType().isCall()) {
					continue;
				}
				Function caller = fm.getFunctionContaining(r.getFromAddress());
				page.offer(() -> "  " + Fmt.addr(r.getFromAddress()) + " in " + (caller != null ? Fmt.fn(caller) : "(no function)"));
			}
			// Thunks of this function are callers too: calls reach it through them.
			for (Address thunk : f.getFunctionThunkAddresses(true) == null ? new Address[0] : f.getFunctionThunkAddresses(true)) {
				page.add("  thunk " + Fmt.fn(fm.getFunctionAt(thunk)));
			}
			sb.append("Callers:\n").append(indentEmpty(page.render("  (none)"))).append('\n');
		}
		if (!dir.equals("callers")) {
			sb.append("Callees:\n").append(indentEmpty(callees(p, f, offset, limit)));
		}
		return sb.toString().stripTrailing();
	}

	private static String indentEmpty(String s) {
		return s;
	}

	private static String callees(Program p, Function f, int offset, int limit) {
		FunctionManager fm = p.getFunctionManager();
		Page page = new Page(offset, limit);
		InstructionIterator it = p.getListing().getInstructions(f.getBody(), true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			FlowType flow = ins.getFlowType();
			if (!flow.isCall()) {
				continue;
			}
			String site = "  " + Fmt.addr(ins.getAddress()) + " -> ";
			boolean found = false;
			for (Reference r : ins.getReferencesFrom()) {
				RefType t = r.getReferenceType();
				if (!t.isCall()) {
					continue;
				}
				found = true;
				Address to = r.getToAddress();
				Function target = fm.getFunctionAt(to);
				String name;
				if (target != null && target.isThunk() && target.getThunkedFunction(true) != null) {
					name = Fmt.fn(target) + " (thunk to " + target.getThunkedFunction(true).getName(true) + ")";
				}
				else if (target != null) {
					name = Fmt.fn(target);
				}
				else {
					String l = Fmt.label(p, to);
					name = (l != null ? l + " @ " : "") + Fmt.addr(to) + " (no function)";
				}
				String nm = name;
				page.offer(() -> site + nm + (t.isComputed() || flow.isComputed() ? " [indirect]" : ""));
			}
			if (!found) {
				page.offer(() -> site + "? [indirect, unresolved: " + ins + "]");
			}
		}
		return page.render("  (none)");
	}

	@Tool(name = "get_callee", description = "List the distinct functions called by the function at, or "
			+ "containing, an address, as 'name @ address' (external functions marked).")
	public String getCallee(Ctx ctx, @P(value = "address", description = "Address inside the function") String address) {
		Function f = ctx.fnAt(address);
		Set<Function> callees = f.getCalledFunctions(TaskMonitor.DUMMY);
		if (callees.isEmpty() && f.isThunk() && f.getThunkedFunction(false) != null) {
			callees = f.getThunkedFunction(false).getCalledFunctions(TaskMonitor.DUMMY);
		}
		if (callees.isEmpty()) {
			return Fmt.fn(f) + " calls no function";
		}
		Set<String> lines = new LinkedHashSet<>();
		callees.stream().sorted((a, b) -> a.getEntryPoint().compareTo(b.getEntryPoint()))
				.forEach(c -> lines.add(c.isExternal() ? c.getName(true) + " (external)" : Fmt.fn(c)));
		return String.join("\n", lines);
	}

	static void requireNonNull(Object o, String what) {
		if (o == null) {
			throw ToolError.notFound(what);
		}
	}
}
