package com.lauriewired.tools;

import java.util.ArrayList;
import java.util.List;

import com.lauriewired.core.Ctx;
import com.lauriewired.core.Fmt;
import com.lauriewired.core.P;
import com.lauriewired.core.Page;
import com.lauriewired.core.Tool;
import com.lauriewired.core.ToolError;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.DataTypeQueryService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/** Functions: reading them, creating and removing them, naming and typing them. */
public final class FunctionTools {

	// ---------------------------------------------------------------------
	// Reading
	// ---------------------------------------------------------------------

	@Tool(name = "decompile_function", description = "Decompile a function by name and return its C "
			+ "pseudocode. Fails (AMBIGUOUS) if several functions share the name; then use "
			+ "decompile_function_by_address.")
	public String decompileFunction(Ctx ctx, @P(value = "name", description = "Function name") String name) {
		return decompiled(ctx, ctx.fnByName(name));
	}

	@Tool(name = "decompile_function_by_address", description = "Decompile the function at, or "
			+ "containing, an address (or a function/label name) and return its C pseudocode.")
	public String decompileFunctionByAddress(Ctx ctx,
			@P(value = "address", description = "Address inside the function, or its name") String address) {
		return decompiled(ctx, ctx.fnAt(address));
	}

	static String decompiled(Ctx ctx, Function f) {
		DecompileResults r = ctx.decompile(f);
		String c = r.getDecompiledFunction().getC();
		return c == null ? "" : c.strip();
	}

	@Tool(name = "disassemble_function", description = "Disassemble a function's body: one line per "
			+ "instruction, 'address: bytes  instruction ; comment', labels on their own line. Paged.")
	public String disassembleFunction(Ctx ctx,
			@P(value = "address", description = "Address inside the function, or its name") String address,
			@P(value = "offset", def = "0", description = "Index of the first instruction") int offset,
			@P(value = "limit", def = "2000", description = "Maximum instructions to return") int limit) {
		Function f = ctx.fnAt(address);
		Program p = ctx.program();
		Listing listing = p.getListing();
		Page page = new Page(offset, limit);
		InstructionIterator it = listing.getInstructions(f.getBody(), true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			page.offer(() -> instructionLine(p, ins, ins.getAddress().equals(f.getEntryPoint())));
		}
		return Fmt.fn(f) + "\n" + page.render("(no instructions)");
	}

	static String instructionLine(Program p, Instruction ins, boolean isEntry) {
		StringBuilder sb = new StringBuilder();
		String label = Fmt.label(p, ins.getAddress());
		if (label != null && !isEntry && p.getSymbolTable().getPrimarySymbol(ins.getAddress()).getSource()
				!= SourceType.DEFAULT) {
			sb.append(label).append(":\n");
		}
		sb.append(Fmt.addr(ins.getAddress())).append(": ");
		try {
			sb.append(String.format("%-12s", Fmt.hex(ins.getBytes()).replace(" ", "")));
		}
		catch (MemoryAccessException e) {
			sb.append("??          ");
		}
		sb.append(' ').append(Fmt.instruction(ins));
		String eol = p.getListing().getComment(CommentType.EOL, ins.getAddress());
		if (eol != null) {
			sb.append("  ; ").append(Fmt.oneLine(eol));
		}
		return sb.toString();
	}

	@Tool(name = "get_listing", description = "Show the listing from an address onward, whether or not it "
			+ "belongs to a function: instructions, defined data and undefined bytes, with labels and "
			+ "comments. Use it for code that is not (yet) a function and for data tables.")
	public String getListing(Ctx ctx,
			@P(value = "address", description = "Start address or symbol") String address,
			@P(value = "count", def = "40", description = "Number of code units to show (max 2000)") int count) {
		if (count < 1 || count > 2000) {
			throw ToolError.invalid("count must be between 1 and 2000");
		}
		Program p = ctx.program();
		Address a = ctx.addr(address);
		if (p.getMemory().getBlock(a) == null) {
			throw ToolError.notFound(Fmt.addr(a) + " is not in any memory block");
		}
		Listing listing = p.getListing();
		StringBuilder sb = new StringBuilder();
		CodeUnit cu = listing.getCodeUnitContaining(a);
		int n = 0;
		while (cu != null && n < count) {
			Address at = cu.getAddress();
			Function f = p.getFunctionManager().getFunctionAt(at);
			if (f != null) {
				sb.append("; ---- function ").append(f.getName(true)).append(" ----\n");
			}
			String plate = cu.getComment(CommentType.PLATE);
			if (plate != null) {
				sb.append("; ").append(Fmt.oneLine(plate)).append('\n');
			}
			if (cu instanceof Instruction ins) {
				sb.append(instructionLine(p, ins, false));
			}
			else {
				String label = Fmt.label(p, at);
				if (label != null) {
					sb.append(label).append(":\n");
				}
				Data d = (Data) cu;
				sb.append(Fmt.addr(at)).append(": ");
				try {
					sb.append(String.format("%-12s", Fmt.hex(d.getBytes()).replace(" ", "")));
				}
				catch (MemoryAccessException e) {
					sb.append("??          ");
				}
				if (d.isDefined()) {
					sb.append(' ').append(d.getDataType().getDisplayName()).append(' ')
							.append(Fmt.oneLine(d.getDefaultValueRepresentation()));
				}
				else {
					sb.append(" (undefined)");
				}
				String eol = cu.getComment(CommentType.EOL);
				if (eol != null) {
					sb.append("  ; ").append(Fmt.oneLine(eol));
				}
			}
			sb.append('\n');
			n++;
			Address next = cu.getMaxAddress().next();
			CodeUnit following = next == null ? null : listing.getCodeUnitAt(next);
			if (following == null) {
				// End of a block: carry on in the next one, and say so.
				following = listing.getCodeUnitAfter(cu.getMaxAddress());
				if (following != null) {
					sb.append("; ---- gap: next block at ").append(Fmt.addr(following.getAddress())).append(" ----\n");
				}
			}
			cu = following;
		}
		return sb.toString().stripTrailing();
	}

	@Tool(name = "get_function_by_address", description = "Describe the function at, or containing, an "
			+ "address: name, entry, signature, calling convention, body range and size, "
			+ "parameters, flags (thunk, no-return, external), plate comment.")
	public String getFunctionByAddress(Ctx ctx,
			@P(value = "address", description = "Address inside the function, or its name") String address) {
		return describe(ctx.fnAt(address));
	}

	static String describe(Function f) {
		StringBuilder sb = new StringBuilder();
		sb.append("Function: ").append(f.getName(true)).append('\n');
		sb.append("Entry: ").append(Fmt.addr(f.getEntryPoint())).append('\n');
		sb.append("Signature: ").append(f.getSignature().getPrototypeString()).append('\n');
		sb.append("Calling convention: ").append(f.getCallingConventionName()).append('\n');
		sb.append("Body: ").append(Fmt.addr(f.getBody().getMinAddress())).append(" - ")
				.append(Fmt.addr(f.getBody().getMaxAddress())).append(" (")
				.append(f.getBody().getNumAddresses()).append(" bytes")
				.append(f.getBody().getNumAddressRanges() > 1
						? ", " + f.getBody().getNumAddressRanges() + " ranges" : "")
				.append(")\n");
		Parameter[] params = f.getParameters();
		if (params.length > 0) {
			sb.append("Parameters:\n");
			for (Parameter prm : params) {
				sb.append("  ").append(prm.getDataType().getDisplayName()).append(' ').append(prm.getName())
						.append("  [").append(prm.getVariableStorage()).append("]\n");
			}
		}
		List<String> flags = new ArrayList<>();
		if (f.isThunk()) {
			Function t = f.getThunkedFunction(true);
			flags.add("thunk to " + (t != null ? Fmt.fn(t) : "?"));
		}
		if (f.hasNoReturn()) {
			flags.add("no-return");
		}
		if (f.isExternal()) {
			flags.add("external");
		}
		if (f.hasVarArgs()) {
			flags.add("varargs");
		}
		if (f.isInline()) {
			flags.add("inline");
		}
		sb.append("Signature source: ").append(f.getSignatureSource()).append('\n');
		if (!flags.isEmpty()) {
			sb.append("Flags: ").append(String.join(", ", flags)).append('\n');
		}
		String plate = f.getComment();
		if (plate != null) {
			sb.append("Plate comment: ").append(Fmt.oneLine(plate)).append('\n');
		}
		return sb.toString().stripTrailing();
	}

	// ---------------------------------------------------------------------
	// Creating, removing
	// ---------------------------------------------------------------------

	@Tool(name = "create_function", readOnly = false, description = "Create a function at one or more "
			+ "addresses, disassembling first if the bytes are undefined. Auto-analysis leaves code that "
			+ "nothing references statically (jump-table targets, hand-written assembly, overlays) as "
			+ "undefined bytes. Refuses an address inside an existing function, since that would split it. "
			+ "Returns a per-address report and counts.")
	public String createFunction(Ctx ctx,
			@P(value = "address", description = "One address, or several separated by commas") String address,
			@P(value = "name", def = "", description = "Name to give; only used when one address is given") String name) {
		Program p = ctx.program();
		String[] parts = address.split(",");
		List<Address> addrs = new ArrayList<>();
		StringBuilder report = new StringBuilder();
		int failed = 0;
		for (String raw : parts) {
			if (raw.isBlank()) {
				continue;
			}
			try {
				addrs.add(ctx.addr(raw));
			}
			catch (ToolError e) {
				report.append(raw.trim()).append(": ").append(e.getMessage()).append('\n');
				failed++;
			}
		}
		String single = addrs.size() == 1 && parts.length == 1 && name != null && !name.isBlank() ? name.trim() : null;
		int[] counts = { 0, 0, failed };
		String body = ctx.write("Create Function", () -> {
			FunctionManager fm = p.getFunctionManager();
			for (Address a : addrs) {
				Function existing = fm.getFunctionAt(a);
				if (existing != null) {
					report.append(Fmt.addr(a)).append(": already defined as ").append(existing.getName()).append('\n');
					counts[1]++;
					continue;
				}
				Function containing = fm.getFunctionContaining(a);
				if (containing != null) {
					report.append(Fmt.addr(a)).append(": inside ").append(Fmt.fn(containing))
							.append(" -- creating here would split it. Refused; delete that function first if you mean to\n");
					counts[2]++;
					continue;
				}
				if (p.getListing().getInstructionAt(a) == null) {
					new DisassembleCommand(a, null, true).applyTo(p, TaskMonitor.DUMMY);
					if (p.getListing().getInstructionAt(a) == null) {
						report.append(Fmt.addr(a)).append(": could not disassemble here (data defined, or invalid instruction)\n");
						counts[2]++;
						continue;
					}
				}
				CreateFunctionCmd cmd = new CreateFunctionCmd(single, a, null,
						single != null ? SourceType.USER_DEFINED : SourceType.DEFAULT);
				if (cmd.applyTo(p, TaskMonitor.DUMMY)) {
					Function nf = fm.getFunctionAt(a);
					report.append(Fmt.addr(a)).append(": created ").append(nf != null ? Fmt.fn(nf) : "?");
					if (nf != null) {
						report.append(" (").append(nf.getBody().getNumAddresses()).append(" bytes)");
					}
					report.append('\n');
					counts[0]++;
				}
				else {
					report.append(Fmt.addr(a)).append(": ").append(cmd.getStatusMsg()).append('\n');
					counts[2]++;
				}
			}
			return report.toString();
		});
		String summary = counts[0] + " created, " + counts[1] + " already defined, " + counts[2] + " failed";
		if (counts[0] == 0 && counts[1] == 0) {
			throw ToolError.failed(body + "\n" + summary);
		}
		return body + "\n" + summary;
	}

	@Tool(name = "delete_function", readOnly = false, description = "Delete the function defined at one "
			+ "or more addresses (the inverse of create_function). Removes the definition (name, "
			+ "signature, locals) and leaves the instructions. Only an address a function STARTS at is "
			+ "deleted; an address inside one is reported and left alone.")
	public String deleteFunction(Ctx ctx,
			@P(value = "address", description = "One address, or several separated by commas") String address) {
		Program p = ctx.program();
		StringBuilder report = new StringBuilder();
		int[] counts = { 0, 0, 0 };
		List<Address> addrs = new ArrayList<>();
		for (String raw : address.split(",")) {
			if (raw.isBlank()) {
				continue;
			}
			try {
				addrs.add(ctx.addr(raw));
			}
			catch (ToolError e) {
				report.append(raw.trim()).append(": ").append(e.getMessage()).append('\n');
				counts[2]++;
			}
		}
		ctx.write("Delete Function", () -> {
			FunctionManager fm = p.getFunctionManager();
			for (Address a : addrs) {
				Function f = fm.getFunctionAt(a);
				if (f == null) {
					Function c = fm.getFunctionContaining(a);
					report.append(Fmt.addr(a)).append(": no function starts here")
							.append(c != null ? " (it is inside " + Fmt.fn(c) + ", which is left alone)" : "")
							.append('\n');
					counts[1]++;
					continue;
				}
				String n = f.getName();
				if (fm.removeFunction(a)) {
					report.append(Fmt.addr(a)).append(": deleted ").append(n).append('\n');
					counts[0]++;
				}
				else {
					report.append(Fmt.addr(a)).append(": Ghidra refused to remove ").append(n).append('\n');
					counts[2]++;
				}
			}
			return null;
		});
		String summary = counts[0] + " deleted, " + counts[1] + " not present, " + counts[2] + " failed";
		if (counts[0] == 0) {
			throw ToolError.notFound(report + "\n" + summary);
		}
		return report + "\n" + summary;
	}

	@Tool(name = "disassemble", readOnly = false, description = "Disassemble undefined bytes starting at an "
			+ "address, following the flow (calls, branches) as Ghidra's D key does, without creating a "
			+ "function. Reports how many instructions now exist.")
	public String disassemble(Ctx ctx,
			@P(value = "address", description = "Start address") String address,
			@P(value = "follow_flow", def = "true", description = "Follow branches and calls") boolean followFlow) {
		Program p = ctx.program();
		Address a = ctx.addr(address);
		long before = p.getListing().getNumInstructions();
		ctx.write("Disassemble", () -> {
			DisassembleCommand cmd = followFlow ? new DisassembleCommand(a, null, true)
					: new DisassembleCommand(new AddressSet(a, a), new AddressSet(a, a), false);
			if (!cmd.applyTo(p, TaskMonitor.DUMMY) && p.getListing().getInstructionAt(a) == null) {
				throw ToolError.failed("Could not disassemble at " + Fmt.addr(a) + ": " + cmd.getStatusMsg());
			}
			return null;
		});
		long added = p.getListing().getNumInstructions() - before;
		if (p.getListing().getInstructionAt(a) == null) {
			throw ToolError.failed("No instruction at " + Fmt.addr(a) + " after disassembly");
		}
		return added + " instructions created from " + Fmt.addr(a);
	}

	// ---------------------------------------------------------------------
	// Naming and typing
	// ---------------------------------------------------------------------

	@Tool(name = "rename_function", readOnly = false, description = "Rename a function given its current "
			+ "name. Prefer rename_function_by_address: names can be ambiguous.")
	public String renameFunction(Ctx ctx,
			@P(value = "old_name", description = "Current name") String oldName,
			@P(value = "new_name", description = "New name") String newName) {
		return rename(ctx, ctx.fnByName(oldName), newName);
	}

	@Tool(name = "rename_function_by_address", readOnly = false, description = "Rename the function at, or "
			+ "containing, an address.")
	public String renameFunctionByAddress(Ctx ctx,
			@P(value = "function_address", description = "Address inside the function") String functionAddress,
			@P(value = "new_name", description = "New name") String newName) {
		return rename(ctx, ctx.fnAt(functionAddress), newName);
	}

	private static String rename(Ctx ctx, Function f, String newName) {
		if (newName == null || newName.isBlank()) {
			throw ToolError.missing("new_name");
		}
		String old = f.getName(true);
		ctx.write("Rename Function", () -> {
			f.setName(newName.trim(), SourceType.USER_DEFINED);
			return null;
		});
		return "Renamed " + old + " to " + f.getName(true) + " @ " + Fmt.addr(f.getEntryPoint());
	}

	@Tool(name = "set_function_prototype", readOnly = false, description = "Set a function's signature from "
			+ "a C prototype, e.g. 'int damage_actor(Actor *a, int amount)' or "
			+ "'void __stdcall f(void)'. Types must exist (create them first). The name in the prototype "
			+ "renames the function.")
	public String setFunctionPrototype(Ctx ctx,
			@P(value = "function_address", description = "Address inside the function") String functionAddress,
			@P(value = "prototype", description = "C prototype") String prototype) {
		Program p = ctx.program();
		Function f = ctx.fnAt(functionAddress);
		if (prototype == null || prototype.isBlank()) {
			throw ToolError.missing("prototype");
		}
		DataTypeQueryService dts = ctx.tool.getService(DataTypeQueryService.class);
		FunctionDefinitionDataType sig;
		try {
			sig = new FunctionSignatureParser(p.getDataTypeManager(), dts).parse(f.getSignature(), prototype.trim());
		}
		catch (Exception e) {
			throw ToolError.invalid("Could not parse prototype '" + prototype.trim() + "': " + Ctx.describe(e)
					+ ". Check that every type exists (unknown names are not guessed).");
		}
		ctx.write("Set Function Prototype", () -> {
			ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(f.getEntryPoint(), sig,
					SourceType.USER_DEFINED, false, false, DataTypeConflictHandler.DEFAULT_HANDLER,
					FunctionRenameOption.RENAME);
			if (!cmd.applyTo(p, TaskMonitor.DUMMY)) {
				throw ToolError.failed("Could not apply prototype: " + cmd.getStatusMsg());
			}
			// A prototype that names no convention leaves "unknown", and the decompiler
			// then warns on every function. Use the compiler's default instead.
			if (Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(f.getCallingConventionName())
					&& p.getCompilerSpec().getDefaultCallingConvention() != null) {
				f.setCallingConvention(p.getCompilerSpec().getDefaultCallingConvention().getName());
			}
			return null;
		});
		return "Prototype of " + Fmt.addr(f.getEntryPoint()) + " is now: " + f.getSignature().getPrototypeString();
	}

	@Tool(name = "set_function_no_return", readOnly = false, description = "Mark (or unmark) a function as "
			+ "never returning, e.g. an error handler or an infinite loop. Wrongly unmarked, such calls make "
			+ "the decompiler run into the following function.")
	public String setFunctionNoReturn(Ctx ctx,
			@P(value = "function_address", description = "Address inside the function") String functionAddress,
			@P(value = "no_return", def = "true", description = "true to mark no-return, false to clear") boolean noReturn) {
		Function f = ctx.fnAt(functionAddress);
		ctx.write("Set No-Return", () -> {
			f.setNoReturn(noReturn);
			return null;
		});
		return Fmt.fn(f) + (noReturn ? " is now no-return" : " now returns normally");
	}
}
