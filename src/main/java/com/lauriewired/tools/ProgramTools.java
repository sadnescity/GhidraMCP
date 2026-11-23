package com.lauriewired.tools;

import com.lauriewired.core.Ctx;
import com.lauriewired.core.Fmt;
import com.lauriewired.core.P;
import com.lauriewired.core.Tool;
import com.lauriewired.core.ToolError;

import ghidra.app.services.CodeViewerService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/** The program itself, and the analyst's view of it. */
public final class ProgramTools {

	@Tool(name = "get_program_info", description = "Identify the target program: name, project path, "
			+ "format, processor/language, compiler spec, endianness, pointer size, image base, address "
			+ "range, memory blocks, function count, entry points, unsaved changes. Call it first to "
			+ "confirm which binary you are working on.")
	public String getProgramInfo(Ctx ctx) {
		Program p = ctx.program();
		Language lang = p.getLanguage();
		StringBuilder sb = new StringBuilder();
		DomainFile df = p.getDomainFile();
		sb.append("Name: ").append(p.getName()).append('\n');
		sb.append("Project path: ").append(df != null ? df.getPathname() : "?").append('\n');
		sb.append("Project: ").append(ctx.tool.getProject() != null ? ctx.tool.getProject().getName() : "?")
				.append('\n');
		sb.append("Format: ").append(p.getExecutableFormat()).append('\n');
		sb.append("Original file: ").append(p.getExecutablePath()).append('\n');
		sb.append("Language: ").append(lang.getLanguageID()).append(" (")
				.append(lang.getProcessor()).append(", ").append(lang.isBigEndian() ? "big" : "little")
				.append(" endian)\n");
		sb.append("Compiler spec: ").append(p.getCompilerSpec().getCompilerSpecID()).append('\n');
		sb.append("Pointer size: ").append(p.getDefaultPointerSize()).append('\n');
		sb.append("Image base: ").append(Fmt.addr(p.getImageBase())).append('\n');
		sb.append("Address range: ").append(Fmt.addr(p.getMinAddress())).append(" - ")
				.append(Fmt.addr(p.getMaxAddress())).append('\n');
		sb.append("Functions: ").append(p.getFunctionManager().getFunctionCount()).append('\n');
		sb.append("Unsaved changes: ").append(p.isChanged() ? "yes" : "no").append('\n');
		sb.append("Memory blocks:\n");
		for (MemoryBlock b : p.getMemory().getBlocks()) {
			sb.append("  ").append(b.getName()).append(' ').append(Fmt.addr(b.getStart())).append('-')
					.append(Fmt.addr(b.getEnd())).append(' ').append(String.format("0x%x bytes", b.getSize()))
					.append(' ').append(perms(b)).append(b.isInitialized() ? "" : " uninitialized")
					.append(b.isOverlay() ? " overlay" : "").append('\n');
		}
		AddressIterator it = p.getSymbolTable().getExternalEntryPointIterator();
		StringBuilder eps = new StringBuilder();
		int n = 0;
		while (it.hasNext() && n < 32) {
			Address a = it.next();
			String l = Fmt.label(p, a);
			eps.append(n == 0 ? "" : ", ").append(l != null ? l + " @ " : "").append(Fmt.addr(a));
			n++;
		}
		sb.append("Entry points: ").append(n == 0 ? "none" : eps).append(it.hasNext() ? ", ..." : "");
		return sb.toString();
	}

	static String perms(MemoryBlock b) {
		return (b.isRead() ? "r" : "-") + (b.isWrite() ? "w" : "-") + (b.isExecute() ? "x" : "-")
				+ (b.isVolatile() ? "v" : "");
	}

	@Tool(name = "get_current_address", description = "Get the address the analyst has selected in the "
			+ "Ghidra listing (cursor position).")
	public String getCurrentAddress(Ctx ctx) {
		ProgramLocation loc = location(ctx);
		return Fmt.where(ctx.program(), loc.getAddress());
	}

	@Tool(name = "get_current_function", description = "Get the function containing the analyst's "
			+ "cursor in the Ghidra listing.")
	public String getCurrentFunction(Ctx ctx) {
		ProgramLocation loc = location(ctx);
		Function f = ctx.program().getFunctionManager().getFunctionContaining(loc.getAddress());
		if (f == null) {
			throw ToolError.functionNotFound("contains the cursor at " + Fmt.addr(loc.getAddress()));
		}
		return FunctionTools.describe(f);
	}

	private static ProgramLocation location(Ctx ctx) {
		CodeViewerService cv = ctx.tool.getService(CodeViewerService.class);
		if (cv == null) {
			throw new ToolError("UNSUPPORTED", "This Ghidra tool has no listing view");
		}
		ProgramLocation loc = cv.getCurrentLocation();
		if (loc == null || loc.getAddress() == null) {
			throw ToolError.notFound("The listing has no cursor position");
		}
		if (loc.getProgram() != ctx.program()) {
			throw ToolError.conflict("The cursor is in " + (loc.getProgram() != null
					? loc.getProgram().getName() : "another program") + ", not in " + ctx.program().getName());
		}
		return loc;
	}

	@Tool(name = "goto_address", description = "Move the analyst's Ghidra listing and decompiler view to an "
			+ "address (or a function/label name), bringing the target program to the front. Use it to "
			+ "show the analyst what you are talking about.")
	public String gotoAddress(Ctx ctx, @P(value = "address", description = "Address or symbol name") String address) {
		Address a = ctx.addr(address);
		GoToService gs = ctx.tool.getService(GoToService.class);
		if (gs == null) {
			throw new ToolError("UNSUPPORTED", "This Ghidra tool has no Go To service");
		}
		boolean[] ok = new boolean[1];
		Ctx.onSwing(() -> {
			ProgramManager pm = ctx.tool.getService(ProgramManager.class);
			if (pm != null && pm.getCurrentProgram() != ctx.program()) {
				pm.setCurrentProgram(ctx.program());
			}
			ok[0] = gs.goTo(a, ctx.program());
		});
		if (!ok[0]) {
			throw ToolError.failed("Ghidra could not go to " + Fmt.addr(a));
		}
		return "Showing " + Fmt.where(ctx.program(), a);
	}

	@Tool(name = "save_program", readOnly = false, description = "Save the program's changes to the "
			+ "project, as File > Save does. Changes made through these tools are otherwise unsaved "
			+ "until the analyst saves.")
	public String saveProgram(Ctx ctx) {
		Program p = ctx.program();
		if (!p.isChanged()) {
			return p.getName() + " has no unsaved changes";
		}
		DomainFile df = p.getDomainFile();
		if (df == null || df.isReadOnly()) {
			throw ToolError.conflict(p.getName() + " is read-only in this project and cannot be saved");
		}
		Exception[] err = new Exception[1];
		Ctx.onSwing(() -> {
			try {
				df.save(TaskMonitor.DUMMY);
			}
			catch (Exception e) {
				err[0] = e;
			}
		});
		if (err[0] != null) {
			throw ToolError.failed("Save failed: " + Ctx.describe(err[0]), err[0]);
		}
		return "Saved " + p.getName();
	}
}
