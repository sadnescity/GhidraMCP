package com.lauriewired.tools;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.lauriewired.core.Ctx;
import com.lauriewired.core.Fmt;
import com.lauriewired.core.P;
import com.lauriewired.core.Tool;
import com.lauriewired.core.ToolError;
import com.lauriewired.core.ToolRegistry;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeEmulationCallbacks;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.DecodePcodeExecutionException;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutionException;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeFrame;
import ghidra.pcode.exec.PcodeStateCallbacks;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/** P-code emulation of a function, with chosen inputs, on Ghidra's PcodeEmulator. */
public final class EmulationTools {

	@Tool(name = "emulate_function", description = "Run a function in Ghidra's P-code emulator with the "
			+ "register and memory inputs you give, until it returns (or a step limit, or an error), and "
			+ "report the result registers, the memory it wrote and any memory you ask to read. Use it to "
			+ "learn what a routine computes -- a decompressor, a checksum, a table lookup -- without running "
			+ "the game. The program itself is not modified. Calls into code that is not in the program "
			+ "(BIOS, hardware) stop the run with an error at that address.")
	public String emulateFunction(Ctx ctx,
			@P(value = "address", description = "Function address or name") String address,
			@P(value = "registers", def = "{}", description = "Initial registers, e.g. {\"a0\": \"0x80100000\", \"a1\": 16}") JsonObject registers,
			@P(value = "memory", def = "[]", description = "Memory to write first: [{\"address\", \"bytes_hex\"}]") JsonArray memory,
			@P(value = "read_memory", def = "[]", description = "Memory to read afterwards: [{\"address\", \"length\"}]") JsonArray readMemory,
			@P(value = "read_registers", def = "[]", description = "Registers to report (default: return value registers, sp, pc)") JsonArray readRegisters,
			@P(value = "max_steps", def = "2000000", description = "Instruction limit") long maxSteps,
			@P(value = "stack_pointer", def = P.NULL, description = "Initial stack pointer (default: an address above all program memory)") String stackPointer) {
		Program p = ctx.program();
		Function f = ctx.fnAt(address);
		Language lang = p.getLanguage();
		if (!(lang instanceof SleighLanguage sleigh)) {
			throw new ToolError("UNSUPPORTED", "The emulator needs a SLEIGH language; " + lang.getLanguageID() + " is not one.");
		}
		Emulation run = new Emulation(p);
		PcodeEmulator emu = new PcodeEmulator(sleigh, run);
		PcodeArithmetic<byte[]> arith = emu.getArithmetic();
		PcodeThread<byte[]> thread = emu.newThread();

		Register pc = lang.getProgramCounter();
		Register sp = p.getCompilerSpec().getStackPointer();
		AddressSpace space = f.getEntryPoint().getAddressSpace();
		int ptr = p.getDefaultPointerSize();
		long spVal;
		if (stackPointer != null) {
			spVal = ctx.addr(stackPointer).getOffset();
		}
		else {
			long top = 0;
			for (MemoryBlock b : p.getMemory().getBlocks()) {
				if (!b.isOverlay() && b.getStart().getAddressSpace().equals(space)) {
					top = Math.max(top, b.getEnd().getOffset());
				}
			}
			spVal = ((top + 0x1000000L) & ~0xffffL) + 0x8000L;
			if (ptr == 4 && spVal > 0xffffffffL) {
				spVal = 0xfffe0000L;
			}
		}
		long sentinel = (spVal + 0x4000L) & ~0xfL;
		if (sp != null) {
			setRegister(thread, arith, sp, BigInteger.valueOf(spVal));
		}
		// Return address: the link register where there is one, else on the stack.
		Register link = lang.getRegister("ra");
		if (link == null) {
			link = lang.getRegister("lr");
		}
		if (link != null) {
			setRegister(thread, arith, link, BigInteger.valueOf(sentinel));
		}
		else if (sp != null) {
			emu.getSharedState().setConcrete(space.getAddress(spVal), arith.fromConst(sentinel, ptr));
		}
		for (String r : registers.keySet()) {
			Register reg = lang.getRegister(r);
			if (reg == null) {
				throw ToolError.invalid("No register named '" + r + "' in " + lang.getLanguageID());
			}
			JsonElement v = registers.get(r);
			long val = v.getAsJsonPrimitive().isString() ? ToolRegistry.parseLong(v.getAsString()) : v.getAsLong();
			setRegister(thread, arith, reg, BigInteger.valueOf(val));
		}
		for (JsonElement e : memory) {
			JsonObject o = e.getAsJsonObject();
			Address a = ctx.addr(o.get("address").getAsString());
			byte[] bytes = MemoryTools.decodeHex(o.get("bytes_hex").getAsString());
			emu.getSharedState().setConcrete(a, bytes);
			if (bytes.length > 0) {
				run.provided.add(a, a.add(bytes.length - 1));
			}
		}
		thread.overrideCounter(f.getEntryPoint());
		thread.overrideContextWithDefault();
		RegisterValue context = p.getProgramContext().getDisassemblyContext(f.getEntryPoint());
		if (context != null) {
			thread.overrideContext(context);
		}
		run.tracking = true;

		long steps = 0;
		String stop;
		while (true) {
			Address at = thread.getCounter();
			if (at != null && at.getOffset() == sentinel && at.getAddressSpace().equals(space)) {
				stop = "returned";
				break;
			}
			if (steps >= maxSteps) {
				stop = "step limit reached at " + Fmt.where(p, at);
				break;
			}
			if ((steps & 0x3ff) == 0) {
				ctx.checkCancelled();
			}
			try {
				thread.stepInstruction();
			}
			catch (DecodePcodeExecutionException ex) {
				Address bad = thread.getCounter();
				stop = run.hasBytes(bad)
						? "stopped at " + Fmt.where(p, bad) + ": not a valid instruction (" + Ctx.describe(ex) + ")"
						: "stopped at " + Fmt.addr(bad) + ": nothing to execute there -- it is outside the program "
								+ "(BIOS, hardware, or code the emulation was not given)";
				break;
			}
			catch (PcodeExecutionException ex) {
				stop = "stopped at " + Fmt.where(p, thread.getCounter()) + ": " + Ctx.describe(ex);
				break;
			}
			steps++;
		}
		run.tracking = false;

		StringBuilder sb = new StringBuilder();
		sb.append("Emulated ").append(Fmt.fn(f)).append(": ").append(stop).append(" after ").append(steps)
				.append(" instructions\n");
		run.skipped.remove("setISAMode");
		if (!run.skipped.isEmpty()) {
			sb.append("Not emulated (result taken as 0): ").append(run.skipped).append('\n');
		}
		List<String> regs = new ArrayList<>();
		if (readRegisters.size() > 0) {
			for (JsonElement e : readRegisters) {
				regs.add(e.getAsString());
			}
		}
		else {
			for (String r : new String[] { "v0", "v1", "r0", "eax", "edx", "rax", "x0", "w0" }) {
				if (lang.getRegister(r) != null) {
					regs.add(r);
				}
			}
			if (sp != null) {
				regs.add(sp.getName());
			}
			if (!stop.equals("returned")) {
				regs.add(pc.getName());
			}
		}
		sb.append("Registers:\n");
		for (String r : regs) {
			Register reg = lang.getRegister(r);
			if (reg == null) {
				sb.append("  ").append(r).append(": no such register\n");
				continue;
			}
			BigInteger v = arith.toBigInteger(thread.getState().getVar(reg, Reason.INSPECT), Purpose.INSPECT);
			sb.append("  ").append(r).append(" = 0x").append(v.toString(16)).append(" (").append(v).append(")\n");
		}
		if (!run.written.isEmpty()) {
			sb.append("Memory written (").append(run.written.getNumAddresses()).append(" bytes):\n");
			Iterator<AddressRange> it = run.written.getAddressRanges();
			int n = 0;
			while (it.hasNext() && n < 40) {
				AddressRange r = it.next();
				boolean stack = r.getMinAddress().getOffset() >= spVal - 0x10000L && r.getMinAddress().getOffset() <= spVal + 0x100L;
				sb.append("  ").append(Fmt.addr(r.getMinAddress())).append('-').append(Fmt.addr(r.getMaxAddress()))
						.append(String.format(" (0x%x bytes)", r.getLength())).append(stack ? " stack" : "").append('\n');
				n++;
			}
			if (it.hasNext()) {
				sb.append("  ...\n");
			}
		}
		for (JsonElement e : readMemory) {
			JsonObject o = e.getAsJsonObject();
			Address a = ctx.addr(o.get("address").getAsString());
			int len = o.has("length") ? o.get("length").getAsInt() : 64;
			if (len < 1 || len > MemoryTools.MAX_READ) {
				throw ToolError.invalid("read_memory length must be 1.." + MemoryTools.MAX_READ);
			}
			byte[] bytes = emu.getSharedState().inspectConcrete(a, len);
			sb.append("Memory at ").append(Fmt.addr(a)).append(":\n").append(hexdump(a, bytes)).append('\n');
		}
		return sb.toString().stripTrailing();
	}

	private static void setRegister(PcodeThread<byte[]> thread, PcodeArithmetic<byte[]> arith, Register reg,
			BigInteger value) {
		int size = reg.getNumBytes();
		BigInteger mask = BigInteger.ONE.shiftLeft(size * 8).subtract(BigInteger.ONE);
		thread.getState().setVar(reg, arith.fromConst(value.and(mask), size));
	}

	/**
	 * What the emulator is told about the program: memory is read from the
	 * program the first time it is touched (so a large image costs nothing up
	 * front), writes are recorded once the run starts, and userops the emulator
	 * has no model for (MIPS setISAMode on every jr ra, GTE/COP2, syscalls...)
	 * are skipped with a zero result rather than ending the run, and counted so
	 * the report says what was not emulated. Code outside the program (BIOS,
	 * hardware) has no bytes, so decoding it stops the run at that address.
	 */
	private static final class Emulation implements PcodeEmulationCallbacks<byte[]> {
		private final Memory memory;
		private final AddressSetView loaded;
		final AddressSet written = new AddressSet();
		/** Memory the caller supplied. */
		final AddressSet provided = new AddressSet();
		final Map<String, Integer> skipped = new TreeMap<>();
		volatile boolean tracking;

		Emulation(Program p) {
			memory = p.getMemory();
			loaded = memory.getLoadedAndInitializedAddressSet();
		}

		/** Whether the emulator has bytes at this address: the program's, the caller's, or written by the run. */
		boolean hasBytes(Address a) {
			if (a == null) {
				return false;
			}
			synchronized (written) {
				return loaded.contains(a) || provided.contains(a) || written.contains(a);
			}
		}

		private static boolean isMemory(AddressSpace space) {
			return space.isMemorySpace() && !space.isRegisterSpace() && !space.isUniqueSpace();
		}

		@Override
		public <A, U> AddressSetView readUninitialized(PcodeThread<byte[]> thread,
				PcodeExecutorStatePiece<A, U> piece, AddressSetView set, Reason reason) {
			if (set.isEmpty() || !isMemory(set.getMinAddress().getAddressSpace())) {
				return set;
			}
			PcodeExecutorStatePiece<A, byte[]> bytes = PcodeStateCallbacks.checkValueDomain(piece, byte[].class);
			if (bytes == null) {
				return set;
			}
			AddressSet fromProgram = set.intersect(loaded);
			if (fromProgram.isEmpty()) {
				return set;
			}
			AddressSet remaining = new AddressSet(set);
			for (AddressRange r : fromProgram) {
				byte[] buf = new byte[(int) r.getLength()];
				try {
					memory.getBytes(r.getMinAddress(), buf);
				}
				catch (MemoryAccessException e) {
					continue;
				}
				bytes.setVarInternal(r.getAddressSpace(), r.getMinAddress().getOffset(), buf.length, buf);
				remaining.delete(r);
			}
			return remaining.equals(set) ? set : remaining;
		}

		@Override
		public <A, U> void dataWritten(PcodeThread<byte[]> thread, PcodeExecutorStatePiece<A, U> piece,
				Address address, int length, U value) {
			if (tracking && length > 0 && isMemory(address.getAddressSpace())) {
				synchronized (written) {
					written.add(address, address.add(length - 1));
				}
			}
		}

		@Override
		public boolean handleMissingUserop(PcodeThread<byte[]> thread, PcodeOp op, PcodeFrame frame,
				String opName, PcodeUseropLibrary<byte[]> library) {
			skipped.merge(opName == null ? "callother" : opName, 1, Integer::sum);
			Varnode out = op.getOutput();
			if (out != null) {
				thread.getState().setVar(out, new byte[out.getSize()]);
			}
			return true;
		}
	}

	private static String hexdump(Address a, byte[] b) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < b.length; i += 16) {
			sb.append("  ").append(Fmt.addr(a.add(i))).append("  ");
			StringBuilder ascii = new StringBuilder();
			for (int j = 0; j < 16 && i + j < b.length; j++) {
				int v = b[i + j] & 0xff;
				sb.append(String.format("%02x ", v));
				ascii.append(v >= 0x20 && v < 0x7f ? (char) v : '.');
			}
			sb.append(" |").append(ascii).append("|\n");
		}
		return sb.toString().stripTrailing();
	}
}
