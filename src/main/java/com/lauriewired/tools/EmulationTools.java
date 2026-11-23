package com.lauriewired.tools;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.lauriewired.core.Ctx;
import com.lauriewired.core.Fmt;
import com.lauriewired.core.P;
import com.lauriewired.core.Tool;
import com.lauriewired.core.ToolError;
import com.lauriewired.core.ToolRegistry;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/** P-code emulation of a function, with chosen inputs. */
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
		EmulatorHelper emu = new EmulatorHelper(p);
		try {
			emu.enableMemoryWriteTracking(true);
			// Ops the emulator has no model for (MIPS setISAMode on every jr ra, GTE/COP2,
			// syscalls...) are skipped with a zero result rather than ending the run, and
			// counted, so the report says what was not emulated.
			java.util.Map<String, Integer> skipped = new java.util.TreeMap<>();
			emu.registerDefaultCallOtherCallback(new ghidra.pcode.emulate.BreakCallBack() {
				@Override
				public boolean pcodeCallback(ghidra.pcode.pcoderaw.PcodeOpRaw op) {
					String opName = emulate.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset());
					skipped.merge(opName == null ? "callother" : opName, 1, Integer::sum);
					if (op.getOutput() != null) {
						emulate.getMemoryState().setValue(op.getOutput(), BigInteger.ZERO);
					}
					return true;
				}
			});
			Register pc = emu.getPCRegister();
			Register sp = emu.getStackPointerRegister();
			AddressSpace space = f.getEntryPoint().getAddressSpace();
			int ptr = p.getDefaultPointerSize();
			long spVal;
			if (stackPointer != null) {
				spVal = ctx.addr(stackPointer).getOffset();
			}
			else {
				long top = 0;
				for (ghidra.program.model.mem.MemoryBlock b : p.getMemory().getBlocks()) {
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
			Address sentinelAddr = space.getAddress(sentinel);
			if (sp != null) {
				emu.writeRegister(sp, BigInteger.valueOf(spVal));
			}
			// Return address: the link register where there is one, else on the stack.
			Register link = p.getLanguage().getRegister("ra");
			if (link == null) {
				link = p.getLanguage().getRegister("lr");
			}
			if (link != null) {
				emu.writeRegister(link, BigInteger.valueOf(sentinel));
			}
			else if (sp != null) {
				try {
					emu.writeStackValue(0, ptr, sentinel);
				}
				catch (Exception e) {
					throw ToolError.failed("Could not push the return address: " + Ctx.describe(e));
				}
			}
			for (String r : registers.keySet()) {
				Register reg = p.getLanguage().getRegister(r);
				if (reg == null) {
					throw ToolError.invalid("No register named '" + r + "' in " + p.getLanguage().getLanguageID());
				}
				JsonElement v = registers.get(r);
				long val = v.getAsJsonPrimitive().isString() ? ToolRegistry.parseLong(v.getAsString()) : v.getAsLong();
				emu.writeRegister(reg, BigInteger.valueOf(val));
			}
			for (JsonElement e : memory) {
				JsonObject o = e.getAsJsonObject();
				emu.writeMemory(ctx.addr(o.get("address").getAsString()),
						MemoryTools.decodeHex(o.get("bytes_hex").getAsString()));
			}
			emu.writeRegister(pc, f.getEntryPoint().getOffsetAsBigInteger());

			long steps = 0;
			String stop;
			while (true) {
				Address at = emu.getExecutionAddress();
				if (at != null && at.getOffset() == sentinel) {
					stop = "returned";
					break;
				}
				if (steps >= maxSteps) {
					stop = "step limit reached at " + Fmt.where(p, at);
					break;
				}
				boolean ok;
				try {
					ok = emu.step(TaskMonitor.DUMMY);
				}
				catch (Exception ex) {
					stop = "error at " + Fmt.where(p, emu.getExecutionAddress()) + ": " + Ctx.describe(ex);
					break;
				}
				if (!ok) {
					String err = emu.getLastError();
					stop = "stopped at " + Fmt.where(p, emu.getExecutionAddress())
							+ (err != null ? ": " + err : "");
					break;
				}
				steps++;
			}

			StringBuilder sb = new StringBuilder();
			sb.append("Emulated ").append(Fmt.fn(f)).append(": ").append(stop).append(" after ").append(steps)
					.append(" instructions\n");
			skipped.remove("setISAMode");
			if (!skipped.isEmpty()) {
				sb.append("Not emulated (result taken as 0): ").append(skipped).append('\n');
			}
			List<String> regs = new ArrayList<>();
			if (readRegisters.size() > 0) {
				for (JsonElement e : readRegisters) {
					regs.add(e.getAsString());
				}
			}
			else {
				for (String r : new String[] { "v0", "v1", "r0", "eax", "edx", "rax", "x0", "w0" }) {
					if (p.getLanguage().getRegister(r) != null) {
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
				Register reg = p.getLanguage().getRegister(r);
				if (reg == null) {
					sb.append("  ").append(r).append(": no such register\n");
					continue;
				}
				BigInteger v = emu.readRegister(reg);
				sb.append("  ").append(r).append(" = 0x").append(v.toString(16)).append(" (").append(v).append(")\n");
			}
			AddressSetView written = emu.getTrackedMemoryWriteSet();
			ghidra.program.model.address.AddressSet mem = new ghidra.program.model.address.AddressSet();
			if (written != null) {
				for (AddressRange r : written) {
					if (r.getMinAddress().isMemoryAddress() && !r.getMinAddress().getAddressSpace().isUniqueSpace()
							&& !r.getMinAddress().getAddressSpace().isRegisterSpace()) {
						mem.add(r);
					}
				}
			}
			if (!mem.isEmpty()) {
				sb.append("Memory written (").append(mem.getNumAddresses()).append(" bytes):\n");
				Iterator<AddressRange> it = mem.getAddressRanges();
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
				byte[] bytes = emu.readMemory(a, len);
				sb.append("Memory at ").append(Fmt.addr(a)).append(":\n").append(hexdump(a, bytes)).append('\n');
			}
			return sb.toString().stripTrailing();
		}
		finally {
			emu.dispose();
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
