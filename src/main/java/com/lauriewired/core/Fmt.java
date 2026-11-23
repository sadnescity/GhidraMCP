package com.lauriewired.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

/** The few text shapes every tool shares, so outputs read the same everywhere. */
public final class Fmt {

	private Fmt() {
	}

	/** "name @ 0x80010000" */
	public static String fn(Function f) {
		return f == null ? "?" : f.getName(true) + " @ " + addr(f.getEntryPoint());
	}

	/** "0x80010000" for memory addresses, Ghidra's own text otherwise. */
	public static String addr(Address a) {
		if (a == null) {
			return "?";
		}
		if (a.isMemoryAddress() && !a.getAddressSpace().isOverlaySpace()
				&& a.getAddressSpace().equals(a.getAddressSpace().getPhysicalSpace())) {
			return "0x" + a.toString(false);
		}
		return a.toString(true);
	}

	/** The primary symbol's name at an address, or null. */
	public static String label(Program p, Address a) {
		Symbol s = p.getSymbolTable().getPrimarySymbol(a);
		return s == null ? null : s.getName(true);
	}

	/** "0x80010010 (in name @ 0x80010000)" or just the address. */
	public static String where(Program p, Address a) {
		Function f = p.getFunctionManager().getFunctionContaining(a);
		return f == null ? addr(a) : addr(a) + " (in " + fn(f) + ")";
	}

	private static final ghidra.program.model.listing.CodeUnitFormat FORMAT =
			new ghidra.program.model.listing.CodeUnitFormat(ghidra.program.model.listing.CodeUnitFormatOptions.ShowBlockName.NEVER,
					ghidra.program.model.listing.CodeUnitFormatOptions.ShowNamespace.NON_LOCAL);

	/**
	 * An instruction as the Ghidra listing shows it: operands that point at
	 * named things show the name ("jal clamp_int"), equates show their name.
	 */
	public static String instruction(ghidra.program.model.listing.Instruction ins) {
		try {
			return FORMAT.getRepresentationString(ins);
		}
		catch (Exception e) {
			return ins.toString();
		}
	}

	public static String hex(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 3);
		for (byte b : bytes) {
			if (sb.length() > 0) {
				sb.append(' ');
			}
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	public static String oneLine(String s) {
		return s == null ? "" : s.replace("\r", "").replace("\n", "\\n");
	}
}
