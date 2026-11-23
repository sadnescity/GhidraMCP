package com.lauriewired.tools;

import java.util.Iterator;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.lauriewired.core.Ctx;
import com.lauriewired.core.Fmt;
import com.lauriewired.core.P;
import com.lauriewired.core.Page;
import com.lauriewired.core.Tool;
import com.lauriewired.core.ToolError;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/** Searching bytes, instructions and the holes analysis left behind. */
public final class SearchTools {

	@Tool(name = "search_bytes", description = "Search memory for a byte pattern. Wildcards: '??' for any "
			+ "byte, '?' for any nibble (e.g. '3c 08 80 ?? 25 08' or '3c0880??'). Lists each hit with the "
			+ "function containing it. Paged.")
	public String searchBytes(Ctx ctx,
			@P(value = "bytes_hex", description = "Pattern in hex, with ?? / ? wildcards") String bytesHex,
			@P(value = "offset", def = "0", description = "Index of the first hit") int offset,
			@P(value = "limit", def = "100", description = "Maximum hits to return") int limit) {
		Program p = ctx.program();
		String h = bytesHex == null ? "" : bytesHex.replaceAll("0x", "").replaceAll("[\\s,]+", "");
		if (h.isEmpty() || h.length() % 2 != 0 || !h.matches("[0-9a-fA-F?]*")) {
			throw ToolError.invalid("Not a hex pattern: '" + bytesHex + "' (use ?? or ? as wildcards)");
		}
		int n = h.length() / 2;
		byte[] bytes = new byte[n];
		byte[] mask = new byte[n];
		boolean anyMask = false;
		for (int i = 0; i < n; i++) {
			char hi = h.charAt(2 * i);
			char lo = h.charAt(2 * i + 1);
			int b = 0;
			int m = 0;
			if (hi != '?') {
				b |= Character.digit(hi, 16) << 4;
				m |= 0xf0;
			}
			if (lo != '?') {
				b |= Character.digit(lo, 16);
				m |= 0x0f;
			}
			bytes[i] = (byte) b;
			mask[i] = (byte) m;
			anyMask |= m != 0xff;
		}
		Memory mem = p.getMemory();
		Page page = new Page(offset, limit);
		Address cur = mem.getMinAddress();
		int cap = offset + limit + 1;
		int count = 0;
		while (cur != null && count < cap) {
			Address found = mem.findBytes(cur, bytes, anyMask ? mask : null, true, TaskMonitor.DUMMY);
			if (found == null) {
				break;
			}
			Address f = found;
			page.offer(() -> Fmt.where(p, f));
			count++;
			cur = found.next();
		}
		String out = page.render("No match for " + bytesHex);
		return count >= cap ? out.replaceAll("of \\d+;", "of " + (cap - 1) + "+;") : out;
	}

	@Tool(name = "search_instructions", description = "Search instructions by a regular expression, "
			+ "matched against both the raw text ('jal 0x80012345') and the listing text with names "
			+ "('jal clamp_int'), e.g. 'lui .*0x1f80' (hardware register access), "
			+ "'^jal 0x80012345', '^syscall'. Optionally only inside one function. Paged.")
	public String searchInstructions(Ctx ctx,
			@P(value = "pattern", description = "Java regex, matched case-insensitively against e.g. 'addiu sp,sp,-0x18'") String pattern,
			@P(value = "function_address", def = P.NULL, description = "Only search this function") String functionAddress,
			@P(value = "offset", def = "0", description = "Index of the first hit") int offset,
			@P(value = "limit", def = "200", description = "Maximum hits to return") int limit) {
		Program p = ctx.program();
		Pattern re;
		try {
			re = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
		}
		catch (PatternSyntaxException e) {
			throw ToolError.invalid("Bad regular expression: " + e.getDescription());
		}
		Listing listing = p.getListing();
		InstructionIterator it = functionAddress != null
				? listing.getInstructions(ctx.fnAt(functionAddress).getBody(), true)
				: listing.getInstructions(true);
		Page page = new Page(offset, limit);
		while (it.hasNext()) {
			Instruction ins = it.next();
			String raw = ins.toString();
			String shown = Fmt.instruction(ins);
			if (re.matcher(raw).find() || re.matcher(shown).find()) {
				page.offer(() -> Fmt.where(p, ins.getAddress()) + ": " + shown);
			}
		}
		return page.render("No instruction matches /" + pattern + "/");
	}

	@Tool(name = "find_code_gaps", description = "Find stretches of executable memory that no function "
			+ "covers: undefined bytes, and instructions outside any function. These are where analysis "
			+ "missed code (jump-table targets, functions only reached through pointers). Ranges shorter "
			+ "than min_length are skipped; all-zero ranges are reported as padding.")
	public String findCodeGaps(Ctx ctx,
			@P(value = "min_length", def = "16", description = "Smallest range to report, in bytes") int minLength,
			@P(value = "offset", def = "0", description = "Pagination offset") int offset,
			@P(value = "limit", def = "200", description = "Pagination limit") int limit) {
		Program p = ctx.program();
		AddressSet exec = new AddressSet();
		for (MemoryBlock b : p.getMemory().getBlocks()) {
			if (b.isExecute() && b.isInitialized()) {
				exec.add(b.getStart(), b.getEnd());
			}
		}
		if (exec.isEmpty()) {
			throw ToolError.notFound("No initialized executable memory block (check permissions with list_segments)");
		}
		AddressSet covered = new AddressSet();
		for (Function f : p.getFunctionManager().getFunctions(exec, true)) {
			covered.add(f.getBody());
		}
		DataIterator dit = p.getListing().getDefinedData(exec, true);
		while (dit.hasNext()) {
			Data d = dit.next();
			covered.add(d.getMinAddress(), d.getMaxAddress());
		}
		AddressSetView gaps = exec.subtract(covered);
		Page page = new Page(offset, limit);
		Iterator<AddressRange> it = gaps.getAddressRanges();
		Memory mem = p.getMemory();
		while (it.hasNext()) {
			AddressRange r = it.next();
			if (r.getLength() < minLength) {
				continue;
			}
			long insns = 0;
			InstructionIterator ii = p.getListing().getInstructions(new AddressSet(r), true);
			while (ii.hasNext()) {
				ii.next();
				insns++;
			}
			boolean zeros = insns == 0 && allZero(mem, r);
			long fi = insns;
			page.offer(() -> Fmt.addr(r.getMinAddress()) + "-" + Fmt.addr(r.getMaxAddress())
					+ String.format(" 0x%x bytes: ", r.getLength())
					+ (fi > 0 ? fi + " instructions outside any function" : zeros ? "zero padding" : "undefined"));
		}
		return page.render("No gaps of " + minLength + " bytes or more: every executable byte is in a function or data");
	}

	private static boolean allZero(Memory mem, AddressRange r) {
		long n = Math.min(r.getLength(), 4096);
		byte[] buf = new byte[(int) n];
		try {
			mem.getBytes(r.getMinAddress(), buf);
		}
		catch (Exception e) {
			return false;
		}
		for (byte b : buf) {
			if (b != 0) {
				return false;
			}
		}
		return true;
	}
}
