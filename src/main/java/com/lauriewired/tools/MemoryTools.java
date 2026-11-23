package com.lauriewired.tools;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

import com.lauriewired.core.Ctx;
import com.lauriewired.core.Fmt;
import com.lauriewired.core.P;
import com.lauriewired.core.Tool;
import com.lauriewired.core.ToolError;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/** Reading and writing program memory. */
public final class MemoryTools {

	public static final int MAX_READ = 65536;

	@Tool(name = "read_memory", description = "Read program memory as a hex dump with ASCII, 16 bytes per "
			+ "line. Bytes that are not mapped or not initialized show as '??' and are listed after the "
			+ "dump, so a gap can never pass for zeros.")
	public String readMemory(Ctx ctx,
			@P(value = "address", description = "Start address or symbol") String address,
			@P(value = "length", def = "256", description = "Number of bytes (max 65536)") int length) {
		if (length < 1 || length > MAX_READ) {
			throw ToolError.invalid("length must be between 1 and " + MAX_READ);
		}
		return dump(ctx.program(), ctx.addr(address), length);
	}

	@Tool(name = "get_bytes", description = "Read raw bytes as a hex dump (same as read_memory; kept for "
			+ "existing callers).")
	public String getBytes(Ctx ctx,
			@P(value = "address", description = "Start address or symbol") String address,
			@P(value = "size", def = "1", description = "Number of bytes (max 65536)") int size) {
		return readMemory(ctx, address, size);
	}

	static String dump(Program p, Address start, int length) {
		Memory mem = p.getMemory();
		StringBuilder out = new StringBuilder();
		StringBuilder gaps = new StringBuilder();
		String gapReason = null;
		Address gapStart = null;
		Address prev = null;
		int readable = 0;
		for (int line = 0; line < length; line += 16) {
			Address la;
			try {
				la = start.addNoWrap(line);
			}
			catch (Exception e) {
				break;
			}
			StringBuilder hex = new StringBuilder();
			StringBuilder ascii = new StringBuilder();
			for (int i = 0; i < 16; i++) {
				if (line + i >= length) {
					hex.append("   ");
					continue;
				}
				Address a;
				try {
					a = la.addNoWrap(i);
				}
				catch (Exception e) {
					break;
				}
				String reason = null;
				byte v = 0;
				MemoryBlock b = mem.getBlock(a);
				if (b == null) {
					reason = "unmapped";
				}
				else if (!b.isInitialized()) {
					reason = "uninitialized";
				}
				else {
					try {
						v = mem.getByte(a);
					}
					catch (MemoryAccessException e) {
						reason = "unreadable";
					}
				}
				if (!Objects.equals(reason, gapReason)) {
					if (gapReason != null) {
						gaps.append("  ").append(Fmt.addr(gapStart)).append('-').append(Fmt.addr(prev)).append(' ')
								.append(gapReason).append('\n');
					}
					gapReason = reason;
					gapStart = a;
				}
				prev = a;
				if (reason == null) {
					readable++;
					hex.append(String.format("%02x ", v & 0xff));
					ascii.append(v >= 0x20 && v < 0x7f ? (char) v : '.');
				}
				else {
					hex.append("?? ");
					ascii.append(' ');
				}
				if (i == 7) {
					hex.append(' ');
				}
			}
			out.append(Fmt.addr(la)).append("  ").append(hex).append(" |").append(ascii).append("|\n");
		}
		if (gapReason != null) {
			gaps.append("  ").append(Fmt.addr(gapStart)).append('-').append(Fmt.addr(prev)).append(' ')
					.append(gapReason).append('\n');
		}
		if (readable == 0) {
			throw ToolError.notFound("No readable bytes at " + Fmt.addr(start) + " (" + length + " bytes):\n" + gaps);
		}
		if (gaps.length() > 0) {
			out.append("Not readable:\n").append(gaps);
		}
		return out.toString().stripTrailing();
	}

	@Tool(name = "set_bytes", readOnly = false, description = "Write bytes into program memory (patch). "
			+ "Instructions overlapping the range are cleared and the range is disassembled again; defined "
			+ "data keeps its type with the new value.")
	public String setBytes(Ctx ctx,
			@P(value = "address", description = "Destination address") String address,
			@P(value = "bytes_hex", description = "Bytes in hex, e.g. '00 00 00 00' or '27bdffe8'") String bytesHex) {
		Program p = ctx.program();
		Address a = ctx.addr(address);
		byte[] bytes = decodeHex(bytesHex);
		Address end = a.add(bytes.length - 1L);
		Memory mem = p.getMemory();
		if (!mem.contains(a) || !mem.contains(end)) {
			throw ToolError.notFound("Range " + Fmt.addr(a) + "-" + Fmt.addr(end) + " is not entirely in memory");
		}
		byte[] old = new byte[bytes.length];
		ctx.write("Write Bytes", () -> {
			if (mem.getBytes(a, old) != old.length) {
				throw ToolError.failed("Could not read the current bytes");
			}
			Listing listing = p.getListing();
			boolean hadCode = false;
			Address clearStart = a;
			Address clearEnd = end;
			Instruction first = listing.getInstructionContaining(a);
			if (first != null) {
				clearStart = first.getMinAddress();
			}
			Instruction last = listing.getInstructionContaining(end);
			if (last != null) {
				clearEnd = last.getMaxAddress();
			}
			if (listing.getInstructions(new AddressSet(clearStart, clearEnd), true).hasNext()) {
				hadCode = true;
				listing.clearCodeUnits(clearStart, clearEnd, false);
			}
			mem.setBytes(a, bytes);
			if (hadCode) {
				new DisassembleCommand(new AddressSet(clearStart, clearEnd), null, true).applyTo(p, TaskMonitor.DUMMY);
			}
			return null;
		});
		return "Wrote " + bytes.length + " bytes at " + Fmt.where(p, a) + " (was: " + Fmt.hex(old) + ")";
	}

	@Tool(name = "create_memory_block", readOnly = false, description = "Add a memory block, e.g. to load an "
			+ "overlay or a data file into the program. Contents come from a file on disk (file_path, "
			+ "file_offset, length) or are zero-filled/uninitialized. overlay=true creates an overlay block "
			+ "that can share addresses with existing memory (PSX/PS2 overlays).")
	public String createMemoryBlock(Ctx ctx,
			@P(value = "name", description = "Block name (overlay name if overlay)") String name,
			@P(value = "address", description = "Start address") String address,
			@P(value = "length", def = "0", description = "Length in bytes (0 = the rest of the file)") long length,
			@P(value = "file_path", def = P.NULL, description = "File to read the contents from") String filePath,
			@P(value = "file_offset", def = "0", description = "Offset in the file") long fileOffset,
			@P(value = "overlay", def = "false", description = "Create an overlay block") boolean overlay,
			@P(value = "permissions", def = "rwx", description = "Any of r, w, x") String permissions,
			@P(value = "initialized", def = "true", description = "Without a file: zero-filled (true) or uninitialized") boolean initialized) {
		Program p = ctx.program();
		Address a = ctx.addr(address);
		byte[] data = null;
		long len = length;
		if (filePath != null) {
			try {
				byte[] all = Files.readAllBytes(Path.of(filePath));
				if (fileOffset < 0 || fileOffset > all.length) {
					throw ToolError.invalid("file_offset is past the end of the file (" + all.length + " bytes)");
				}
				if (len <= 0) {
					len = all.length - fileOffset;
				}
				if (fileOffset + len > all.length) {
					throw ToolError.invalid("file_offset + length is past the end of the file (" + all.length + " bytes)");
				}
				data = java.util.Arrays.copyOfRange(all, (int) fileOffset, (int) (fileOffset + len));
			}
			catch (java.io.IOException e) {
				throw ToolError.notFound("Cannot read " + filePath + ": " + Ctx.describe(e));
			}
		}
		if (len <= 0) {
			throw ToolError.missing("length (or file_path)");
		}
		long fl = len;
		byte[] fd = data;
		MemoryBlock b = ctx.write("Create Memory Block", () -> {
			Memory mem = p.getMemory();
			MemoryBlock nb;
			if (fd != null) {
				nb = mem.createInitializedBlock(name, a, new ByteArrayInputStream(fd), fl, TaskMonitor.DUMMY, overlay);
			}
			else if (initialized) {
				nb = mem.createInitializedBlock(name, a, fl, (byte) 0, TaskMonitor.DUMMY, overlay);
			}
			else {
				nb = mem.createUninitializedBlock(name, a, fl, overlay);
			}
			String perm = permissions.toLowerCase();
			nb.setRead(perm.contains("r"));
			nb.setWrite(perm.contains("w"));
			nb.setExecute(perm.contains("x"));
			return nb;
		});
		return "Created block " + b.getName() + " " + Fmt.addr(b.getStart()) + "-" + Fmt.addr(b.getEnd())
				+ String.format(" (0x%x bytes)", b.getSize()) + (b.isOverlay() ? " overlay" : "")
				+ (overlay ? ". Overlay addresses are written " + b.getStart().getAddressSpace().getName() + "::<offset>" : "");
	}

	static byte[] decodeHex(String hex) {
		if (hex == null || hex.isBlank()) {
			throw ToolError.missing("bytes_hex");
		}
		String h = hex.replaceAll("0x", "").replaceAll("[\\s,]+", "");
		if (h.length() % 2 != 0 || !h.matches("[0-9a-fA-F]*")) {
			throw ToolError.invalid("Not a hex byte string: '" + hex + "'");
		}
		byte[] out = new byte[h.length() / 2];
		for (int i = 0; i < out.length; i++) {
			out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
		}
		return out;
	}
}
