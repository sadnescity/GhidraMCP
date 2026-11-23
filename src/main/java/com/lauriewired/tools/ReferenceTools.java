package com.lauriewired.tools;

import java.util.Locale;

import com.lauriewired.core.Ctx;
import com.lauriewired.core.Fmt;
import com.lauriewired.core.P;
import com.lauriewired.core.Tool;
import com.lauriewired.core.ToolError;
import com.lauriewired.core.ToolRegistry;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;

/** References and equates the analyzer could not infer. */
public final class ReferenceTools {

	@Tool(name = "add_reference", readOnly = false, description = "Add a reference from an instruction or "
			+ "data address to a target the analyzer could not infer: a pointer computed at run time, a "
			+ "jump-table entry, a callback stored in a table. Makes the target show up in xrefs and, for "
			+ "calls/jumps, in the call graph.")
	public String addReference(Ctx ctx,
			@P(value = "from_address", description = "Instruction or data address the reference starts at") String fromAddress,
			@P(value = "to_address", description = "Target address") String toAddress,
			@P(value = "ref_type", def = "DATA", oneOf = { "DATA", "READ", "WRITE", "READ_WRITE", "CALL", "JUMP",
					"COMPUTED_CALL", "COMPUTED_JUMP" }, description = "Kind of reference") String refType,
			@P(value = "operand_index", def = "-1", description = "Operand the reference belongs to; -1 = the instruction/data itself") int operandIndex) {
		Program p = ctx.program();
		Address from = ctx.addr(fromAddress);
		Address to = ctx.addr(toAddress);
		RefType t = switch (refType.toUpperCase(Locale.ROOT)) {
			case "READ" -> RefType.READ;
			case "WRITE" -> RefType.WRITE;
			case "READ_WRITE" -> RefType.READ_WRITE;
			case "CALL" -> RefType.UNCONDITIONAL_CALL;
			case "JUMP" -> RefType.UNCONDITIONAL_JUMP;
			case "COMPUTED_CALL" -> RefType.COMPUTED_CALL;
			case "COMPUTED_JUMP" -> RefType.COMPUTED_JUMP;
			default -> RefType.DATA;
		};
		ctx.write("Add Reference", () -> {
			Reference r = p.getReferenceManager().addMemoryReference(from, to, t, SourceType.USER_DEFINED, operandIndex);
			if (r == null) {
				throw ToolError.failed("Ghidra did not add the reference");
			}
			return null;
		});
		return "Added " + t.getName() + " reference " + Fmt.addr(from) + " -> " + Fmt.addr(to);
	}

	@Tool(name = "remove_reference", readOnly = false, description = "Remove the references from one address "
			+ "to another (all kinds), e.g. a wrong pointer the analyzer guessed.")
	public String removeReference(Ctx ctx,
			@P(value = "from_address", description = "Source address") String fromAddress,
			@P(value = "to_address", description = "Target address") String toAddress) {
		Program p = ctx.program();
		Address from = ctx.addr(fromAddress);
		Address to = ctx.addr(toAddress);
		int n = ctx.write("Remove Reference", () -> {
			ReferenceManager rm = p.getReferenceManager();
			int c = 0;
			for (Reference r : rm.getReferencesFrom(from)) {
				if (r.getToAddress().equals(to)) {
					rm.delete(r);
					c++;
				}
			}
			if (c == 0) {
				throw ToolError.notFound("No reference from " + Fmt.addr(from) + " to " + Fmt.addr(to));
			}
			return c;
		});
		return "Removed " + n + " reference(s) " + Fmt.addr(from) + " -> " + Fmt.addr(to);
	}

	@Tool(name = "set_equate", readOnly = false, description = "Show a constant operand by name (an equate), "
			+ "e.g. 0x1f801810 as GPU_DATA or 4 as ITEM_POTION, in the listing and the decompiler. Finds "
			+ "the operand holding the value at the instruction; pass operand_index if several do. An empty "
			+ "name removes the equate there.")
	public String setEquate(Ctx ctx,
			@P(value = "address", description = "Instruction address") String address,
			@P(value = "value", description = "The constant, decimal or 0x hex") String value,
			@P(value = "name", description = "Equate name; empty to remove") String name,
			@P(value = "operand_index", def = "-1", description = "Operand index; -1 = find it") int operandIndex) {
		Program p = ctx.program();
		Address a = ctx.addr(address);
		long v = ToolRegistry.parseLong(value);
		Instruction ins = p.getListing().getInstructionAt(a);
		if (ins == null) {
			throw ToolError.notFound("No instruction at " + Fmt.addr(a));
		}
		int op = operandIndex;
		if (op < 0) {
			for (int i = 0; i < ins.getNumOperands() && op < 0; i++) {
				for (Object o : ins.getOpObjects(i)) {
					if (o instanceof Scalar s && (s.getUnsignedValue() == v || s.getSignedValue() == v)) {
						op = i;
						break;
					}
				}
			}
			if (op < 0) {
				throw ToolError.notFound("No operand of '" + ins + "' holds the value " + value);
			}
		}
		int opIndex = op;
		ctx.write("Set Equate", () -> {
			EquateTable et = p.getEquateTable();
			for (Equate e : et.getEquates(a, opIndex)) {
				e.removeReference(a, opIndex);
				if (e.getReferenceCount() == 0) {
					et.removeEquate(e.getName());
				}
			}
			if (name != null && !name.isBlank()) {
				Equate e = et.getEquate(name.trim());
				if (e == null) {
					e = et.createEquate(name.trim(), v);
				}
				else if (e.getValue() != v) {
					throw ToolError.conflict("Equate " + name + " already means 0x" + Long.toHexString(e.getValue()));
				}
				e.addReference(a, opIndex);
			}
			return null;
		});
		return (name == null || name.isBlank() ? "Removed equate" : "Equate " + name.trim() + " = " + value)
				+ " at " + Fmt.addr(a) + " operand " + opIndex;
	}
}
