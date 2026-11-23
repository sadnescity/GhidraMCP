package com.lauriewired.tools;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.lauriewired.core.Ctx;
import com.lauriewired.core.Fmt;
import com.lauriewired.core.ToolError;
import com.lauriewired.core.ToolRegistry;

import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;

/** Parsing and placing struct/union members, shared by the struct, union and class tools. */
final class Members {

	private Members() {
	}

	record Member(String name, DataType type, int offset, String comment) {
	}

	/** Parses [{name, type, offset?, comment?}], resolving every type before anything is changed. */
	static List<Member> parse(Ctx ctx, JsonArray arr) {
		if (arr == null) {
			return List.of();
		}
		List<Member> out = new ArrayList<>();
		for (JsonElement e : arr) {
			if (!e.isJsonObject()) {
				throw ToolError.invalid("Each member must be an object {name, type, offset?, comment?}");
			}
			JsonObject o = e.getAsJsonObject();
			String name = o.has("name") && !o.get("name").isJsonNull() ? o.get("name").getAsString() : null;
			if (!o.has("type")) {
				throw ToolError.missing("type (member " + name + ")");
			}
			DataType dt;
			try {
				dt = ctx.type(o.get("type").getAsString());
			}
			catch (ToolError te) {
				throw new ToolError(te.code(), "Member '" + name + "': " + te.getMessage());
			}
			int offset = -1;
			if (o.has("offset") && !o.get("offset").isJsonNull()) {
				JsonElement oe = o.get("offset");
				offset = oe.getAsJsonPrimitive().isString() ? (int) ToolRegistry.parseLong(oe.getAsString())
						: oe.getAsInt();
			}
			String comment = o.has("comment") && !o.get("comment").isJsonNull() ? o.get("comment").getAsString() : null;
			out.add(new Member(name, dt, offset, comment));
		}
		return out;
	}

	/**
	 * Places a member. With an offset inside the struct, it replaces the
	 * undefined bytes there (and fails, naming the field, if a defined field is
	 * in the way); with an offset past the end, the struct grows to reach it;
	 * with none, it is appended.
	 */
	static void place(Composite c, Member m) {
		int len = m.type.getLength() > 0 ? m.type.getLength() : -1;
		if (len < 0) {
			throw ToolError.invalid("Member '" + m.name + "': type " + m.type.getDisplayName()
					+ " has no fixed size");
		}
		if (!(c instanceof Structure s) || m.offset < 0) {
			c.add(m.type, len, m.name, m.comment);
			return;
		}
		if (m.offset >= s.getLength()) {
			if (m.offset > s.getLength()) {
				s.growStructure(m.offset - s.getLength());
			}
			s.add(m.type, len, m.name, m.comment);
			return;
		}
		for (DataTypeComponent dc : s.getDefinedComponents()) {
			int start = dc.getOffset();
			int end = start + dc.getLength();
			if (m.offset < end && m.offset + len > start) {
				throw ToolError.conflict("Member '" + m.name + "' at offset 0x" + Integer.toHexString(m.offset)
						+ " (" + len + " bytes) overlaps field '" + dc.getFieldName() + "' at 0x"
						+ Integer.toHexString(start) + " (" + dc.getLength() + " bytes). Remove or modify it first.");
			}
		}
		if (m.offset + len > s.getLength()) {
			s.growStructure(m.offset + len - s.getLength());
		}
		s.replaceAtOffset(m.offset, m.type, len, m.name, m.comment);
	}

	/** A C-like rendering of a struct or union, with offsets and gaps. */
	static String render(Composite c) {
		StringBuilder sb = new StringBuilder();
		sb.append(c instanceof Structure ? "struct " : "union ").append(c.getName()).append("  // ")
				.append(c.getCategoryPath().getPath()).append(", size 0x").append(Integer.toHexString(c.getLength()))
				.append(" (").append(c.getLength()).append(")");
		if (c.isPackingEnabled()) {
			sb.append(", packed");
		}
		if (c.getDescription() != null && !c.getDescription().isBlank()) {
			sb.append("\n// ").append(Fmt.oneLine(c.getDescription()));
		}
		sb.append("\n{\n");
		int cursor = 0;
		for (DataTypeComponent dc : c.getDefinedComponents()) {
			if (c instanceof Structure && dc.getOffset() > cursor) {
				sb.append(String.format("  /* +0x%03x */ undefined[%d]\n", cursor, dc.getOffset() - cursor));
			}
			sb.append(String.format("  /* +0x%03x */ %s %s;", dc.getOffset(), dc.getDataType().getDisplayName(),
					dc.getFieldName() != null ? dc.getFieldName() : dc.getDefaultFieldName()));
			if (dc.getLength() != dc.getDataType().getLength() && !dc.isBitFieldComponent()) {
				sb.append(" /* ").append(dc.getLength()).append(" bytes */");
			}
			if (dc.getComment() != null) {
				sb.append(" // ").append(Fmt.oneLine(dc.getComment()));
			}
			sb.append('\n');
			cursor = Math.max(cursor, dc.getOffset() + dc.getLength());
		}
		if (c instanceof Structure && cursor < c.getLength()) {
			sb.append(String.format("  /* +0x%03x */ undefined[%d]\n", cursor, c.getLength() - cursor));
		}
		return sb.append('}').toString();
	}
}
