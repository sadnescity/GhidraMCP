package com.lauriewired.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.lauriewired.core.Ctx;
import com.lauriewired.core.Fmt;
import com.lauriewired.core.P;
import com.lauriewired.core.Page;
import com.lauriewired.core.Tool;
import com.lauriewired.core.ToolError;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

/** Listing comments of every kind. */
public final class CommentTools {

	private static final String[] TYPES = { "plate", "pre", "eol", "post", "repeatable" };

	@Tool(name = "set_decompiler_comment", readOnly = false, description = "Set the comment the decompiler "
			+ "shows above the statement at an address (a PRE comment). An empty comment removes it.")
	public String setDecompilerComment(Ctx ctx,
			@P(value = "address", description = "Instruction address") String address,
			@P(value = "comment", description = "Comment text; empty to remove") String comment) {
		return set(ctx, ctx.addr(address), CommentType.PRE, comment);
	}

	@Tool(name = "set_disassembly_comment", readOnly = false, description = "Set the end-of-line comment shown "
			+ "in the disassembly at an address (an EOL comment). An empty comment removes it.")
	public String setDisassemblyComment(Ctx ctx,
			@P(value = "address", description = "Instruction or data address") String address,
			@P(value = "comment", description = "Comment text; empty to remove") String comment) {
		return set(ctx, ctx.addr(address), CommentType.EOL, comment);
	}

	@Tool(name = "set_comment", readOnly = false, description = "Set a listing comment of any kind at any "
			+ "address (code or data). type: plate (a header box above; at a function entry it is the "
			+ "function's header comment, shown by the decompiler too), pre (above the line; shown in the "
			+ "decompiler), eol (end of line), post (below the line), repeatable (shown at every reference). "
			+ "An empty comment removes it.")
	public String setComment(Ctx ctx,
			@P(value = "address", description = "Address or symbol") String address,
			@P(value = "comment", description = "Comment text; empty to remove") String comment,
			@P(value = "type", def = "pre", oneOf = { "plate", "pre", "eol", "post", "repeatable" },
					description = "Comment kind") String type) {
		return set(ctx, ctx.addr(address), type(type), comment);
	}

	@Tool(name = "set_comments", readOnly = false, description = "Set many comments in one transaction (all or "
			+ "nothing). Each entry: {\"address\", \"comment\", \"type\"?: plate|pre|eol|post|repeatable "
			+ "(default pre)}. Use it to annotate a whole function at once.")
	public String setComments(Ctx ctx,
			@P(value = "comments", description = "List of {address, comment, type?}") JsonArray comments) {
		if (comments == null || comments.size() == 0) {
			throw ToolError.missing("comments");
		}
		record C(Address a, CommentType t, String text) {
		}
		List<C> list = new ArrayList<>();
		for (JsonElement e : comments) {
			if (!e.isJsonObject()) {
				throw ToolError.invalid("Each entry must be an object {address, comment, type?}");
			}
			JsonObject o = e.getAsJsonObject();
			if (!o.has("address")) {
				throw ToolError.missing("address (in comments)");
			}
			String text = o.has("comment") && !o.get("comment").isJsonNull() ? o.get("comment").getAsString() : "";
			String t = o.has("type") ? o.get("type").getAsString() : "pre";
			list.add(new C(ctx.addr(o.get("address").getAsString()), type(t), text));
		}
		Program p = ctx.program();
		ctx.write("Set Comments", () -> {
			for (C c : list) {
				p.getListing().setComment(c.a, c.t, c.text.isBlank() ? null : c.text);
			}
			return null;
		});
		return "Set " + list.size() + " comments";
	}

	@Tool(name = "get_comments", description = "Read comments. With scope=address: every kind of comment at "
			+ "that address. With scope=function: every comment inside the function containing the address, "
			+ "in address order.")
	public String getComments(Ctx ctx,
			@P(value = "address", description = "Address or symbol") String address,
			@P(value = "scope", def = "address", oneOf = { "address", "function" }, description = "What to read") String scope,
			@P(value = "offset", def = "0", description = "Pagination offset (function scope)") int offset,
			@P(value = "limit", def = "500", description = "Pagination limit (function scope)") int limit) {
		Program p = ctx.program();
		Address a = ctx.addr(address);
		Listing l = p.getListing();
		if (scope.equalsIgnoreCase("address")) {
			StringBuilder sb = new StringBuilder();
			for (String t : TYPES) {
				String c = l.getComment(type(t), a);
				if (c != null) {
					sb.append(t).append(": ").append(c.replace("\n", "\n    ")).append('\n');
				}
			}
			return sb.length() == 0 ? "No comments at " + Fmt.addr(a) : sb.toString().stripTrailing();
		}
		Function f = ctx.fnAt(a);
		AddressSetView body = f.getBody();
		Page page = new Page(offset, limit);
		AddressIterator it = l.getCommentAddressIterator(body, true);
		while (it.hasNext()) {
			Address at = it.next();
			for (String t : TYPES) {
				String c = l.getComment(type(t), at);
				if (c != null) {
					page.offer(() -> Fmt.addr(at) + " " + t + ": " + Fmt.oneLine(c));
				}
			}
		}
		return Fmt.fn(f) + "\n" + page.render("No comments");
	}

	static CommentType type(String t) {
		return switch (t.toLowerCase(Locale.ROOT)) {
			case "plate" -> CommentType.PLATE;
			case "pre" -> CommentType.PRE;
			case "eol" -> CommentType.EOL;
			case "post" -> CommentType.POST;
			case "repeatable" -> CommentType.REPEATABLE;
			default -> throw ToolError.invalid("Comment type must be plate, pre, eol, post or repeatable (got '" + t + "')");
		};
	}

	private static String set(Ctx ctx, Address a, CommentType t, String comment) {
		Program p = ctx.program();
		if (p.getMemory().getBlock(a) == null) {
			throw ToolError.notFound(Fmt.addr(a) + " is not in any memory block");
		}
		String text = comment == null || comment.isBlank() ? null : comment;
		ctx.write("Set Comment", () -> {
			p.getListing().setComment(a, t, text);
			return null;
		});
		return (text == null ? "Removed " : "Set ") + t.name().toLowerCase(Locale.ROOT) + " comment at "
				+ Fmt.where(p, a);
	}
}
