package com.lauriewired.core;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * Builds one page of a text listing. Every item is counted, so the footer can
 * say how many there are in all, but only the items inside the window are
 * rendered.
 */
public final class Page {

	public static final int MAX_LIMIT = 10_000;

	private final int offset;
	private final int limit;
	private final List<String> lines = new ArrayList<>();
	private int total;

	public Page(int offset, int limit) {
		if (offset < 0) {
			throw ToolError.invalid("offset must be >= 0 (got " + offset + ")");
		}
		if (limit < 1 || limit > MAX_LIMIT) {
			throw ToolError.invalid("limit must be between 1 and " + MAX_LIMIT + " (got " + limit + ")");
		}
		this.offset = offset;
		this.limit = limit;
	}

	public void offer(Supplier<String> line) {
		if (total >= offset && lines.size() < limit) {
			lines.add(line.get());
		}
		total++;
	}

	public void add(String line) {
		offer(() -> line);
	}

	public int total() {
		return total;
	}

	/**
	 * The page, followed by a footer whenever it is not the whole list, so the
	 * model can never mistake a first page for everything.
	 */
	public String render(String emptyMessage) {
		if (total == 0) {
			return emptyMessage;
		}
		StringBuilder sb = new StringBuilder(String.join("\n", lines));
		int shownEnd = offset + lines.size();
		if (offset > 0 || shownEnd < total) {
			if (sb.length() > 0) {
				sb.append('\n');
			}
			if (lines.isEmpty()) {
				sb.append("-- offset ").append(offset).append(" is past the end: there are ")
						.append(total).append(" items --");
			}
			else {
				sb.append("-- items ").append(offset + 1).append('-').append(shownEnd).append(" of ")
						.append(total);
				if (shownEnd < total) {
					sb.append("; next page: offset=").append(shownEnd);
				}
				sb.append(" --");
			}
		}
		return sb.toString();
	}
}
