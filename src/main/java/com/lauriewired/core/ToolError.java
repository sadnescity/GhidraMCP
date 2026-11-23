package com.lauriewired.core;

/**
 * A failure reported to the model as an error result, with a stable code.
 *
 * <p>Every failure a tool can foresee is one of these. The model then sees
 * {@code isError: true} and "[CODE] message", rather than an error sentence
 * dressed as a successful result, which it used to read as data.
 */
public class ToolError extends RuntimeException {

	private final String code;

	public ToolError(String code, String message) {
		super(message);
		this.code = code;
	}

	public ToolError(String code, String message, Throwable cause) {
		super(message, cause);
		this.code = code;
	}

	public String code() {
		return code;
	}

	public static ToolError noProgram() {
		return new ToolError("NO_PROGRAM", "No program is open in this Ghidra instance");
	}

	public static ToolError missing(String name) {
		return new ToolError("MISSING_PARAMETER", "Missing required parameter '" + name + "'");
	}

	public static ToolError invalid(String message) {
		return new ToolError("INVALID_PARAMETER", message);
	}

	public static ToolError badAddress(String text) {
		return new ToolError("BAD_ADDRESS", "Not a valid address in this program: '" + text + "'");
	}

	public static ToolError notFound(String message) {
		return new ToolError("NOT_FOUND", message);
	}

	public static ToolError functionNotFound(String where) {
		return new ToolError("FUNCTION_NOT_FOUND", "No function " + where);
	}

	public static ToolError ambiguous(String message) {
		return new ToolError("AMBIGUOUS", message);
	}

	public static ToolError conflict(String message) {
		return new ToolError("CONFLICT", message);
	}

	public static ToolError failed(String message) {
		return new ToolError("FAILED", message);
	}

	public static ToolError failed(String message, Throwable cause) {
		return new ToolError("FAILED", message, cause);
	}
}
