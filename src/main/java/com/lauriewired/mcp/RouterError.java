package com.lauriewired.mcp;

/** A refusal or failure of the router itself, reported to the model with a code. */
public class RouterError extends RuntimeException {

	private final String code;

	public RouterError(String code, String message) {
		super(message);
		this.code = code;
	}

	public String code() {
		return code;
	}
}
