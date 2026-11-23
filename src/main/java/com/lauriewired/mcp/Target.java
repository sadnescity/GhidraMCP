package com.lauriewired.mcp;

/**
 * Where one call goes: the program (by its database file id) and the port its
 * instance answered on when the call was resolved. Never kept between calls.
 */
public record Target(int port, String program, String project, String fileId) {

	String describe() {
		return (program != null ? program : "no program") + " (" + (project != null ? project : "unknown project") + ")";
	}
}
