package com.lauriewired.core;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import com.google.gson.GsonBuilder;

/**
 * Build step: writes the tool catalog to a JSON file that goes into the jar,
 * so the stdio server can list the tools before any Ghidra is running.
 */
public final class SchemaDump {

	private SchemaDump() {
	}

	public static void main(String[] args) throws Exception {
		Path out = Path.of(args[0]);
		Files.createDirectories(out.getParent());
		String json = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()
				.toJson(new ToolRegistry().schema());
		Files.writeString(out, json, StandardCharsets.UTF_8);
		System.out.println("Wrote " + out);
	}
}
