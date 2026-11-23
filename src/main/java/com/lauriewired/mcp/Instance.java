package com.lauriewired.mcp;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * What one Ghidra instance says about itself on /instances: its port, its
 * project, every program it has open, and the process it runs in (-1 if an
 * older plugin did not say). Two CodeBrowser windows of one Ghidra are two
 * instances with the same pid, and share their open programs.
 */
public record Instance(int port, String project, String current, List<Program> programs, long pid) {

	/** One open program. The file id is the database's identity; the name is not. */
	public record Program(String name, String fileId, String path) {
	}

	static Instance fromJson(JsonObject o) {
		List<Program> ps = new ArrayList<>();
		JsonElement arr = o.get("programs");
		if (arr != null && arr.isJsonArray()) {
			for (JsonElement e : (JsonArray) arr) {
				JsonObject p = e.getAsJsonObject();
				ps.add(new Program(str(p, "name"), str(p, "file_id"), str(p, "path")));
			}
		}
		else if (str(o, "program") != null) {
			// A plugin from before multi-program support lists only its current program.
			ps.add(new Program(str(o, "program"), str(o, "file_id"), null));
		}
		JsonElement pid = o.get("pid");
		return new Instance(o.get("port").getAsInt(), str(o, "project"), str(o, "program"), ps,
				pid != null && pid.isJsonPrimitive() ? pid.getAsLong() : -1);
	}

	static String str(JsonObject o, String k) {
		JsonElement e = o.get(k);
		return e == null || e.isJsonNull() ? null : e.getAsString();
	}
}
