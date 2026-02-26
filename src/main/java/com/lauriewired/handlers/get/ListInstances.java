package com.lauriewired.handlers.get;

import com.lauriewired.GhidraMCPPlugin;
import com.lauriewired.handlers.Handler;
import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Handler that lists all active GhidraMCP plugin instances.
 * Returns a JSON array with port, program name, and project name for each instance.
 * This enables the MCP bridge to discover all running instances from any single one.
 */
public final class ListInstances extends Handler {

	private static final Gson gson = new Gson();

	public ListInstances(PluginTool tool) {
		super(tool, "/instances");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		ConcurrentHashMap<Integer, GhidraMCPPlugin> instances =
			GhidraMCPPlugin.getActiveInstances();

		List<Map<String, Object>> result = new ArrayList<>();
		for (Map.Entry<Integer, GhidraMCPPlugin> entry : instances.entrySet()) {
			Map<String, Object> info = new LinkedHashMap<>();
			info.put("port", entry.getKey());
			GhidraMCPPlugin plugin = entry.getValue();
			String programName = plugin.getProgramName();
			String projectName = plugin.getProjectName();
			info.put("program", programName != null ? programName : "");
			info.put("project", projectName != null ? projectName : "");
			result.add(info);
		}

		byte[] bytes = gson.toJson(result).getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
		exchange.sendResponseHeaders(200, bytes.length);
		try (OutputStream os = exchange.getResponseBody()) {
			os.write(bytes);
		}
	}
}
