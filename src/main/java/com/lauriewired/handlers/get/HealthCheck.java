package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;

import java.io.IOException;

import static com.lauriewired.util.ParseUtils.sendResponse;

/**
 * Lightweight health check endpoint for instance discovery.
 * Returns "ok" if the server is running. Used by the MCP bridge
 * to quickly scan ports during instance discovery.
 */
public final class HealthCheck extends Handler {

	public HealthCheck(PluginTool tool) {
		super(tool, "/health");
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		sendResponse(exchange, "ok");
	}
}
