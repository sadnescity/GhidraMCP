package com.lauriewired;

import java.io.IOException;

import com.lauriewired.core.DecompilerCache;
import com.lauriewired.core.InstanceServer;
import com.lauriewired.core.Services;
import com.lauriewired.core.ToolRegistry;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * GhidraMCP: lets an MCP client (Claude Code and others) read and annotate
 * the programs open in this Ghidra tool.
 *
 * <p>Each CodeBrowser with the plugin enabled serves its open programs on the
 * first free loopback port from 8080 (/instances, /mcp/tools, /mcp/call). The
 * MCP protocol itself is spoken by a separate process the client starts,
 * {@code java -jar ghidra-mcp-bridge.jar} (package com.lauriewired.mcp), which
 * finds these endpoints and sends each call to the program it names.
 */
@PluginInfo(status = PluginStatus.RELEASED, packageName = ghidra.app.DeveloperPluginPackage.NAME,
		category = PluginCategoryNames.ANALYSIS, shortDescription = "MCP server for Ghidra",
		description = "Exposes the open programs to MCP clients. Port and timeout under Tool Options > GhidraMCP HTTP Server.")
public class GhidraMCPPlugin extends Plugin {

	private static final String OPTIONS = "GhidraMCP HTTP Server";
	private static final String PORT_OPTION = "Server Port";
	private static final String TIMEOUT_OPTION = "Decompile Timeout";
	private static final int DEFAULT_PORT = 8080;
	private static final int PORT_SCAN = 100;
	private static final int DEFAULT_TIMEOUT = 60;

	/** The tool catalog: stateless, so one per JVM. */
	private static volatile ToolRegistry registry;

	private final Services services;
	private final InstanceServer server;

	public GhidraMCPPlugin(PluginTool tool) {
		super(tool);
		ToolOptions options = tool.getOptions(OPTIONS);
		options.registerOption(PORT_OPTION, DEFAULT_PORT, null,
				"First loopback port tried for this tool's endpoint; the next free one is used. Takes effect when the plugin reloads.");
		options.registerOption(TIMEOUT_OPTION, DEFAULT_TIMEOUT, null, "Decompilation timeout, in seconds.");

		if (registry == null) {
			synchronized (GhidraMCPPlugin.class) {
				if (registry == null) {
					registry = new ToolRegistry();
				}
			}
		}
		services = new Services(new DecompilerCache(this, options.getInt(TIMEOUT_OPTION, DEFAULT_TIMEOUT)));
		options.addOptionsChangeListener((opts, name, oldV, newV) -> {
			if (TIMEOUT_OPTION.equals(name) && newV instanceof Integer i) {
				services.decompilers().setTimeoutSeconds(i);
			}
		});
		server = new InstanceServer(tool, registry, services, this::currentProgram);
		try {
			int port = server.start(options.getInt(PORT_OPTION, DEFAULT_PORT), PORT_SCAN);
			Msg.info(this, "GhidraMCP serving this tool's programs on 127.0.0.1:" + port + " ("
					+ registry.all().size() + " tools)");
		}
		catch (IOException e) {
			Msg.error(this, "GhidraMCP could not start: " + e.getMessage(), e);
		}
	}

	private Program currentProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		return pm != null ? pm.getCurrentProgram() : null;
	}

	@Override
	public void dispose() {
		// Stop taking calls first, then stop any decompile still running.
		server.stop();
		services.dispose();
		super.dispose();
	}
}
