package com.lauriewired.handlers.set;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;

import javax.swing.*;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

/**
 * Handler for renaming data at a specific address in the current program.
 * Expects POST parameters: "address" (the address of the data) and "newName"
 * (the new name).
 */
public final class RenameData extends Handler {
	/**
	 * Constructs a new RenameData handler.
	 *
	 * @param tool the PluginTool instance to use for program access
	 */
	public RenameData(PluginTool tool) {
		super(tool, "/renameData");
	}

	/**
	 * Handles the HTTP request to rename data at a specified address.
	 * Expects POST parameters "address" and "newName".
	 *
	 * @param exchange the HttpExchange object containing the request
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		Map<String, String> params = parsePostParams(exchange);
		boolean success = renameDataAtAddress(params.get("address"), params.get("newName"));
		sendResponse(exchange, success ? "Rename data successful" : "Failed to rename data");
	}

	/**
	 * Renames the data or label at the specified address in the current program.
	 * If a symbol already exists at the address, it renames it; otherwise, it creates a new label.
	 *
	 * @param addressStr the address of the data as a string
	 * @param newName    the new name for the data
	 * @return true if the rename was successful, false otherwise
	 */
	private boolean renameDataAtAddress(String addressStr, String newName) {
		Program program = getCurrentProgram(tool);
		if (program == null)
			return false;

		java.util.concurrent.atomic.AtomicBoolean success = new java.util.concurrent.atomic.AtomicBoolean(false);

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Rename data");
				try {
					Address addr = program.getAddressFactory().getAddress(addressStr);
					SymbolTable symTable = program.getSymbolTable();
					Symbol symbol = symTable.getPrimarySymbol(addr);
					if (symbol != null) {
						symbol.setName(newName, SourceType.USER_DEFINED);
					} else {
						symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
					}
					success.set(true);
				} catch (Exception e) {
					Msg.error(this, "Rename data error", e);
				} finally {
					program.endTransaction(tx, success.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute rename data on Swing thread", e);
		}

		return success.get();
	}
}
