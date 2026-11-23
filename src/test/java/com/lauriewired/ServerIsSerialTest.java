package com.lauriewired;

import static org.junit.Assert.assertTrue;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.Test;

/**
 * A guard: each instance runs its tool calls one at a time. The decompiler
 * cache and Ghidra's DecompInterface are not thread-safe; if you need
 * concurrency, give each worker its own decompiler first.
 */
public class ServerIsSerialTest {

	@Test
	public void theInstanceServerRunsOneCallAtATime() throws Exception {
		String src = Files.readString(Paths.get("src/main/java/com/lauriewired/core/InstanceServer.java"));
		assertTrue("tool calls must run on a single-threaded executor",
				src.contains("calls = Executors.newSingleThreadExecutor"));
		assertTrue("every tool call must go through that executor",
				src.contains("runner.submit(() -> run(") && src.split("registry\\.invoke\\(", -1).length == 2
						&& src.indexOf("registry.invoke(") > src.indexOf("private Reply run("));
	}
}
