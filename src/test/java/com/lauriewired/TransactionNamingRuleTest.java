package com.lauriewired;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import org.junit.Test;

/**
 * A rule, not a habit: nothing may open a Ghidra transaction except Ctx.write,
 * which names the session that asked for it. A tool written next year cannot
 * quietly go back to "Create Function" with no author, nor commit half a change
 * after an error.
 */
public class TransactionNamingRuleTest {

	@Test
	public void onlyCtxWriteOpensTransactions() throws IOException {
		List<String> bad = new ArrayList<>();
		try (Stream<Path> files = Files.walk(Paths.get("src/main/java"))) {
			for (Path p : (Iterable<Path>) files.filter(f -> f.toString().endsWith(".java"))::iterator) {
				int n = 0;
				for (String line : Files.readAllLines(p)) {
					n++;
					if (line.contains("startTransaction(") && !line.contains("txName(")) {
						bad.add(p.getFileName() + ":" + n + " " + line.trim());
					}
					if (line.contains("startTransaction(") && !p.getFileName().toString().equals("Ctx.java")) {
						bad.add(p.getFileName() + ":" + n + " opens a transaction outside Ctx.write");
					}
				}
			}
		}
		assertEquals(Collections.emptyList(), bad);
	}
}
