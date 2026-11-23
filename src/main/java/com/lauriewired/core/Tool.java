package com.lauriewired.core;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares an MCP tool. A tool is defined exactly once, here, on the method
 * that implements it: its name, description and parameter schema are all read
 * from this annotation and the {@link P} annotations on the parameters, so
 * there is no second copy (no bridge wrapper) to keep in step.
 *
 * <p>The method's first parameter is always a {@link Ctx}; every other
 * parameter carries a {@link P}. It returns the text the model reads, or
 * throws {@link ToolError}.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Tool {
	/** The tool's name as the model sees it. Never rename: allowlists and skills name it. */
	String name();

	/** What the tool does, when to use it, and what it returns. */
	String description();

	/** True if the tool never changes the program. */
	boolean readOnly() default true;
}
