package com.lauriewired.core;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * A tool parameter. Supported Java types: String, int, long, boolean,
 * com.google.gson.JsonArray and com.google.gson.JsonObject.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
public @interface P {
	/** Marks a parameter that has no default and must be given. */
	String REQUIRED = "\u0000required";

	/** Marks an optional parameter whose absence is passed as null. */
	String NULL = "\u0000null";

	/** The parameter's name in the tool schema. */
	String value();

	/** What the parameter means. */
	String description() default "";

	/** Default value, as text; {@link #REQUIRED} or {@link #NULL} otherwise. */
	String def() default REQUIRED;

	/** If not empty, the only values accepted. */
	String[] oneOf() default {};
}
