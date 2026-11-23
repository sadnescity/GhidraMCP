package com.lauriewired.core;

/**
 * Long-lived state shared by every call to one plugin instance.
 */
public final class Services {

	private final DecompilerCache decompilers;

	public Services(DecompilerCache decompilers) {
		this.decompilers = decompilers;
	}

	public DecompilerCache decompilers() {
		return decompilers;
	}

	public void dispose() {
		decompilers.disposeAll();
	}
}
