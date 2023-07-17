/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.util.exceptions;

import java.io.IOException;

/**
 * {@code NestedIOException} is an {@code IOException} that encapsulates
 * an {@code IOException} throw during IO process usually from {@code MessageConsumer} and {@code MessageProvider}.
 * <p>This can let user avoid unneeded {@code IOException} catch in case where {@code IOException} can never be thrown
 * because no external resource is used.   
 * <p>User should carefully check if source/destination of cipher process can throw {@code IOException} or not
 * (cases like {@code MessageProvider#from(java.io.File)} and {@code MessageConsumer#to(java.nio.channels.WritableByteChannel)}
 * where given {@code WritableByteChannel} is connected to external resource like {@code File} and {@code Socket})
 * and explicitly catch {@code NestedIOException} to avoid unexpected application failure
 * */
public class NestedIOException extends RuntimeException {
	
	private static final long serialVersionUID = 1670078192706028987L;
	private final IOException nested;
	
	public NestedIOException(IOException nested) {
		super(nested);
		this.nested = nested;
	}
	
	public Exception getNested() {
		return nested;
	}
	
	@Override
	public String getMessage() {
		return nested.getMessage();
	}

	@Override
	public String getLocalizedMessage() {
		return nested.getLocalizedMessage();
	}

	@Override
	public synchronized Throwable getCause() {
		return nested;
	}

	@Override
	public String toString() {
		return "NestedIOException with nested " + nested.toString();
	}

}
