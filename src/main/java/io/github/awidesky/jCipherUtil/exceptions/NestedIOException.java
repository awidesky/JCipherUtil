/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.exceptions;

import java.io.IOException;

/**
 * {@code NestedIOException} is an {@code IOException} that encapsulates
 * an {@code IOException} throw during IO process usually from {@code OutPut} and {@code InPut}.
 * <p>This can let user avoid unneeded {@code IOException} catch in case where {@code IOException} can never be thrown
 * because no external resource is used.   
 * <p>User should carefully check if source/destination of cipher process can throw {@code IOException} or not
 * (cases like {@code InPut#from(java.io.File)} and {@code OutPut#to(java.nio.channels.WritableByteChannel)}
 * where given {@code WritableByteChannel} is connected to external resource like {@code File} and {@code Socket})
 * and explicitly catch {@code NestedIOException} to avoid unexpected application failure
 * */
public class NestedIOException extends RuntimeException {
	
	private static final long serialVersionUID = 1670078192706028987L;
	/** Nested {@code IOException} which is the cause of this {@code NestedIOException} */
	private final IOException nested;
	
	/**
	 * Constructs a new NestedIOException with given cause(nested {@code IOException})
	 */
	public NestedIOException(IOException nested) {
		super(nested);
		this.nested = nested;
	}
	
	/**
	 * @return nested {@code IOException}
	 */
	public Exception getNested() {
		return nested;
	}
	
	/**
	 * Returns the detail message string of nested {@code IOException}.
	 * @return {@code IOException#getMessage()} of nested {@code IOException}
	 */
	@Override
	public String getMessage() {
		return nested.getMessage();
	}

	/**
	 * Returns the localized description of nested {@code IOException}.
	 * @return {@code IOException#getLocalizedMessage()} of nested {@code IOException}
	 */
	@Override
	public String getLocalizedMessage() {
		return nested.getLocalizedMessage();
	}

	/**
	 * Returns the cause of this {@code NestedIOException}, which is the nested {@code IOException}
	 */
	@Override
	public synchronized Throwable getCause() {
		return nested;
	}

	/**
	 * Returns a short description of this {@code NestedIOException} and the nested {@code IOException}
	 * */
	@Override
	public String toString() {
		return getClass().getSimpleName() + " with nested " + nested.toString();
	}

}
