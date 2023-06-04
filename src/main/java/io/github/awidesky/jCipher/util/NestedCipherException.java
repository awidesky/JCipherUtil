/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.util;

/**
 * {@code NestedCipherException} is an {@code RuntimeException} that encapsulates
 * cipher-related exception that is usually developer of this library's fault.
 * Those like {@code NoSuchAlgorithmException}, {@code NoSuchPaddingException} or {@code IllegalStateException}
 * is usually not thrown, and if they were, it's probably fault of the developer who wrote the subclass of {@code CipherUtil},
 * or some rare mistake cases (e.g. try to decrypt totally wrong data. etc.) 
 * 
 * */
public class NestedCipherException extends RuntimeException {

	private static final long serialVersionUID = -6976828145263718764L;
	private final Exception nested;
	
	public NestedCipherException(Exception nested) {
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
		return "NestedCipherException with nested Exception : " + nested.toString();
	}

}
