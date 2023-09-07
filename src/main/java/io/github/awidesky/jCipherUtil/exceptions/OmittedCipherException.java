/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.exceptions;

/**
 * {@code NestedOmittedCipherException} is an {@code RuntimeException} that encapsulates
 * cipher-related exception that is usually this library's fault.
 * <p>
 * Some examples are {@code NoSuchAlgorithmException}, {@code NoSuchPaddingException},
 * which are usually not thrown, since the name of the algorithms are statically specified as constant
 * (in worse term, hardcoded) in source code of {@code CipherUtil} subclasses,
 * Another example is {@code IllegalStateException}, which is usually not thrown either since initiating backing
 * {@code Cipher} object is driven by internal initEncrypt/initDecrypt logic. 
 * Also note that these bugs are usually discovered when testing.
 * <p>
 * So these find of exceptions should not be thrown in most of situations. if they are thrown,
 * it's probably fault of the developer who wrote the subclass of {@code CipherUtil},
 * So these checked exceptions are wrapped into a {@code OmittedCipherException} and treated as a runtime exception.
 * */
public class OmittedCipherException extends RuntimeException {

	private static final long serialVersionUID = -6976828145263718764L;
	private final Exception nested;
	
	/**
	 * Constructs a new OmittedCipherException with given cause(nested {@code Exception})
	 */
	public OmittedCipherException(Exception nested) {
		super(nested);
		this.nested = nested;
	}
	/**
	 * @return nested {@code Exception}
	 */
	public Exception getNested() {
		return nested;
	}
	/**
	 * Returns the detail message string of nested {@code Exception}.
	 * @return {@code Exception#getMessage()} of nested {@code Exception}
	 */
	@Override
	public String getMessage() {
		return nested.getMessage();
	}
	/**
	 * Returns the localized description of nested {@code Exception}.
	 * @return {@code Exception#getLocalizedMessage()} of nested {@code Exception}
	 */
	@Override
	public String getLocalizedMessage() {
		return nested.getLocalizedMessage();
	}
	/**
	 * Returns the cause of this {@code OmittedCipherException}, which is the nested {@code Exception}
	 */
	@Override
	public synchronized Throwable getCause() {
		return nested;
	}
	/**
	 * Returns a short description of this {@code OmittedCipherException} and the nested {@code Exception}
	 * */
	@Override
	public String toString() {
		return getClass().getSimpleName() + " with nested " + nested.toString();
	}

}
